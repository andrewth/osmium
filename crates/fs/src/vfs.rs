//! The namespace: absolute path lookup across mounted file systems.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use osmium_sync::RwSpinLock;

use crate::{Errno, File, FileKind, OpenFlags, Stat};

/// Longest accepted path, in bytes (`PATH_MAX`, including the NUL).
pub const PATH_MAX: usize = 4096;
/// Longest accepted path component, in bytes (`NAME_MAX`).
pub const NAME_MAX: usize = 255;
/// Symbolic links followed in one lookup before `ELOOP`.
const MAX_SYMLINKS: usize = 40;

struct Mount {
    /// Canonical absolute path of the covered directory.
    path: String,
    root: Arc<dyn File>,
}

/// A tree of mounted file systems, looked up by absolute path.
///
/// Paths must start with `/`; resolving relative paths against a working
/// directory is the caller's job. `.` and `..` are handled here (`..` at a
/// mount's root leaves the mount), symbolic links are followed, and a
/// trailing `/` requires a directory. No permission checks are made.
pub struct Vfs {
    /// Copied on write, so a lookup never holds the lock across file system
    /// calls. The first entry is always `/`; later entries cover earlier ones.
    mounts: RwSpinLock<Arc<Vec<Mount>>>,
}

/// A path resolved to a node, with its canonical path.
struct Resolved {
    node: Arc<dyn File>,
    path: String,
}

/// A path resolved to its parent directory and final component.
struct Parent<'a> {
    dir: Arc<dyn File>,
    /// The directory's canonical path.
    path: String,
    /// The final component: `None` for `/`, otherwise possibly `.` or `..`.
    name: Option<&'a str>,
    /// The path ended in `/`.
    trailing_slash: bool,
}

impl Vfs {
    /// A namespace whose `/` is `root`, a directory.
    pub fn new(root: Arc<dyn File>) -> Self {
        Vfs { mounts: RwSpinLock::new(Arc::new(vec![Mount { path: "/".to_string(), root }])) }
    }

    /// Mounts `root`, a file system's root directory, over the existing
    /// directory `path`. A later mount on the same path covers an earlier
    /// one until [`unmount`](Vfs::unmount).
    pub fn mount(&self, path: &str, root: Arc<dyn File>) -> Result<(), Errno> {
        let at = self.resolve(path, true)?;
        if at.node.stat().kind != FileKind::Directory || root.stat().kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        let mut mounts = self.mounts.write();
        let mut new: Vec<Mount> = mounts.iter().map(|m| Mount { path: m.path.clone(), root: m.root.clone() }).collect();
        new.push(Mount { path: at.path, root });
        *mounts = Arc::new(new);
        Ok(())
    }

    /// Removes the most recent mount on `path`: `EINVAL` if nothing is
    /// mounted there, `EBUSY` for the original `/` or a mount that has others
    /// inside it.
    pub fn unmount(&self, path: &str) -> Result<(), Errno> {
        let at = self.resolve(path, true)?;
        let mut mounts = self.mounts.write();
        let i = mounts.iter().rposition(|m| m.path == at.path).ok_or(Errno::EINVAL)?;
        if i == 0 {
            return Err(Errno::EBUSY);
        }
        if mounts[i + 1..].iter().any(|m| is_inside(&m.path, &at.path)) {
            return Err(Errno::EBUSY);
        }
        let new: Vec<Mount> = mounts
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != i)
            .map(|(_, m)| Mount { path: m.path.clone(), root: m.root.clone() })
            .collect();
        *mounts = Arc::new(new);
        Ok(())
    }

    /// Opens `path`, creating a regular file with permission bits `mode` if
    /// `flags` has [`OpenFlags::CREATE`] and it does not exist.
    ///
    /// Fails with `EISDIR` when opening a directory for writing, `ENOTDIR`
    /// when [`OpenFlags::DIRECTORY`] names something else, and `ELOOP` when
    /// [`OpenFlags::NOFOLLOW`] names a symbolic link. [`OpenFlags::TRUNC`]
    /// with [`OpenFlags::WRITE`] empties a regular file.
    pub fn open(&self, path: &str, flags: OpenFlags, mode: u32) -> Result<Arc<dyn File>, Errno> {
        let follow = !flags.contains(OpenFlags::NOFOLLOW);
        let node = if flags.contains(OpenFlags::CREATE) {
            let parent = self.parent(path)?;
            match parent.name {
                Some(name) if name != "." && name != ".." => match parent.dir.lookup(name) {
                    Ok(_) if flags.contains(OpenFlags::EXCL) => return Err(Errno::EEXIST),
                    Ok(node) if node.stat().kind == FileKind::Symlink && follow => self.resolve(path, true)?.node,
                    Ok(node) => node,
                    Err(Errno::ENOENT) if parent.trailing_slash => return Err(Errno::EISDIR),
                    Err(Errno::ENOENT) => parent.dir.create(name, FileKind::Regular, mode & 0o7777)?,
                    Err(e) => return Err(e),
                },
                // `/`, `.` or `..`: always an existing directory.
                _ => return Err(if flags.contains(OpenFlags::EXCL) { Errno::EEXIST } else { Errno::EISDIR }),
            }
        } else {
            self.resolve(path, follow)?.node
        };
        let stat = node.stat();
        if stat.kind == FileKind::Symlink {
            return Err(Errno::ELOOP);
        }
        if stat.kind == FileKind::Directory {
            if flags.contains(OpenFlags::WRITE) {
                return Err(Errno::EISDIR);
            }
        } else if flags.contains(OpenFlags::DIRECTORY) {
            return Err(Errno::ENOTDIR);
        }
        if stat.kind == FileKind::Regular && flags.contains(OpenFlags::TRUNC | OpenFlags::WRITE) {
            node.truncate(0)?;
        }
        Ok(node)
    }

    /// Finds `path`, following symbolic links.
    pub fn lookup(&self, path: &str) -> Result<Arc<dyn File>, Errno> {
        Ok(self.resolve(path, true)?.node)
    }

    /// `stat` of `path`; with `follow` false, a final symbolic link is
    /// described itself (`lstat`).
    pub fn stat(&self, path: &str, follow: bool) -> Result<Stat, Errno> {
        Ok(self.resolve(path, follow)?.node.stat())
    }

    /// Creates the directory `path` with permission bits `mode`.
    pub fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let parent = self.parent(path)?;
        match parent.name {
            Some(name) if name != "." && name != ".." => {
                parent.dir.create(name, FileKind::Directory, mode & 0o7777).map(drop)
            }
            _ => Err(Errno::EEXIST),
        }
    }

    /// Creates a symbolic link at `path` pointing to `target`.
    pub fn symlink(&self, target: &str, path: &str) -> Result<(), Errno> {
        if target.is_empty() {
            return Err(Errno::ENOENT);
        }
        let parent = self.parent(path)?;
        match parent.name {
            Some(name) if name != "." && name != ".." && !parent.trailing_slash => {
                let link = parent.dir.create(name, FileKind::Symlink, 0o777)?;
                link.write(0, target.as_bytes()).map(drop)
            }
            _ => Err(Errno::EEXIST),
        }
    }

    /// Removes the non-directory `path`.
    pub fn unlink(&self, path: &str) -> Result<(), Errno> {
        let parent = self.parent(path)?;
        match parent.name {
            Some(name) if name != "." && name != ".." => {
                if parent.trailing_slash {
                    // `unlink("file/")`: a directory was asked for.
                    let kind = parent.dir.lookup(name)?.stat().kind;
                    return Err(if kind == FileKind::Directory { Errno::EISDIR } else { Errno::ENOTDIR });
                }
                parent.dir.remove(name, false)
            }
            _ => Err(Errno::EISDIR),
        }
    }

    /// Removes the empty directory `path`.
    pub fn rmdir(&self, path: &str) -> Result<(), Errno> {
        let parent = self.parent(path)?;
        match parent.name {
            None => Err(Errno::EBUSY),
            Some(".") => Err(Errno::EINVAL),
            Some("..") => Err(Errno::ENOTEMPTY),
            Some(name) => {
                if self.is_mount_point(&join(&parent.path, name)) {
                    return Err(Errno::EBUSY);
                }
                parent.dir.remove(name, true)
            }
        }
    }

    /// The target of the symbolic link `path`.
    pub fn readlink(&self, path: &str) -> Result<String, Errno> {
        let node = self.resolve(path, false)?.node;
        if node.stat().kind != FileKind::Symlink {
            return Err(Errno::EINVAL);
        }
        node.readlink()
    }

    /// The canonical form of `path`: absolute, with `.`, `..`, repeated `/`
    /// and symbolic links resolved (`realpath`).
    pub fn canonicalize(&self, path: &str) -> Result<String, Errno> {
        Ok(self.resolve(path, true)?.path)
    }

    fn snapshot(&self) -> Arc<Vec<Mount>> {
        self.mounts.read().clone()
    }

    fn is_mount_point(&self, path: &str) -> bool {
        self.snapshot().iter().any(|m| m.path == path)
    }

    fn resolve(&self, path: &str, follow: bool) -> Result<Resolved, Errno> {
        let (comps, trailing_slash) = split(path)?;
        let mut walker = Walker::new(self.snapshot());
        // With a trailing slash the final component must be a directory, so
        // a final symlink is followed regardless.
        walker.walk(comps, follow || trailing_slash)?;
        let (node, path) = walker.finish();
        if trailing_slash && node.stat().kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(Resolved { node, path })
    }

    fn parent<'a>(&self, path: &'a str) -> Result<Parent<'a>, Errno> {
        let (mut comps, trailing_slash) = split(path)?;
        let name = comps.pop();
        let mut walker = Walker::new(self.snapshot());
        walker.walk(comps, true)?;
        let (dir, path) = walker.finish();
        if dir.stat().kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(Parent { dir, path, name, trailing_slash })
    }
}

/// Splits an absolute path into its components, dropping empty ones;
/// also returns whether it ended in `/`.
fn split(path: &str) -> Result<(Vec<&str>, bool), Errno> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if !path.starts_with('/') {
        return Err(Errno::EINVAL);
    }
    if path.len() >= PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if comps.iter().any(|c| c.len() > NAME_MAX) {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok((comps, path.len() > 1 && path.ends_with('/')))
}

/// `dir/name` for a canonical directory path.
fn join(dir: &str, name: &str) -> String {
    let mut path = String::with_capacity(dir.len() + 1 + name.len());
    path.push_str(dir);
    if dir != "/" {
        path.push('/');
    }
    path.push_str(name);
    path
}

/// Whether canonical `path` is `dir` or below it.
fn is_inside(path: &str, dir: &str) -> bool {
    dir == "/" || path == dir || (path.starts_with(dir) && path.as_bytes()[dir.len()] == b'/')
}

/// The state of one lookup: the directories walked through from `/`, so that
/// `..` can step back out, including out of a mount.
struct Walker {
    mounts: Arc<Vec<Mount>>,
    /// Each node with the length of its canonical path in `path`.
    stack: Vec<(Arc<dyn File>, usize)>,
    path: String,
    symlinks: usize,
}

impl Walker {
    fn new(mounts: Arc<Vec<Mount>>) -> Self {
        let root = Self::covering(&mounts, "/").expect("the root is always mounted");
        Walker { mounts, stack: vec![(root, 1)], path: "/".to_string(), symlinks: 0 }
    }

    /// The root of the most recent mount on `path`.
    fn covering(mounts: &[Mount], path: &str) -> Option<Arc<dyn File>> {
        mounts.iter().rev().find(|m| m.path == path).map(|m| m.root.clone())
    }

    fn top(&self) -> &Arc<dyn File> {
        &self.stack.last().expect("the walk never pops the root").0
    }

    fn finish(mut self) -> (Arc<dyn File>, String) {
        let (node, _) = self.stack.pop().expect("the walk never pops the root");
        (node, self.path)
    }

    /// Walks `comps` from the current node. A symbolic link is followed
    /// unless it is the final component and `follow_last` is false.
    fn walk(&mut self, comps: Vec<&str>, follow_last: bool) -> Result<(), Errno> {
        // Owned, since a symlink's target splices in components of its own.
        let mut pending: Vec<String> = comps.into_iter().rev().map(String::from).collect();
        while let Some(comp) = pending.pop() {
            if self.top().stat().kind != FileKind::Directory {
                return Err(Errno::ENOTDIR);
            }
            match comp.as_str() {
                "." => continue,
                ".." => {
                    if self.stack.len() > 1 {
                        self.stack.pop();
                        let len = self.stack.last().expect("the root stays").1;
                        self.path.truncate(len);
                    }
                    continue;
                }
                _ => {}
            }
            let mut node = self.top().lookup(&comp)?;
            let path = join(&self.path, &comp);
            if let Some(root) = Self::covering(&self.mounts, &path) {
                node = root;
            }
            if node.stat().kind == FileKind::Symlink && (follow_last || !pending.is_empty()) {
                self.symlinks += 1;
                if self.symlinks > MAX_SYMLINKS {
                    return Err(Errno::ELOOP);
                }
                let target = node.readlink()?;
                if target.is_empty() {
                    return Err(Errno::ENOENT);
                }
                if target.starts_with('/') {
                    self.stack.truncate(1);
                    self.path.truncate(1);
                }
                pending.extend(target.split('/').filter(|c| !c.is_empty()).rev().map(String::from));
                continue;
            }
            self.path = path;
            self.stack.push((node, self.path.len()));
        }
        Ok(())
    }
}
