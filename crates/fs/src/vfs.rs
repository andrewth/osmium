//! The namespace: absolute path lookup across mounted file systems.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_sync::RwSpinLock;
use osmium_sync::fallible::{try_arc, try_push, try_string};

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
struct Parent<'path> {
    dir: Arc<dyn File>,
    /// The directory's canonical path.
    path: String,
    /// The final component: `None` for `/`, otherwise possibly `.` or `..`.
    name: Option<&'path str>,
    /// The path ended in `/`.
    trailing_slash: bool,
}

impl Vfs {
    /// A namespace whose `/` is `root`, a directory.
    ///
    /// # Panics
    /// If memory runs out: [`Vfs::try_new`] reports that instead.
    #[allow(clippy::expect_used)] // documented `# Panics` on OOM at boot; `try_new` is the fallible form.
    pub fn new(root: Arc<dyn File>) -> Self {
        Self::try_new(root).expect("out of memory for the namespace")
    }

    /// [`Vfs::new`], failing with `ENOMEM` instead of panicking.
    pub fn try_new(root: Arc<dyn File>) -> Result<Self, Errno> {
        let mut mounts = Vec::new();
        try_push(&mut mounts, Mount { path: try_string("/")?, root })?;
        Ok(Vfs { mounts: RwSpinLock::new(try_arc(mounts)?) })
    }

    /// A copy of the mounts, for `mount` and `unmount` to change, with room
    /// for `extra` more. Made before anything is changed.
    fn copy_mounts(mounts: &[Mount], skip: Option<usize>, extra: usize) -> Result<Vec<Mount>, Errno> {
        let mut new = Vec::new();
        new.try_reserve_exact(mounts.len() + extra).map_err(|_| Errno::ENOMEM)?;
        for (i, m) in mounts.iter().enumerate().filter(|&(i, _)| Some(i) != skip) {
            let _ = i;
            new.push(Mount { path: try_string(&m.path)?, root: m.root.clone() });
        }
        Ok(new)
    }

    /// Mounts `root`, a file system's root directory, over the existing
    /// directory `path`. A later mount on the same path covers an earlier
    /// one until [`unmount`](Vfs::unmount).
    pub fn mount(&self, path: &str, root: Arc<dyn File>) -> Result<(), Errno> {
        let at = self.resolve(path, true)?;
        if at.node.try_stat()?.kind != FileKind::Directory || root.try_stat()?.kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        let mut mounts = self.mounts.write();
        let mut new = Self::copy_mounts(&mounts, None, 1)?;
        new.push(Mount { path: at.path, root });
        *mounts = try_arc(new)?;
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
        if mounts.iter().skip(i + 1).any(|m| is_inside(&m.path, &at.path)) {
            return Err(Errno::EBUSY);
        }
        let new = Self::copy_mounts(&mounts, Some(i), 0)?;
        *mounts = try_arc(new)?;
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
            self.open_create(path, flags, mode, 0)?
        } else {
            self.resolve(path, follow)?.node
        };
        let stat = node.try_stat()?;
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

    /// The node `open` with [`OpenFlags::CREATE`] ends up on: the existing
    /// one (through mounts, and through a final symbolic link unless
    /// `NOFOLLOW`), or a new regular file; a dangling link creates its target.
    fn open_create(&self, path: &str, flags: OpenFlags, mode: u32, depth: usize) -> Result<Arc<dyn File>, Errno> {
        let follow = !flags.contains(OpenFlags::NOFOLLOW);
        let parent = self.parent(path)?;
        let name = match parent.name {
            Some(name) if name != "." && name != ".." => name,
            // `/`, `.` or `..`: always an existing directory.
            _ => return Err(if flags.contains(OpenFlags::EXCL) { Errno::EEXIST } else { Errno::EISDIR }),
        };
        let mut node = match parent.dir.lookup(name) {
            Ok(node) => node,
            Err(Errno::ENOENT) if parent.trailing_slash => return Err(Errno::EISDIR),
            Err(Errno::ENOENT) => match parent.dir.create(name, FileKind::Regular, mode & 0o7777) {
                Ok(node) => return Ok(node),
                // Created by someone else since the lookup: open that one
                // unless the caller insisted on a new file.
                Err(Errno::EEXIST) if !flags.contains(OpenFlags::EXCL) => parent.dir.lookup(name)?,
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };
        // A mount point shows the mounted root, not the covered directory.
        if let Some(root) = Walker::covering(&self.snapshot(), &join(&parent.path, name)?) {
            node = root;
        }
        if flags.contains(OpenFlags::EXCL) {
            return Err(Errno::EEXIST);
        }
        if parent.trailing_slash {
            // `open("file/", O_CREAT)`: a directory was asked for.
            let node = self.resolve(path, true)?.node;
            return Err(if node.try_stat()?.kind == FileKind::Directory { Errno::EISDIR } else { Errno::ENOTDIR });
        }
        if node.try_stat()?.kind == FileKind::Symlink && follow {
            return match self.resolve(path, true) {
                Ok(resolved) => Ok(resolved.node),
                Err(Errno::ENOENT) => {
                    // Dangling: create what the link points at.
                    if depth >= MAX_SYMLINKS {
                        return Err(Errno::ELOOP);
                    }
                    let target = node.readlink()?;
                    if target.is_empty() {
                        return Err(Errno::ENOENT);
                    }
                    let target = if target.starts_with('/') { target } else { join(&parent.path, &target)? };
                    self.open_create(&target, flags, mode, depth + 1)
                }
                Err(e) => Err(e),
            };
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
        self.resolve(path, follow)?.node.try_stat()
    }

    /// Creates the directory `path` with permission bits `mode`.
    pub fn mkdir(&self, path: &str, mode: u32) -> Result<(), Errno> {
        self.mknod(path, FileKind::Directory, mode).map(drop)
    }

    /// Creates a node of `kind` at `path` with permission bits `mode`, such
    /// as a FIFO or device node (`mknod`), or a regular file or directory.
    /// Symbolic links need a target: use [`symlink`](Vfs::symlink).
    pub fn mknod(&self, path: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        if kind == FileKind::Symlink {
            return Err(Errno::EINVAL);
        }
        let parent = self.parent(path)?;
        match parent.name {
            Some(name) if name != "." && name != ".." && (!parent.trailing_slash || kind == FileKind::Directory) => {
                parent.dir.create(name, kind, mode & 0o7777)
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
                // Two steps: a link without its target must not stay behind.
                if let Err(e) = link.write(0, target.as_bytes()) {
                    let _ = parent.dir.remove(name, false);
                    return Err(e);
                }
                Ok(())
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
                    let kind = parent.dir.lookup(name)?.try_stat()?.kind;
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
                if self.is_mount_point(&join(&parent.path, name)?) {
                    return Err(Errno::EBUSY);
                }
                parent.dir.remove(name, true)
            }
        }
    }

    /// Makes `new` a hard link to the existing non-directory `old` (`link`;
    /// a final symbolic link in `old` is linked itself, not followed).
    ///
    /// `EPERM` for a directory or a file system without hard links, `EEXIST`
    /// if `new` exists, `EXDEV` if the two are on different file systems.
    pub fn link(&self, old: &str, new: &str) -> Result<(), Errno> {
        let target = self.resolve(old, false)?.node;
        if target.try_stat()?.kind == FileKind::Directory {
            return Err(Errno::EPERM);
        }
        let parent = self.parent(new)?;
        match parent.name {
            Some(name) if name != "." && name != ".." && !parent.trailing_slash => parent.dir.link(name, &*target),
            _ => Err(Errno::EEXIST),
        }
    }

    /// Moves `old` to `new` (`rename`), replacing `new` if it exists as
    /// [`File::rename`] describes.
    ///
    /// `EBUSY` for `/` or a mount point, `EINVAL` for `.`, `..` or moving a
    /// directory below itself, `EXDEV` across file systems, `EPERM` where the
    /// file system has no rename.
    pub fn rename(&self, old: &str, new: &str) -> Result<(), Errno> {
        let from = self.parent(old)?;
        let to = self.parent(new)?;
        let (Some(from_name), Some(to_name)) = (from.name, to.name) else { return Err(Errno::EBUSY) };
        if from_name == "." || from_name == ".." || to_name == "." || to_name == ".." {
            return Err(Errno::EINVAL);
        }
        let from_path = join(&from.path, from_name)?;
        let to_path = join(&to.path, to_name)?;
        if self.is_mount_point(&from_path) || self.is_mount_point(&to_path) {
            return Err(Errno::EBUSY);
        }
        let kind = from.dir.lookup(from_name)?.try_stat()?.kind;
        if (from.trailing_slash || to.trailing_slash) && kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if from_path == to_path {
            return Ok(());
        }
        if kind == FileKind::Directory && is_inside(&to_path, &from_path) {
            return Err(Errno::EINVAL);
        }
        from.dir.rename(from_name, &*to.dir, to_name)
    }

    /// The target of the symbolic link `path`.
    pub fn readlink(&self, path: &str) -> Result<String, Errno> {
        let node = self.resolve(path, false)?.node;
        if node.try_stat()?.kind != FileKind::Symlink {
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
        let trailing_slash = check(path)?;
        let mut walker = Walker::new(self.snapshot())?;
        // With a trailing slash the final component must be a directory, so
        // a final symlink is followed regardless.
        walker.walk(path, follow || trailing_slash)?;
        let (node, path) = walker.finish();
        if trailing_slash && node.try_stat()?.kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(Resolved { node, path })
    }

    fn parent<'path>(&self, path: &'path str) -> Result<Parent<'path>, Errno> {
        let trailing_slash = check(path)?;
        let (dirs, name) = split_last(path);
        let mut walker = Walker::new(self.snapshot())?;
        walker.walk(dirs, true)?;
        let (dir, path) = walker.finish();
        if dir.try_stat()?.kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(Parent { dir, path, name, trailing_slash })
    }
}

/// Checks an absolute path (`ENOENT`, `EINVAL`, `ENAMETOOLONG`); returns
/// whether it ended in `/`.
fn check(path: &str) -> Result<bool, Errno> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if !path.starts_with('/') {
        return Err(Errno::EINVAL);
    }
    if path.len() >= PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if path.split('/').any(|c| c.len() > NAME_MAX) {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(path.len() > 1 && path.ends_with('/'))
}

/// An absolute path without its final component, and that component (`None`
/// for `/`).
fn split_last(path: &str) -> (&str, Option<&str>) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((dirs, name)) if !name.is_empty() => (dirs, Some(name)),
        _ => (trimmed, None),
    }
}

/// `dir/name` for a canonical directory path.
fn join(dir: &str, name: &str) -> Result<String, Errno> {
    let mut path = String::new();
    path.try_reserve_exact(dir.len() + 1 + name.len()).map_err(|_| Errno::ENOMEM)?;
    path.push_str(dir);
    if dir != "/" {
        path.push('/');
    }
    path.push_str(name);
    Ok(path)
}

/// Whether canonical `path` is `dir` or below it.
fn is_inside(path: &str, dir: &str) -> bool {
    dir == "/" || path == dir || (path.starts_with(dir) && path.as_bytes().get(dir.len()) == Some(&b'/'))
}

/// What is left to walk: the path being resolved, and the targets of the
/// symbolic links followed so far, the latest first. A target is owned, since
/// the file system made it; the path is borrowed. Each holds the position of
/// its next component.
struct Pending<'path> {
    path: (&'path str, usize),
    links: Vec<(String, usize)>,
}

impl<'path> Pending<'path> {
    /// The next component, skipping empty ones, and the frame it came from
    /// (`None` for the path); advances past it.
    fn next(&mut self) -> Option<(Option<usize>, usize, usize)> {
        fn scan(text: &str, pos: &mut usize) -> Option<(usize, usize)> {
            let bytes = text.as_bytes();
            let rest = bytes.get(*pos..).unwrap_or_default();
            let start = *pos + rest.iter().take_while(|&&b| b == b'/').count();
            let tail = bytes.get(start..).unwrap_or_default();
            let len = tail.iter().position(|&b| b == b'/').unwrap_or(tail.len());
            if len == 0 {
                *pos = text.len();
                return None;
            }
            *pos = start + len;
            Some((start, start + len))
        }
        // A link's target comes before what follows the link.
        while let Some(last) = self.links.len().checked_sub(1) {
            let Some((text, pos)) = self.links.get_mut(last) else { break };
            if let Some((s, e)) = scan(text, pos) {
                return Some((Some(last), s, e));
            }
            self.links.pop();
        }
        let (text, pos) = &mut self.path;
        scan(text, pos).map(|(s, e)| (None, s, e))
    }

    fn component(&self, frame: Option<usize>, start: usize, end: usize) -> &str {
        match frame {
            Some(i) => self.links.get(i).map(|l| l.0.as_str()),
            None => Some(self.path.0),
        }
        .and_then(|text| text.get(start..end))
        .unwrap_or_default()
    }

    /// Whether any component is left.
    fn more(&self) -> bool {
        let has = |text: &str, pos: usize| text.as_bytes().get(pos..).unwrap_or_default().iter().any(|&b| b != b'/');
        has(self.path.0, self.path.1) || self.links.iter().any(|(t, p)| has(t, *p))
    }
}

/// The state of one lookup: the directories walked through from `/`, so that
/// `..` can step back out, including out of a mount.
struct Walker {
    mounts: Arc<Vec<Mount>>,
    /// The root of `/`, where every walk starts.
    root: Arc<dyn File>,
    /// Each node walked into below the root, with the length of its
    /// canonical path in `path`.
    stack: Vec<(Arc<dyn File>, usize)>,
    path: String,
    symlinks: usize,
}

impl Walker {
    fn new(mounts: Arc<Vec<Mount>>) -> Result<Self, Errno> {
        // The original `/` mount is never removed.
        let root = Self::covering(&mounts, "/").ok_or(Errno::ENOENT)?;
        Ok(Walker { mounts, root, stack: Vec::new(), path: try_string("/")?, symlinks: 0 })
    }

    /// The root of the most recent mount on `path`.
    fn covering(mounts: &[Mount], path: &str) -> Option<Arc<dyn File>> {
        mounts.iter().rev().find(|m| m.path == path).map(|m| m.root.clone())
    }

    fn top(&self) -> &Arc<dyn File> {
        self.stack.last().map_or(&self.root, |entry| &entry.0)
    }

    fn finish(mut self) -> (Arc<dyn File>, String) {
        let node = self.stack.pop().map_or(self.root, |entry| entry.0);
        (node, self.path)
    }

    /// Walks the components of `path` from the current node. A symbolic link
    /// is followed unless it is the final component and `follow_last` is
    /// false.
    fn walk(&mut self, path: &str, follow_last: bool) -> Result<(), Errno> {
        let mut pending = Pending { path: (path, 0), links: Vec::new() };
        while let Some((frame, s, e)) = pending.next() {
            if self.top().try_stat()?.kind != FileKind::Directory {
                return Err(Errno::ENOTDIR);
            }
            let comp = pending.component(frame, s, e);
            match comp {
                "." => continue,
                ".." => {
                    if self.stack.pop().is_some() {
                        let len = self.stack.last().map_or(1, |entry| entry.1);
                        self.path.truncate(len);
                    }
                    continue;
                }
                _ => {}
            }
            let mut node = self.top().lookup(comp)?;
            let path = join(&self.path, comp)?;
            if let Some(root) = Self::covering(&self.mounts, &path) {
                node = root;
            }
            if node.try_stat()?.kind == FileKind::Symlink && (follow_last || pending.more()) {
                self.symlinks += 1;
                if self.symlinks > MAX_SYMLINKS {
                    return Err(Errno::ELOOP);
                }
                let target = node.readlink()?;
                if target.is_empty() {
                    return Err(Errno::ENOENT);
                }
                if target.starts_with('/') {
                    self.stack.clear();
                    self.path.truncate(1);
                }
                try_push(&mut pending.links, (target, 0))?;
                continue;
            }
            self.stack.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            self.path = path;
            self.stack.push((node, self.path.len()));
        }
        Ok(())
    }
}
