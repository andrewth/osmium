//! A union of directory trees: a writable upper tree over read-only lower
//! ones.
//!
//! The layers are any [`File`] directories, on any file systems. A name is
//! looked up in the upper layer, then in each lower one in turn. Directories
//! of the same name merge; any other kind of node hides what is below it.
//! Changing a lower node first copies it up (kind, permission bits and
//! contents, its parents too) into the upper layer. Removing a name that a
//! lower layer still has leaves a *whiteout* in the upper one, and a
//! directory made where a name was removed is marked *opaque*, so nothing
//! below shows through. How whiteouts and opaque directories are recorded is
//! up to a [`Markers`] strategy; [`DeviceMarkers`], the default, needs
//! nothing from the upper layer but the ordinary [`File`] operations.
//!
//! ```
//! use osmium_fs::overlay::OverlayFs;
//! use osmium_fs::{File, OpenFlags, RamFs, Vfs};
//!
//! let lower = Vfs::new(RamFs::new(1).root());
//! lower.open("/etc", OpenFlags::CREATE, 0o644).unwrap().write(0, b"base").unwrap();
//! let upper = RamFs::new(2);
//! let overlay = OverlayFs::new(3, Some(upper.root()), vec![lower.lookup("/").unwrap()]).unwrap();
//! let vfs = Vfs::new(overlay.root());
//! vfs.lookup("/etc").unwrap().write(0, b"BASE").unwrap(); // copies up
//! let mut buf = [0; 4];
//! lower.lookup("/etc").unwrap().read(0, &mut buf).unwrap();
//! assert_eq!(&buf, b"base"); // the lower layer is untouched
//! ```
//!
//! What this is not:
//!
//! - Renaming a directory that has lower contents fails with `EXDEV`, as
//!   Linux's overlayfs does without `redirect_dir`; the caller copies it.
//! - There is no inode index: a hard link to a lower file comes apart when it
//!   is copied up, and the link is made to the copy.
//! - A copy-up cannot carry what [`File`] has no way to set: times, owners,
//!   extended attributes, and the device number of a device node.
//! - Inode numbers are the topmost layer's, tagged with its position in the
//!   top byte, so a node's number changes when it is copied up.
//! - Removing, renaming over and making a name leaves the upper layer in
//!   between states for a moment (a whiteout is made after the name is
//!   removed). The layers are not changed atomically; a crash in the
//!   middle of an operation can leave a name showing through.
//! - A node opened before another handle copied the same file up keeps
//!   reading the lower layer until it writes (its copy-up then adopts the
//!   one that exists).
//! - Listing a directory builds the whole merged listing, for each call.
//! - Names starting with `.ovl-tmp-` and the markers' own names are reserved.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use osmium_sync::SpinLock;
use osmium_sync::fallible::{try_arc, try_push, try_string, try_zeroed};

use crate::{DirEntry, Errno, File, FileKind, NAME_MAX, Stat};

/// Most lower layers an overlay stacks (a layer's position is tagged into
/// inode numbers in a byte).
pub const MAX_LAYERS: usize = 200;

/// Bytes moved at a time when a file is copied up.
const COPY_CHUNK: usize = 64 << 10;

/// Prefix of the names copy-up works under before renaming into place.
const TEMP_PREFIX: &str = ".ovl-tmp-";

/// Where the position of the layer an inode number came from goes.
const LAYER_SHIFT: u32 = 56;

/// How whiteouts and opaque directories are recorded in a layer.
///
/// Implementations work through [`File`] operations on the *upper* layer, so
/// the representation has to be something that layer can hold. Lower layers
/// are only read: [`is_whiteout`](Markers::is_whiteout) and
/// [`is_opaque`](Markers::is_opaque) run on them too.
pub trait Markers: Send + Sync {
    /// Whether `entry`, found by name in a layer's directory, is a whiteout:
    /// the name is removed, whatever the layers below hold.
    fn is_whiteout(&self, entry: &dyn File) -> bool;

    /// Records in the upper directory `dir` that `name` is removed. `name` is
    /// not in `dir` at the time.
    fn make_whiteout(&self, dir: &dyn File, name: &str) -> Result<(), Errno>;

    /// Whether the directory `dir` is opaque: the layers below its own do not
    /// contribute to the merged directory.
    fn is_opaque(&self, dir: &dyn File) -> Result<bool, Errno>;

    /// Marks the upper directory `dir` opaque.
    fn set_opaque(&self, dir: &dyn File) -> Result<(), Errno>;

    /// Whether `name` is one of the markers' own entries, which listings and
    /// lookups of the merged tree leave out and creation refuses.
    fn is_hidden(&self, name: &str) -> bool;
}

/// Name of the marker entry [`DeviceMarkers`] puts in an opaque directory.
pub const OPAQUE_NAME: &str = ".wh..wh..opq";

/// Linux's whiteout format, as far as it can go without extended attributes:
/// a whiteout is a character device node with device number 0, and a directory
/// is opaque when it holds an entry named [`OPAQUE_NAME`] (the name the aufs
/// file system uses; Linux itself uses an extended attribute).
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceMarkers;

impl Markers for DeviceMarkers {
    fn is_whiteout(&self, entry: &dyn File) -> bool {
        let st = entry.stat();
        st.kind == FileKind::CharDevice && st.rdev == 0
    }

    fn make_whiteout(&self, dir: &dyn File, name: &str) -> Result<(), Errno> {
        dir.create(name, FileKind::CharDevice, 0).map(drop)
    }

    fn is_opaque(&self, dir: &dyn File) -> Result<bool, Errno> {
        match dir.lookup(OPAQUE_NAME) {
            Ok(_) => Ok(true),
            Err(Errno::ENOENT) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn set_opaque(&self, dir: &dyn File) -> Result<(), Errno> {
        match dir.create(OPAQUE_NAME, FileKind::Regular, 0) {
            Ok(_) | Err(Errno::EEXIST) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn is_hidden(&self, name: &str) -> bool {
        name == OPAQUE_NAME
    }
}

/// A layer: its position (0 is the upper layer) and its directory.
type Layer = (usize, Arc<dyn File>);

struct Shared {
    dev: u64,
    markers: Arc<dyn Markers>,
    writable: bool,
    /// Held while a node is copied up, so two copy-ups do not race for the
    /// same name.
    copy_up: SpinLock<()>,
    next_tmp: AtomicU64,
}

impl Shared {
    fn reserved(&self, name: &str) -> bool {
        name.starts_with(TEMP_PREFIX) || self.markers.is_hidden(name)
    }
}

/// The union of an upper and some lower trees. [`root`](OverlayFs::root) is
/// the merged top directory.
pub struct OverlayFs {
    root: OvNode,
}

impl OverlayFs {
    /// The union of `upper` (writable; `None` makes the overlay read-only) and
    /// `lower`, topmost first, using [`DeviceMarkers`]. `dev` is reported as
    /// every node's `st_dev`.
    ///
    /// `EINVAL` with no layers or more than [`MAX_LAYERS`] lower ones;
    /// `ENOTDIR` if a layer is not a directory.
    pub fn new(dev: u64, upper: Option<Arc<dyn File>>, lower: Vec<Arc<dyn File>>) -> Result<Self, Errno> {
        Self::with_markers(dev, upper, lower, try_arc(DeviceMarkers)?)
    }

    /// [`OverlayFs::new`] with whiteouts and opaque directories kept by
    /// `markers`.
    pub fn with_markers(
        dev: u64,
        upper: Option<Arc<dyn File>>,
        lower: Vec<Arc<dyn File>>,
        markers: Arc<dyn Markers>,
    ) -> Result<Self, Errno> {
        if lower.len() > MAX_LAYERS || (upper.is_none() && lower.is_empty()) {
            return Err(Errno::EINVAL);
        }
        for layer in upper.iter().chain(&lower) {
            if layer.try_stat()?.kind != FileKind::Directory {
                return Err(Errno::ENOTDIR);
            }
        }
        let shared = try_arc(Shared {
            dev,
            markers,
            writable: upper.is_some(),
            copy_up: SpinLock::new(()),
            next_tmp: AtomicU64::new(0),
        })?;
        let mut layers = Layers { upper, lower: Vec::new() };
        for (i, dir) in lower.into_iter().enumerate() {
            try_push(&mut layers.lower, (i + 1, dir))?;
        }
        Ok(OverlayFs { root: OvNode::make(&shared, None, "", FileKind::Directory, layers)? })
    }

    /// The merged root directory, to pass to [`Vfs::new`](crate::Vfs::new) or
    /// [`Vfs::mount`](crate::Vfs::mount).
    pub fn root(&self) -> Arc<dyn File> {
        Arc::new(OvNode(self.root.0.clone()))
    }
}

/// What a node is in each layer.
struct Layers {
    upper: Option<Arc<dyn File>>,
    /// For a directory, the lower directories merged into it; for anything
    /// else, at most the lower node it is (until it is copied up).
    lower: Vec<Layer>,
}

/// A node of the merged tree.
struct NodeData {
    shared: Arc<Shared>,
    /// The directory it was found in and its name there (none for the root).
    parent: Option<Arc<NodeData>>,
    name: String,
    kind: FileKind,
    layers: SpinLock<Layers>,
}

/// A node of an [`OverlayFs`].
struct OvNode(Arc<NodeData>);

/// The node, or what is known of a name before there is a node for it.
struct Found {
    layers: Layers,
    kind: FileKind,
}

impl OvNode {
    fn make(
        shared: &Arc<Shared>,
        parent: Option<&Arc<NodeData>>,
        name: &str,
        kind: FileKind,
        layers: Layers,
    ) -> Result<OvNode, Errno> {
        Ok(OvNode(try_arc(NodeData {
            shared: shared.clone(),
            parent: parent.cloned(),
            name: try_string(name)?,
            kind,
            layers: SpinLock::new(layers),
        })?))
    }
}

/// The tag in the top byte of an inode number from layer `layer`.
fn tag(layer: usize, ino: u64) -> u64 {
    (ino & ((1 << LAYER_SHIFT) - 1)) | ((layer as u64) << LAYER_SHIFT)
}

/// Checks a name passed to a method that makes one.
fn check_name(shared: &Shared, name: &str) -> Result<(), Errno> {
    if name.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) || shared.reserved(name) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

impl NodeData {
    fn upper(&self) -> Option<Arc<dyn File>> {
        self.layers.lock().upper.clone()
    }

    fn has_lower(&self) -> bool {
        !self.layers.lock().lower.is_empty()
    }

    /// Its layers, upper first.
    fn layer_list(&self) -> Result<Vec<Layer>, Errno> {
        let layers = self.layers.lock();
        let mut out = Vec::new();
        out.try_reserve(layers.lower.len() + 1).map_err(|_| Errno::ENOMEM)?;
        if let Some(upper) = &layers.upper {
            out.push((0, upper.clone()));
        }
        out.extend(layers.lower.iter().cloned());
        Ok(out)
    }

    /// Its topmost layer.
    fn top(&self) -> Result<Layer, Errno> {
        let layers = self.layers.lock();
        match (&layers.upper, layers.lower.first()) {
            (Some(upper), _) => Ok((0, upper.clone())),
            (None, Some(lower)) => Ok(lower.clone()),
            (None, None) => Err(Errno::EIO),
        }
    }

    fn require_dir(&self) -> Result<(), Errno> {
        if self.kind == FileKind::Directory { Ok(()) } else { Err(Errno::ENOTDIR) }
    }

    fn require_writable(&self) -> Result<(), Errno> {
        if self.shared.writable { Ok(()) } else { Err(Errno::EROFS) }
    }

    /// What `name` is in the merged directory made of `layers` (upper first),
    /// or `None` if it is not there.
    fn resolve(&self, layers: &[Layer], name: &str) -> Result<Option<Found>, Errno> {
        let markers = &self.shared.markers;
        let mut found = Layers { upper: None, lower: Vec::new() };
        let mut kind = None;
        for (idx, dir) in layers {
            let child = match dir.lookup(name) {
                Ok(child) => child,
                Err(Errno::ENOENT) => continue,
                Err(e) => return Err(e),
            };
            if markers.is_whiteout(&*child) {
                break;
            }
            let child_kind = child.try_stat()?.kind;
            match kind {
                None => kind = Some(child_kind),
                // Only directories merge: a node of another kind below one hides.
                Some(_) if child_kind != FileKind::Directory => break,
                Some(_) => {}
            }
            if *idx == 0 {
                found.upper = Some(child.clone());
            } else {
                try_push(&mut found.lower, (*idx, child.clone()))?;
            }
            if child_kind != FileKind::Directory || markers.is_opaque(&*child)? {
                break;
            }
        }
        Ok(kind.map(|kind| Found { layers: found, kind }))
    }

    /// The node for `name` of this directory.
    fn lookup_node(self: &Arc<Self>, name: &str) -> Result<OvNode, Errno> {
        self.require_dir()?;
        if self.shared.reserved(name) {
            return Err(Errno::ENOENT);
        }
        let found = self.resolve(&self.layer_list()?, name)?.ok_or(Errno::ENOENT)?;
        OvNode::make(&self.shared, Some(self), name, found.kind, found.layers)
    }

    /// Whether a lower layer shows `name` of this directory (what a removed
    /// or replaced name needs a whiteout for).
    fn lower_shows(&self, name: &str) -> Result<bool, Errno> {
        let lower: Vec<Layer> = self.layers.lock().lower.clone();
        Ok(self.resolve(&lower, name)?.is_some())
    }

    /// The merged entries of this directory.
    fn list(&self) -> Result<Vec<DirEntry>, Errno> {
        self.require_dir()?;
        let markers = &self.shared.markers;
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (idx, dir) in self.layer_list()? {
            let mut i = 0;
            while let Some(entry) = dir.readdir(i)? {
                i += 1;
                if self.shared.reserved(&entry.name) || seen.contains(&entry.name) {
                    continue;
                }
                // A name seen in a layer hides the same name below, a
                // whiteout included.
                seen.insert(try_string(&entry.name)?);
                if entry.kind == FileKind::CharDevice && markers.is_whiteout(&*dir.lookup(&entry.name)?) {
                    continue;
                }
                try_push(&mut out, DirEntry { ino: tag(idx, entry.ino), ..entry })?;
            }
        }
        Ok(out)
    }

    /// The upper directory `self` is in, made (with its parents) if need be.
    fn upper_dir(self: &Arc<Self>) -> Result<Arc<dyn File>, Errno> {
        self.require_dir()?;
        self.ensure_upper()
    }

    /// The node's upper-layer file, copying it up first if it has none.
    fn ensure_upper(self: &Arc<Self>) -> Result<Arc<dyn File>, Errno> {
        self.require_writable()?;
        if let Some(upper) = self.upper() {
            return Ok(upper);
        }
        let _serial = self.shared.copy_up.lock();
        self.copy_up_locked()
    }

    fn copy_up_locked(self: &Arc<Self>) -> Result<Arc<dyn File>, Errno> {
        if let Some(upper) = self.upper() {
            return Ok(upper);
        }
        let parent = self.parent.as_ref().ok_or(Errno::EIO)?;
        let dir = parent.copy_up_locked()?;
        let (_, source) = self.top()?;
        let stat = source.try_stat()?;
        // Someone else's copy-up (of another node for the same name) came
        // first: use theirs.
        let upper = match dir.lookup(&self.name) {
            Ok(existing) if !self.shared.markers.is_whiteout(&*existing) => {
                if existing.try_stat()?.kind != self.kind {
                    return Err(Errno::ENOENT);
                }
                existing
            }
            Ok(_) => return Err(Errno::ENOENT),
            Err(Errno::ENOENT) => self.copy_into(&*dir, &*source, &stat)?,
            Err(e) => return Err(e),
        };
        let mut layers = self.layers.lock();
        layers.upper = Some(upper.clone());
        if self.kind != FileKind::Directory {
            layers.lower.clear();
        }
        Ok(upper)
    }

    /// Makes a copy of `source` as the entry named like `self` in `dir`.
    fn copy_into(&self, dir: &dyn File, source: &dyn File, stat: &Stat) -> Result<Arc<dyn File>, Errno> {
        match self.kind {
            FileKind::Regular | FileKind::Symlink => {
                // Put together under another name, so that nobody sees half a file.
                let tmp = format!("{TEMP_PREFIX}{}", self.shared.next_tmp.fetch_add(1, Ordering::Relaxed));
                let copy = dir.create(&tmp, self.kind, stat.mode)?;
                let done = self.fill(&*copy, source).and_then(|()| dir.rename(&tmp, dir, &self.name));
                if let Err(e) = done {
                    let _ = dir.remove(&tmp, false);
                    return Err(e);
                }
                dir.lookup(&self.name)
            }
            // Directories and nodes with nothing to copy but their kind.
            kind => dir.create(&self.name, kind, stat.mode),
        }
    }

    fn fill(&self, copy: &dyn File, source: &dyn File) -> Result<(), Errno> {
        if self.kind == FileKind::Symlink {
            let target = source.readlink()?;
            if !target.is_empty() {
                copy.write(0, target.as_bytes())?;
            }
            return Ok(());
        }
        let mut buf = try_zeroed(COPY_CHUNK)?;
        let mut off = 0;
        loop {
            let n = source.read(off, &mut buf)?;
            let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else { return Ok(()) };
            let mut done = 0;
            while let Some(rest) = chunk.get(done..).filter(|r| !r.is_empty()) {
                done += copy.write(off + done as u64, rest)?;
            }
            off += n as u64;
        }
    }

    /// Removes everything from the upper directory `dir`, which is empty
    /// in the merged tree and so holds only markers and leftovers.
    fn clear(dir: &dyn File) -> Result<(), Errno> {
        while let Some(entry) = dir.readdir(0)? {
            dir.remove(&entry.name, entry.kind == FileKind::Directory)?;
        }
        Ok(())
    }
}

impl File for OvNode {
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.0.top()?.1.read(off, buf)
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        if self.0.kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        self.0.ensure_upper()?.write(off, buf)
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        if self.0.kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        self.0.ensure_upper()?.truncate(len)
    }

    fn stat(&self) -> Stat {
        self.try_stat().unwrap_or_default()
    }

    fn try_stat(&self) -> Result<Stat, Errno> {
        let (idx, top) = self.0.top()?;
        let mut stat = top.try_stat()?;
        stat.dev = self.0.shared.dev;
        stat.ino = tag(idx, stat.ino);
        // As Linux reports a merged directory: its link count says nothing.
        if stat.kind == FileKind::Directory && self.0.has_lower() {
            stat.nlink = 1;
        }
        Ok(stat)
    }

    fn sync(&self) -> Result<(), Errno> {
        match self.0.upper() {
            Some(upper) => upper.sync(),
            None => Ok(()),
        }
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        Ok(self.0.list()?.into_iter().nth(index))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        Ok(Arc::new(self.0.lookup_node(name)?))
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        let d = &self.0;
        d.require_dir()?;
        check_name(&d.shared, name)?;
        d.require_writable()?;
        match d.lookup_node(name) {
            Ok(_) => return Err(Errno::EEXIST),
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        let dir = d.upper_dir()?;
        // A whiteout in the way is replaced by the new node.
        let hid = match dir.lookup(name) {
            Ok(entry) if d.shared.markers.is_whiteout(&*entry) => {
                dir.remove(name, false)?;
                true
            }
            Ok(_) => return Err(Errno::EEXIST),
            Err(Errno::ENOENT) => false,
            Err(e) => return Err(e),
        };
        let made = dir.create(name, kind, mode)?;
        // Over a removed directory a new one must not show the old contents.
        if hid && kind == FileKind::Directory {
            let marked = d.shared.markers.set_opaque(&*made);
            if marked.is_err() {
                let _ = dir.remove(name, true);
                let _ = d.shared.markers.make_whiteout(&*dir, name);
            }
            marked?;
        }
        let layers = Layers { upper: Some(made), lower: Vec::new() };
        Ok(Arc::new(OvNode::make(&d.shared, Some(d), name, kind, layers)?))
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        let d = &self.0;
        d.require_dir()?;
        d.require_writable()?;
        let target = d.lookup_node(name)?;
        match (dir, target.0.kind == FileKind::Directory) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if !target.0.list()?.is_empty() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        let shows = d.lower_shows(name)?;
        let parent = d.upper_dir()?;
        if let Some(upper) = target.0.upper() {
            if dir {
                NodeData::clear(&*upper)?;
            }
            parent.remove(name, dir)?;
        }
        if shows {
            d.shared.markers.make_whiteout(&*parent, name)?;
        }
        Ok(())
    }

    fn link(&self, name: &str, target: &dyn File) -> Result<(), Errno> {
        let d = &self.0;
        d.require_dir()?;
        check_name(&d.shared, name)?;
        let target = target.as_any().and_then(|a| a.downcast_ref::<OvNode>()).ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&target.0.shared, &d.shared) {
            return Err(Errno::EXDEV);
        }
        d.require_writable()?;
        if target.0.kind == FileKind::Directory {
            return Err(Errno::EPERM);
        }
        match d.lookup_node(name) {
            Ok(_) => return Err(Errno::EEXIST),
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        let dir = d.upper_dir()?;
        let upper = target.0.ensure_upper()?;
        match dir.lookup(name) {
            Ok(entry) if d.shared.markers.is_whiteout(&*entry) => dir.remove(name, false)?,
            Ok(_) => return Err(Errno::EEXIST),
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        dir.link(name, &*upper)
    }

    fn rename(&self, old_name: &str, new_dir: &dyn File, new_name: &str) -> Result<(), Errno> {
        let d = &self.0;
        d.require_dir()?;
        check_name(&d.shared, new_name)?;
        let nd = &new_dir.as_any().and_then(|a| a.downcast_ref::<OvNode>()).ok_or(Errno::EXDEV)?.0;
        if !Arc::ptr_eq(&nd.shared, &d.shared) {
            return Err(Errno::EXDEV);
        }
        nd.require_dir()?;
        d.require_writable()?;
        let src = d.lookup_node(old_name)?;
        let is_dir = src.0.kind == FileKind::Directory;
        let dst = match nd.lookup_node(new_name) {
            Ok(dst) => Some(dst),
            Err(Errno::ENOENT) => None,
            Err(e) => return Err(e),
        };
        if let Some(dst) = &dst {
            let (a, b) = (src.try_stat()?, dst.try_stat()?);
            if (a.dev, a.ino, a.kind) == (b.dev, b.ino, b.kind) && a.kind != FileKind::Directory {
                return Ok(());
            }
            match (is_dir, dst.0.kind == FileKind::Directory) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                (true, true) if !dst.0.list()?.is_empty() => return Err(Errno::ENOTEMPTY),
                _ => {}
            }
        }
        // Without `redirect_dir` a directory with lower contents cannot move.
        if is_dir && src.0.has_lower() {
            return Err(Errno::EXDEV);
        }
        if is_dir {
            // A directory into itself.
            let moved = src.0.upper().ok_or(Errno::EIO)?.try_stat()?;
            let mut at = Some(nd.clone());
            while let Some(node) = at {
                if let Some(up) = node.upper() {
                    let st = up.try_stat()?;
                    if (st.dev, st.ino) == (moved.dev, moved.ino) {
                        return Err(Errno::EINVAL);
                    }
                }
                at = node.parent.clone();
            }
        }
        let from = d.upper_dir()?;
        let to = nd.upper_dir()?;
        src.0.ensure_upper()?;
        let markers = &d.shared.markers;
        // Whatever the new name has in the upper layer (a whiteout, or the
        // directory being replaced, which only holds markers) is cleared.
        match to.lookup(new_name) {
            Ok(entry) if markers.is_whiteout(&*entry) => to.remove(new_name, false)?,
            Ok(entry) if dst.is_some() && dst.as_ref().is_some_and(|dst| dst.0.kind == FileKind::Directory) => {
                NodeData::clear(&*entry)?
            }
            Ok(_) | Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        let shows_new = nd.lower_shows(new_name)?;
        let shows_old = d.lower_shows(old_name)?;
        from.rename(old_name, &*to, new_name)?;
        if is_dir && shows_new {
            let moved = to.lookup(new_name)?;
            markers.set_opaque(&*moved)?;
        }
        if shows_old {
            markers.make_whiteout(&*from, old_name)?;
        }
        Ok(())
    }

    fn readlink(&self) -> Result<String, Errno> {
        self.0.top()?.1.readlink()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenFlags, RamFs, Vfs};
    use alloc::string::ToString;
    use alloc::vec;
    use core::sync::atomic::AtomicUsize;

    const RW: OpenFlags = OpenFlags::READ.union(OpenFlags::WRITE);

    fn put(vfs: &Vfs, path: &str, data: &[u8]) {
        vfs.open(path, RW | OpenFlags::CREATE, 0o644).unwrap().write(0, data).unwrap();
    }

    fn read(vfs: &Vfs, path: &str) -> Vec<u8> {
        let f = vfs.lookup(path).unwrap();
        let mut out = vec![0; 256];
        let n = f.read(0, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn names(vfs: &Vfs, path: &str) -> Vec<String> {
        let dir = vfs.lookup(path).unwrap();
        let mut v: Vec<String> = (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect();
        v.sort();
        v
    }

    struct Fixture {
        lower: Vfs,
        lower2: Vfs,
        upper: Vfs,
        overlay: Vfs,
    }

    /// `lower`: /a, /dir/{x,y}, /dir/sub/z, /link -> a, /ro (mode 0444).
    /// `lower2` (below it): /b, /dir/w, /a (shadowed), /only2/f.
    fn fixture() -> Fixture {
        let lower = Vfs::new(RamFs::new(1).root());
        put(&lower, "/a", b"lower a");
        lower.mkdir("/dir", 0o750).unwrap();
        put(&lower, "/dir/x", b"x");
        put(&lower, "/dir/y", b"y");
        lower.mkdir("/dir/sub", 0o755).unwrap();
        put(&lower, "/dir/sub/z", b"z");
        lower.symlink("a", "/link").unwrap();
        lower.open("/ro", OpenFlags::CREATE, 0o444).unwrap().write(0, b"read only").unwrap();
        let lower2 = Vfs::new(RamFs::new(2).root());
        put(&lower2, "/b", b"lower2 b");
        put(&lower2, "/a", b"lower2 a");
        lower2.mkdir("/dir", 0o700).unwrap();
        put(&lower2, "/dir/w", b"w");
        lower2.mkdir("/only2", 0o755).unwrap();
        put(&lower2, "/only2/f", b"f");
        let upper = Vfs::new(RamFs::new(3).root());
        let fs = OverlayFs::new(
            4,
            Some(upper.lookup("/").unwrap()),
            vec![lower.lookup("/").unwrap(), lower2.lookup("/").unwrap()],
        )
        .unwrap();
        Fixture { lower, lower2, upper, overlay: Vfs::new(fs.root()) }
    }

    fn is_whiteout(vfs: &Vfs, path: &str) -> bool {
        vfs.stat(path, false).is_ok_and(|st| st.kind == FileKind::CharDevice && st.rdev == 0)
    }

    #[test]
    fn merges_layers() {
        let f = fixture();
        assert_eq!(names(&f.overlay, "/"), ["a", "b", "dir", "link", "only2", "ro"]);
        // The upper layer's version wins, then the first lower's.
        assert_eq!(read(&f.overlay, "/a"), b"lower a");
        assert_eq!(read(&f.overlay, "/b"), b"lower2 b");
        // Directories merge across all three layers.
        assert_eq!(names(&f.overlay, "/dir"), ["sub", "w", "x", "y"]);
        assert_eq!(read(&f.overlay, "/dir/w"), b"w");
        assert_eq!(read(&f.overlay, "/dir/sub/z"), b"z");
        assert_eq!(read(&f.overlay, "/only2/f"), b"f");
        // A merged directory has the topmost layer's mode and a link count of 1.
        let st = f.overlay.stat("/dir", true).unwrap();
        assert_eq!((st.kind, st.mode, st.nlink, st.dev), (FileKind::Directory, 0o750, 1, 4));
        assert_eq!(f.overlay.stat("/only2", true).unwrap().nlink, 1);
        assert_eq!(f.overlay.lookup("/nothing").err(), Some(Errno::ENOENT));
        assert_eq!(f.overlay.lookup("/a/x").err(), Some(Errno::ENOTDIR));
        // Links resolve through the merged tree.
        assert_eq!(f.overlay.readlink("/link").unwrap(), "a");
        assert_eq!(read(&f.overlay, "/link"), b"lower a");
        // Nothing was written below.
        assert_eq!(names(&f.upper, "/"), Vec::<String>::new());
    }

    #[test]
    fn a_node_hides_what_is_below_it() {
        let f = fixture();
        // A file in the upper layer over a directory below, and the reverse.
        put(&f.upper, "/dir", b"now a file");
        f.upper.mkdir("/a", 0o755).unwrap();
        put(&f.upper, "/a/n", b"n");
        let st = f.overlay.stat("/dir", true).unwrap();
        assert_eq!(st.kind, FileKind::Regular);
        assert_eq!(read(&f.overlay, "/dir"), b"now a file");
        assert_eq!(f.overlay.lookup("/dir/x").err(), Some(Errno::ENOTDIR));
        assert_eq!(f.overlay.stat("/a", true).unwrap().kind, FileKind::Directory);
        assert_eq!(names(&f.overlay, "/a"), ["n"]);
        let root = names(&f.overlay, "/");
        assert_eq!(root.iter().filter(|n| *n == "dir").count(), 1);
    }

    #[test]
    fn whiteouts_and_opaque_directories_in_the_layers_below_count() {
        let f = fixture();
        // lower hides lower2's /b, and makes /dir opaque.
        f.lower.open("/b", OpenFlags::CREATE, 0o644).unwrap();
        f.lower.unlink("/b").unwrap();
        f.lower.lookup("/").unwrap().create("b", FileKind::CharDevice, 0).unwrap();
        f.lower.lookup("/dir").unwrap().create(OPAQUE_NAME, FileKind::Regular, 0).unwrap();
        assert_eq!(f.overlay.lookup("/b").err(), Some(Errno::ENOENT));
        assert!(!names(&f.overlay, "/").contains(&"b".to_string()));
        assert_eq!(names(&f.overlay, "/dir"), ["sub", "x", "y"]);
        assert_eq!(f.overlay.lookup("/dir/w").err(), Some(Errno::ENOENT));
        // The marker is not shown.
        assert_eq!(f.overlay.lookup(&format!("/dir/{OPAQUE_NAME}")).err(), Some(Errno::ENOENT));
    }

    #[test]
    fn read_only_overlay() {
        let f = fixture();
        let fs = OverlayFs::new(5, None, vec![f.lower.lookup("/").unwrap(), f.lower2.lookup("/").unwrap()]).unwrap();
        let vfs = Vfs::new(fs.root());
        assert_eq!(read(&vfs, "/b"), b"lower2 b");
        assert_eq!(vfs.lookup("/a").unwrap().write(0, b"x").err(), Some(Errno::EROFS));
        assert_eq!(vfs.lookup("/a").unwrap().truncate(0).err(), Some(Errno::EROFS));
        assert_eq!(vfs.mkdir("/n", 0o755).err(), Some(Errno::EROFS));
        assert_eq!(vfs.unlink("/a").err(), Some(Errno::EROFS));
        assert_eq!(vfs.rename("/a", "/c").err(), Some(Errno::EROFS));
        assert_eq!(vfs.link("/a", "/c").err(), Some(Errno::EROFS));
        assert_eq!(read(&vfs, "/a"), b"lower a");
    }

    #[test]
    fn bad_layers() {
        let f = fixture();
        let file = f.lower.lookup("/a").unwrap();
        let dir = f.lower.lookup("/").unwrap();
        assert_eq!(OverlayFs::new(1, None, vec![]).err(), Some(Errno::EINVAL));
        assert_eq!(OverlayFs::new(1, Some(file.clone()), vec![dir.clone()]).err(), Some(Errno::ENOTDIR));
        assert_eq!(OverlayFs::new(1, None, vec![file]).err(), Some(Errno::ENOTDIR));
        let many = vec![dir.clone(); MAX_LAYERS + 1];
        assert_eq!(OverlayFs::new(1, None, many).err(), Some(Errno::EINVAL));
        assert!(OverlayFs::new(1, Some(dir), vec![]).is_ok());
    }

    #[test]
    fn writing_copies_up() {
        let f = fixture();
        let node = f.overlay.open("/dir/x", RW, 0).unwrap();
        // Opening changed nothing.
        assert_eq!(names(&f.upper, "/"), Vec::<String>::new());
        assert_eq!(node.write(1, b"yz").unwrap(), 2);
        assert_eq!(read(&f.overlay, "/dir/x"), b"xyz");
        // The change is in the upper layer, whose parents were made with the
        // lower directory's mode; the lower layer is as it was.
        assert_eq!(read(&f.upper, "/dir/x"), b"xyz");
        assert_eq!(f.upper.stat("/dir", true).unwrap().mode, 0o750);
        assert_eq!(read(&f.lower, "/dir/x"), b"x");
        assert_eq!(names(&f.upper, "/"), ["dir"]);
        assert_eq!(names(&f.upper, "/dir"), ["x"]);
        // The merged directory still shows the other lower entries.
        assert_eq!(names(&f.overlay, "/dir"), ["sub", "w", "x", "y"]);
        // The file keeps its mode.
        f.overlay.lookup("/ro").unwrap().write(0, b"READ").unwrap();
        assert_eq!(f.upper.stat("/ro", true).unwrap().mode, 0o444);
        assert_eq!(read(&f.overlay, "/ro"), b"READ only");
        // No copy-up leftovers.
        assert!(!names(&f.upper, "/").iter().any(|n| n.starts_with(TEMP_PREFIX)));
    }

    #[test]
    fn truncating_and_big_files() {
        let f = fixture();
        f.overlay.lookup("/a").unwrap().truncate(5).unwrap();
        assert_eq!(read(&f.overlay, "/a"), b"lower");
        assert_eq!(read(&f.lower, "/a"), b"lower a");
        let big: Vec<u8> = (0..COPY_CHUNK * 2 + 123).map(|i| (i % 251) as u8).collect();
        let node = f.lower.open("/big", RW | OpenFlags::CREATE, 0o600).unwrap();
        node.write(0, &big).unwrap();
        f.overlay.lookup("/big").unwrap().write(0, b"!").unwrap();
        let copy = f.upper.lookup("/big").unwrap();
        assert_eq!(copy.stat().size, big.len() as u64);
        let mut buf = vec![0; big.len()];
        assert_eq!(copy.read(0, &mut buf).unwrap(), big.len());
        assert_eq!(buf.get(1..), big.get(1..));
        assert_eq!(buf.first(), Some(&b'!'));
        assert_eq!(f.upper.stat("/big", true).unwrap().mode, 0o600);
    }

    #[test]
    fn symlinks_copy_up() {
        let f = fixture();
        let link = f.overlay.lookup("/link");
        assert!(link.is_ok());
        // Copy up through a handle on the link itself.
        let root = f.overlay.lookup("/").unwrap();
        let node = root.lookup("link").unwrap();
        assert_eq!(node.stat().kind, FileKind::Symlink);
        // Removing and remaking it replaces it.
        f.overlay.unlink("/link").unwrap();
        f.overlay.symlink("b", "/link").unwrap();
        assert_eq!(f.overlay.readlink("/link").unwrap(), "b");
        assert_eq!(read(&f.overlay, "/link"), b"lower2 b");
        assert_eq!(f.lower.readlink("/link").unwrap(), "a");
    }

    #[test]
    fn a_copied_up_link_keeps_its_target() {
        let f = fixture();
        // Rename forces a copy-up of the link.
        f.overlay.rename("/link", "/moved").unwrap();
        assert_eq!(f.upper.readlink("/moved").unwrap(), "a");
        assert_eq!(f.overlay.readlink("/moved").unwrap(), "a");
        assert_eq!(f.overlay.lookup("/link").err(), Some(Errno::ENOENT));
        assert!(is_whiteout(&f.upper, "/link"));
    }

    #[test]
    fn creating() {
        let f = fixture();
        put(&f.overlay, "/new", b"new");
        assert_eq!(read(&f.upper, "/new"), b"new");
        // In a lower directory: its upper counterpart is made first.
        put(&f.overlay, "/dir/sub/n", b"n");
        assert_eq!(names(&f.upper, "/dir/sub"), ["n"]);
        assert_eq!(names(&f.overlay, "/dir/sub"), ["n", "z"]);
        f.overlay.mkdir("/dir/d", 0o700).unwrap();
        assert_eq!(f.overlay.stat("/dir/d", true).unwrap().mode, 0o700);
        // Names that exist (in any layer) or cannot be made.
        assert_eq!(f.overlay.mkdir("/a", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(f.overlay.mkdir("/dir", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(f.overlay.mkdir("/b", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(f.overlay.open("/a", RW | OpenFlags::CREATE | OpenFlags::EXCL, 0o644).err(), Some(Errno::EEXIST));
        assert_eq!(f.overlay.mkdir("/x/y", 0o755).err(), Some(Errno::ENOENT));
        let root = f.overlay.lookup("/").unwrap();
        assert_eq!(root.create(OPAQUE_NAME, FileKind::Regular, 0).err(), Some(Errno::EINVAL));
        assert_eq!(root.create(".ovl-tmp-0", FileKind::Regular, 0).err(), Some(Errno::EINVAL));
        assert_eq!(root.create("a/b", FileKind::Regular, 0).err(), Some(Errno::EINVAL));
        // Open an existing lower file for create without EXCL: no copy-up.
        f.overlay.open("/b", OpenFlags::CREATE, 0o644).unwrap();
        assert_eq!(f.upper.lookup("/b").err(), Some(Errno::ENOENT));
        // Devices keep their kind.
        let dev = root.create("tty", FileKind::CharDevice, 0o600).unwrap();
        assert_eq!(dev.stat().kind, FileKind::CharDevice);
    }

    #[test]
    fn removing_a_lower_name_leaves_a_whiteout() {
        let f = fixture();
        f.overlay.unlink("/dir/x").unwrap();
        assert_eq!(f.overlay.lookup("/dir/x").err(), Some(Errno::ENOENT));
        assert_eq!(names(&f.overlay, "/dir"), ["sub", "w", "y"]);
        assert!(is_whiteout(&f.upper, "/dir/x"));
        assert_eq!(read(&f.lower, "/dir/x"), b"x");
        // A name only the lowest layer has, too.
        f.overlay.unlink("/b").unwrap();
        assert!(is_whiteout(&f.upper, "/b"));
        assert_eq!(f.overlay.unlink("/b").err(), Some(Errno::ENOENT));
        assert_eq!(f.overlay.rmdir("/a").err(), Some(Errno::ENOTDIR));
        assert_eq!(f.overlay.unlink("/dir").err(), Some(Errno::EISDIR));
        // Removing a name that is only in the upper layer leaves nothing behind.
        put(&f.overlay, "/tmp", b"t");
        f.overlay.unlink("/tmp").unwrap();
        assert_eq!(f.upper.lookup("/tmp").err(), Some(Errno::ENOENT));
        // Removing a copied-up name: the copy goes and the whiteout comes.
        f.overlay.lookup("/dir/y").unwrap().write(0, b"Y").unwrap();
        f.overlay.unlink("/dir/y").unwrap();
        assert!(is_whiteout(&f.upper, "/dir/y"));
        assert_eq!(f.overlay.lookup("/dir/y").err(), Some(Errno::ENOENT));
    }

    #[test]
    fn a_name_in_two_layers_stays_hidden_after_removal() {
        let f = fixture();
        // /a is in both lowers; one whiteout hides both.
        f.overlay.unlink("/a").unwrap();
        assert_eq!(f.overlay.lookup("/a").err(), Some(Errno::ENOENT));
        assert!(!names(&f.overlay, "/").contains(&"a".to_string()));
        // Making it again does not bring back either.
        put(&f.overlay, "/a", b"fresh");
        assert_eq!(read(&f.overlay, "/a"), b"fresh");
        assert_eq!(read(&f.upper, "/a"), b"fresh");
        assert_eq!(names(&f.overlay, "/").iter().filter(|n| *n == "a").count(), 1);
    }

    #[test]
    fn a_directory_made_over_a_removed_one_is_opaque() {
        let f = fixture();
        f.overlay.unlink("/dir/sub/z").unwrap();
        f.overlay.rmdir("/dir/sub").unwrap();
        assert_eq!(f.overlay.lookup("/dir/sub").err(), Some(Errno::ENOENT));
        f.overlay.mkdir("/dir/sub", 0o700).unwrap();
        assert_eq!(names(&f.overlay, "/dir/sub"), Vec::<String>::new());
        put(&f.overlay, "/dir/sub/new", b"n");
        assert_eq!(names(&f.overlay, "/dir/sub"), ["new"]);
        assert_eq!(f.overlay.stat("/dir/sub", true).unwrap().mode, 0o700);
        // Nothing of the lower directory shows through, not even what was
        // not removed first.
        f.lower.lookup("/dir/sub").unwrap().create("late", FileKind::Regular, 0o644).unwrap();
        assert_eq!(f.overlay.lookup("/dir/sub/late").err(), Some(Errno::ENOENT));
        // The marker itself is not listed, and it ends with the directory.
        assert!(names(&f.upper, "/dir/sub").contains(&OPAQUE_NAME.to_string()));
        assert!(!names(&f.overlay, "/dir/sub").contains(&OPAQUE_NAME.to_string()));
    }

    #[test]
    fn rmdir_needs_an_empty_merged_directory() {
        let f = fixture();
        assert_eq!(f.overlay.rmdir("/dir").err(), Some(Errno::ENOTEMPTY));
        assert_eq!(f.overlay.rmdir("/dir/sub").err(), Some(Errno::ENOTEMPTY));
        f.overlay.unlink("/dir/sub/z").unwrap();
        // The upper directory holds a whiteout; the merged one is empty.
        f.overlay.rmdir("/dir/sub").unwrap();
        assert!(is_whiteout(&f.upper, "/dir/sub"));
        for name in ["x", "y", "w"] {
            f.overlay.unlink(&format!("/dir/{name}")).unwrap();
        }
        f.overlay.rmdir("/dir").unwrap();
        assert_eq!(f.overlay.lookup("/dir").err(), Some(Errno::ENOENT));
        assert!(is_whiteout(&f.upper, "/dir"));
        // A directory only in the upper layer goes without a trace.
        f.overlay.mkdir("/up", 0o755).unwrap();
        put(&f.overlay, "/up/f", b"f");
        assert_eq!(f.overlay.rmdir("/up").err(), Some(Errno::ENOTEMPTY));
        f.overlay.unlink("/up/f").unwrap();
        f.overlay.rmdir("/up").unwrap();
        assert_eq!(f.upper.lookup("/up").err(), Some(Errno::ENOENT));
    }

    #[test]
    fn renaming_files() {
        let f = fixture();
        f.overlay.rename("/dir/x", "/moved").unwrap();
        assert_eq!(read(&f.overlay, "/moved"), b"x");
        assert_eq!(f.overlay.lookup("/dir/x").err(), Some(Errno::ENOENT));
        assert!(is_whiteout(&f.upper, "/dir/x"));
        assert_eq!(read(&f.lower, "/dir/x"), b"x");
        // Over a file that only a lower layer has.
        f.overlay.rename("/moved", "/b").unwrap();
        assert_eq!(read(&f.overlay, "/b"), b"x");
        assert_eq!(f.overlay.lookup("/moved").err(), Some(Errno::ENOENT));
        // Within the upper layer: no whiteout for a name it alone has.
        put(&f.overlay, "/u1", b"1");
        f.overlay.rename("/u1", "/u2").unwrap();
        assert_eq!(f.upper.lookup("/u1").err(), Some(Errno::ENOENT));
        assert_eq!(read(&f.overlay, "/u2"), b"1");
        // Back onto a whited-out name.
        f.overlay.rename("/u2", "/dir/x").unwrap();
        assert_eq!(read(&f.overlay, "/dir/x"), b"1");
        assert_eq!(names(&f.overlay, "/dir"), ["sub", "w", "x", "y"]);
        // A name onto itself, and the usual errors.
        f.overlay.rename("/a", "/a").unwrap();
        assert_eq!(f.overlay.rename("/nothing", "/z").err(), Some(Errno::ENOENT));
        assert_eq!(f.overlay.rename("/a", "/dir").err(), Some(Errno::EISDIR));
        assert_eq!(f.overlay.rename("/only2", "/a").err(), Some(Errno::ENOTDIR));
        assert_eq!(f.overlay.rename("/a", "/missing/x").err(), Some(Errno::ENOENT));
        assert_eq!(read(&f.overlay, "/a"), b"lower a");
    }

    #[test]
    fn renaming_directories() {
        let f = fixture();
        // One with lower contents cannot move.
        assert_eq!(f.overlay.rename("/dir", "/elsewhere").err(), Some(Errno::EXDEV));
        assert_eq!(f.overlay.rename("/only2", "/elsewhere").err(), Some(Errno::EXDEV));
        // One that is only in the upper layer can.
        f.overlay.mkdir("/up", 0o755).unwrap();
        put(&f.overlay, "/up/f", b"f");
        f.overlay.rename("/up", "/up2").unwrap();
        assert_eq!(read(&f.overlay, "/up2/f"), b"f");
        assert_eq!(f.overlay.lookup("/up").err(), Some(Errno::ENOENT));
        // Into itself.
        f.overlay.mkdir("/up2/in", 0o755).unwrap();
        assert_eq!(f.overlay.rename("/up2", "/up2/in/x").err(), Some(Errno::EINVAL));
        // Over a lower directory: it replaces it, nothing shows through.
        f.overlay.unlink("/dir/sub/z").unwrap();
        f.overlay.rmdir("/dir/sub").unwrap();
        f.overlay.unlink("/only2/f").unwrap();
        f.overlay.mkdir("/fresh", 0o755).unwrap();
        put(&f.overlay, "/fresh/q", b"q");
        f.overlay.rename("/fresh", "/only2").unwrap();
        assert_eq!(names(&f.overlay, "/only2"), ["q"]);
        assert!(!names(&f.overlay, "/").contains(&"fresh".to_string()));
        // A non-empty target stays.
        f.overlay.mkdir("/other", 0o755).unwrap();
        assert_eq!(f.overlay.rename("/other", "/up2").err(), Some(Errno::ENOTEMPTY));
    }

    #[test]
    fn hard_links() {
        let f = fixture();
        f.overlay.link("/dir/x", "/dir/x2").unwrap();
        assert_eq!(read(&f.overlay, "/dir/x2"), b"x");
        // The target was copied up and the two names are one file.
        f.overlay.lookup("/dir/x2").unwrap().write(0, b"Q").unwrap();
        assert_eq!(read(&f.overlay, "/dir/x"), b"Q");
        assert_eq!(f.overlay.stat("/dir/x", true).unwrap().nlink, 2);
        assert_eq!(read(&f.lower, "/dir/x"), b"x");
        assert_eq!(f.overlay.link("/dir/x", "/dir/y").err(), Some(Errno::EEXIST));
        assert_eq!(f.overlay.link("/dir", "/dir2").err(), Some(Errno::EPERM));
        assert_eq!(f.overlay.link("/nothing", "/z").err(), Some(Errno::ENOENT));
        // Onto a removed name.
        f.overlay.unlink("/a").unwrap();
        f.overlay.link("/b", "/a").unwrap();
        assert_eq!(read(&f.overlay, "/a"), b"lower2 b");
        // Across file systems.
        let other = Vfs::new(RamFs::new(9).root());
        put(&other, "/f", b"");
        let root = f.overlay.lookup("/").unwrap();
        assert_eq!(root.link("f", &*other.lookup("/f").unwrap()).err(), Some(Errno::EXDEV));
    }

    #[test]
    fn handles_that_race_a_copy_up_agree() {
        let f = fixture();
        let one = f.overlay.lookup("/dir/y").unwrap();
        let two = f.overlay.lookup("/dir/y").unwrap();
        one.write(0, b"1").unwrap();
        // The second node still reads below, but its write finds the copy.
        assert_eq!(read(&f.overlay, "/dir/y"), b"1");
        two.write(0, b"2").unwrap();
        assert_eq!(read(&f.overlay, "/dir/y"), b"2");
        assert_eq!(names(&f.upper, "/dir"), ["y"]);
    }

    #[test]
    fn inode_numbers_name_the_layer() {
        let f = fixture();
        let lower = f.overlay.stat("/b", true).unwrap();
        let root = f.overlay.lookup("/").unwrap();
        let listed = (0..).map_while(|i| root.readdir(i).unwrap()).find(|e| e.name == "b").unwrap();
        assert_eq!(lower.ino, listed.ino);
        assert_eq!(lower.ino >> LAYER_SHIFT, 2);
        assert_eq!(f.overlay.stat("/a", true).unwrap().ino >> LAYER_SHIFT, 1);
        put(&f.overlay, "/up", b"");
        assert_eq!(f.overlay.stat("/up", true).unwrap().ino >> LAYER_SHIFT, 0);
        // Distinct files have distinct numbers even if their layers number them alike.
        let all: Vec<u64> = ["/a", "/b", "/up", "/dir"].iter().map(|p| f.overlay.stat(p, true).unwrap().ino).collect();
        let distinct: BTreeSet<u64> = all.iter().copied().collect();
        assert_eq!(distinct.len(), all.len());
    }

    #[test]
    fn mounts_and_stacks() {
        let f = fixture();
        let top = Vfs::new(RamFs::new(7).root());
        top.mkdir("/mnt", 0o755).unwrap();
        let fs = OverlayFs::new(8, None, vec![f.overlay.lookup("/").unwrap()]).unwrap();
        top.mount("/mnt", fs.root()).unwrap();
        assert_eq!(read(&top, "/mnt/dir/w"), b"w");
        assert_eq!(top.stat("/mnt/a", true).unwrap().dev, 8);
        // An overlay as a lower layer shows its merged view, whiteouts applied.
        f.overlay.unlink("/dir/x").unwrap();
        assert_eq!(names(&top, "/mnt/dir"), ["sub", "w", "y"]);
        assert_eq!(top.lookup("/mnt/dir/x").err(), Some(Errno::ENOENT));
    }

    /// A strategy that wraps another and counts what it is asked to make.
    struct Counting {
        inner: DeviceMarkers,
        whiteouts: AtomicUsize,
        opaques: AtomicUsize,
    }

    impl Markers for Counting {
        fn is_whiteout(&self, entry: &dyn File) -> bool {
            self.inner.is_whiteout(entry)
        }
        fn make_whiteout(&self, dir: &dyn File, name: &str) -> Result<(), Errno> {
            self.whiteouts.fetch_add(1, Ordering::SeqCst);
            self.inner.make_whiteout(dir, name)
        }
        fn is_opaque(&self, dir: &dyn File) -> Result<bool, Errno> {
            self.inner.is_opaque(dir)
        }
        fn set_opaque(&self, dir: &dyn File) -> Result<(), Errno> {
            self.opaques.fetch_add(1, Ordering::SeqCst);
            self.inner.set_opaque(dir)
        }
        fn is_hidden(&self, name: &str) -> bool {
            self.inner.is_hidden(name)
        }
    }

    #[test]
    fn markers_are_pluggable() {
        let f = fixture();
        let markers =
            Arc::new(Counting { inner: DeviceMarkers, whiteouts: AtomicUsize::new(0), opaques: AtomicUsize::new(0) });
        let upper = Vfs::new(RamFs::new(3).root());
        let fs = OverlayFs::with_markers(
            4,
            Some(upper.lookup("/").unwrap()),
            vec![f.lower.lookup("/").unwrap()],
            markers.clone(),
        )
        .unwrap();
        let vfs = Vfs::new(fs.root());
        vfs.unlink("/a").unwrap();
        assert_eq!(markers.whiteouts.load(Ordering::SeqCst), 1);
        // Only a removal that a lower layer shows needs one.
        put(&vfs, "/tmp", b"");
        vfs.unlink("/tmp").unwrap();
        assert_eq!(markers.whiteouts.load(Ordering::SeqCst), 1);
        vfs.unlink("/dir/sub/z").unwrap();
        vfs.rmdir("/dir/sub").unwrap();
        vfs.mkdir("/dir/sub", 0o755).unwrap();
        assert_eq!(markers.opaques.load(Ordering::SeqCst), 1);
        vfs.mkdir("/plain", 0o755).unwrap();
        assert_eq!(markers.opaques.load(Ordering::SeqCst), 1);
    }
}
