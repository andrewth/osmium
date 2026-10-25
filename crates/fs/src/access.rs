//! Permission checks on plain types.
//!
//! The VFS does no permission checks and [`Stat`](crate::Stat) carries no
//! owner, because Osmium has no users of its own. A kernel that does have
//! them keeps owners wherever it likes and asks these functions the
//! questions that follow the classic owner/group/other rules, with a
//! privileged override standing in for a superuser or a capability.

use core::ops::BitOr;

/// The set-group-ID and sticky mode bits, and the three execute bits.
const S_ISGID: u32 = 0o2000;
const S_ISVTX: u32 = 0o1000;
const EXEC_BITS: u32 = 0o111;

/// A set of requested accesses: any of read, write and execute (search, for
/// a directory).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Access(u8);

impl Access {
    /// No access.
    pub const NONE: Access = Access(0);
    /// Read the file or list the directory.
    pub const READ: Access = Access(4);
    /// Write the file or change the directory.
    pub const WRITE: Access = Access(2);
    /// Execute the file or search the directory.
    pub const EXEC: Access = Access(1);

    /// Whether every access in `other` is in `self`.
    pub const fn contains(self, other: Access) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for Access {
    type Output = Access;

    fn bitor(self, rhs: Access) -> Access {
        Access(self.0 | rhs.0)
    }
}

/// Who is asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity<'groups> {
    /// The user the access is made as.
    pub uid: u32,
    /// The primary group.
    pub gid: u32,
    /// Supplementary groups.
    pub groups: &'groups [u32],
    /// Whether the caller may override the permission bits (a superuser, or
    /// whatever the embedder maps to one). Executing a plain file still
    /// needs some execute bit.
    pub privileged: bool,
}

impl Identity<'_> {
    /// Whether the caller is in group `gid`, as primary or supplementary.
    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// Whether `id` may make the accesses `want` to a node owned by `owner` and
/// `group` with permission bits `mode` (only the low nine are read).
///
/// The owner is judged by the owner bits alone, even where the group or
/// other bits would be more generous; a group member by the group bits;
/// anyone else by the other bits. A privileged caller may read and write
/// anything and search any directory, but executes a non-directory only if
/// some execute bit is set.
pub fn permits(id: &Identity<'_>, owner: u32, group: u32, mode: u32, is_dir: bool, want: Access) -> bool {
    if id.privileged {
        return !want.contains(Access::EXEC) || is_dir || mode & EXEC_BITS != 0;
    }
    let class = if id.uid == owner {
        mode >> 6
    } else if id.in_group(group) {
        mode >> 3
    } else {
        mode
    };
    class & 7 & u32::from(want.0) == u32::from(want.0)
}

/// Whether `id` may remove or rename the entry whose inode is owned by
/// `file_owner` from a directory owned by `dir_owner` with mode `dir_mode`.
/// Only a sticky directory restricts this, to the file's owner, the
/// directory's owner and the privileged. The caller still checks write and
/// search access to the directory itself.
pub fn sticky_allows(id: &Identity<'_>, dir_mode: u32, dir_owner: u32, file_owner: u32) -> bool {
    dir_mode & S_ISVTX == 0 || id.privileged || id.uid == file_owner || id.uid == dir_owner
}

/// The group a node created by `id` in a directory with mode `dir_mode` and
/// group `dir_group` belongs to: the directory's if it has the set-group-ID
/// bit, else the creator's primary group.
pub fn new_group(id: &Identity<'_>, dir_mode: u32, dir_group: u32) -> u32 {
    if dir_mode & S_ISGID != 0 { dir_group } else { id.gid }
}

/// The mode bits a new subdirectory takes from its parent: the set-group-ID
/// bit is inherited, so the rule carries down the tree.
pub fn inherited_mode(parent_mode: u32, new_is_dir: bool) -> u32 {
    if new_is_dir { parent_mode & S_ISGID } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUPS: &[u32] = &[30, 31];

    fn user(uid: u32, gid: u32) -> Identity<'static> {
        Identity { uid, gid, groups: GROUPS, privileged: false }
    }

    const ROOT: Identity<'static> = Identity { uid: 0, gid: 0, groups: &[], privileged: true };

    #[test]
    fn classes() {
        let rw = Access::READ | Access::WRITE;
        // rw-r----- owned by 10:20.
        let check = |id: &Identity<'_>, want| permits(id, 10, 20, 0o640, false, want);
        assert!(check(&user(10, 99), rw));
        assert!(check(&user(11, 20), Access::READ));
        assert!(!check(&user(11, 20), Access::WRITE));
        assert!(check(&Identity { uid: 11, gid: 99, groups: &[5, 20], privileged: false }, Access::READ));
        assert!(!check(&user(11, 99), Access::READ));
        assert!(check(&user(11, 99), Access::NONE));
    }

    #[test]
    fn owner_bits_win_over_wider_classes() {
        // ---rwxrwx: the owner is locked out although group and other are not.
        assert!(!permits(&user(10, 20), 10, 20, 0o077, false, Access::READ));
        assert!(permits(&user(11, 20), 10, 20, 0o077, false, Access::READ));
        // The group class beats the other class too.
        assert!(!permits(&user(11, 20), 10, 20, 0o407, false, Access::READ));
    }

    #[test]
    fn privileged_override() {
        assert!(permits(&ROOT, 10, 20, 0o000, false, Access::READ | Access::WRITE));
        assert!(permits(&ROOT, 10, 20, 0o000, true, Access::EXEC));
        assert!(!permits(&ROOT, 10, 20, 0o666, false, Access::EXEC));
        assert!(permits(&ROOT, 10, 20, 0o010, false, Access::EXEC));
    }

    #[test]
    fn sticky_directories() {
        let sticky = 0o1777;
        assert!(sticky_allows(&user(10, 1), sticky, 0, 10));
        assert!(!sticky_allows(&user(11, 1), sticky, 0, 10));
        assert!(sticky_allows(&user(0, 1), sticky, 0, 10));
        assert!(sticky_allows(&ROOT, sticky, 5, 10));
        assert!(sticky_allows(&user(11, 1), 0o777, 0, 10));
    }

    #[test]
    fn setgid_directories() {
        let id = user(10, 20);
        assert_eq!(new_group(&id, 0o2775, 77), 77);
        assert_eq!(new_group(&id, 0o0775, 77), 20);
        assert_eq!(inherited_mode(0o2775, true), 0o2000);
        assert_eq!(inherited_mode(0o2775, false), 0);
        assert_eq!(inherited_mode(0o0775, true), 0);
    }
}
