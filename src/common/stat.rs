use bitflags::bitflags;

#[repr(C)]
#[derive(Debug)]
pub struct Stat {
    /// ID of device containing file
    pub dev: u64,
    /// inode number
    pub ino: u64,
    /// file type and mode
    pub mode: StatMode,
    /// number of hard links
    pub nlink: u32,

    /// user ID of owner
    pub uid: u32,
    /// group ID of owner
    pub gid: u32,
    /// device ID (if special file)
    pub rdev: u64,
    /// padding
    pub _pad0: u64,
    /// total size, in bytes
    pub size: u64,
    /// blocksize for filesystem I/O
    pub blksize: u32,
    /// padding
    pub _pad1: u32,
    /// number of 512B blocks allocated
    pub blocks: u64,

    /// last access time
    pub atime: TimeSpec,
    /// last modification time
    pub mtime: TimeSpec,
    /// last status change time
    pub ctime: TimeSpec,
}

bitflags! {
    pub struct StatMode: u32 {
        /// Type
        const TYPE_MASK = 0o170_000;
        /// FIFO
        const FIFO  = 0o010_000;
        /// character device
        const CHAR  = 0o020_000;
        /// directory
        const DIR   = 0o040_000;
        /// block device
        const BLOCK = 0o060_000;
        /// ordinary regular file
        const FILE  = 0o100_000;
        /// symbolic link
        const LINK  = 0o120_000;
        /// socket
        const SOCKET = 0o140_000;

        /// Set-user-ID on execution.
        const SET_UID = 0o4_000;
        /// Set-group-ID on execution.
        const SET_GID = 0o2_000;

        /// Read, write, execute/search by owner.
        const OWNER_MASK = 0o700;
        /// Read permission, owner.
        const OWNER_READ = 0o400;
        /// Write permission, owner.
        const OWNER_WRITE = 0o200;
        /// Execute/search permission, owner.
        const OWNER_EXEC = 0o100;

        /// Read, write, execute/search by group.
        const GROUP_MASK = 0o70;
        /// Read permission, group.
        const GROUP_READ = 0o40;
        /// Write permission, group.
        const GROUP_WRITE = 0o20;
        /// Execute/search permission, group.
        const GROUP_EXEC = 0o10;

        /// Read, write, execute/search by others.
        const OTHER_MASK = 0o7;
        /// Read permission, others.
        const OTHER_READ = 0o4;
        /// Write permission, others.
        const OTHER_WRITE = 0o2;
        /// Execute/search permission, others.
        const OTHER_EXEC = 0o1;
    }
}

// impl StatMode {
//     fn from_type_mode(type_: FileType, mode: u16) -> Self {
//         let type_ = match type_ {
//             FileType::File => StatMode::FILE,
//             FileType::Dir => StatMode::DIR,
//             FileType::SymLink => StatMode::LINK,
//             FileType::CharDevice => StatMode::CHAR,
//             FileType::BlockDevice => StatMode::BLOCK,
//             FileType::Socket => StatMode::SOCKET,
//             FileType::NamedPipe => StatMode::FIFO,
//         };
//         let mode = StatMode::from_bits_truncate(mode as u32);
//         type_ | mode
//     }
// }

#[derive(Debug)]
pub struct TimeSpec {
    pub sec: i32,
    pub nsec: i32,
}
