pub const _IOC_NRBITS: usize = 8;
pub const _IOC_TYPEBITS: usize = 8;
pub const _IOC_SIZEBITS: usize = 14;
pub const _IOC_DIRBITS: usize = 2;

pub const _IOC_NRMASK: usize = (1 << _IOC_NRBITS) - 1;
pub const _IOC_TYPEMASK: usize = (1 << _IOC_TYPEBITS) - 1;
pub const _IOC_SIZEMASK: usize = (1 << _IOC_SIZEBITS) - 1;
pub const _IOC_DIRMASK: usize = (1 << _IOC_DIRBITS) - 1;

pub const _IOC_NRSHIFT: usize = 0;
pub const _IOC_TYPESHIFT: usize = _IOC_NRSHIFT + _IOC_NRBITS;
pub const _IOC_SIZESHIFT: usize = _IOC_TYPESHIFT + _IOC_TYPEBITS;
pub const _IOC_DIRSHIFT: usize = 0;

pub const _IOC_NONE: usize = 0;
pub const _IOC_WRITE: usize = 1;
pub const _IOC_READ: usize = 2;

#[inline]
pub const fn _IOC(dir: usize, _type: usize, nr: usize, size: usize) -> usize {
    (dir << _IOC_DIRSHIFT) | (_type << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)
}

#[inline]
pub const fn _IO(_type: usize, nr: usize) -> usize {
    _IOC(_IOC_NONE, _type, nr, 0)
}

#[inline]
pub const fn _IOR(_type: usize, nr: usize, size: usize) -> usize {
    _IOC(_IOC_READ, _type, nr, size)
}

#[inline]
pub const fn _IOW(_type: usize, nr: usize, size: usize) -> usize {
    _IOC(_IOC_WRITE, _type, nr, size)
}

#[inline]
pub const fn _IOWR(_type: usize, nr: usize, size: usize) -> usize {
    _IOC(_IOC_READ | _IOC_WRITE, _type, nr, size)
}

#[inline]
pub const fn _IOC_DIR(nr: usize) -> usize {
    (nr >> _IOC_DIRSHIFT) & _IOC_DIRMASK
}

#[inline]
pub const fn _IOC_TYPE(nr: usize) -> usize {
    (nr >> _IOC_TYPESHIFT) & _IOC_TYPEMASK
}

#[inline]
pub const fn _IOC_NR(nr: usize) -> usize {
    (nr >> _IOC_NRSHIFT) & _IOC_NRMASK
}

#[inline]
pub const fn _IOC_SIZE(nr: usize) -> usize {
    (nr >> _IOC_SIZESHIFT) & _IOC_SIZEMASK
}

pub const IOC_IN: usize = _IOC_WRITE << _IOC_DIRSHIFT;
pub const IOC_OUT: usize = _IOC_READ << _IOC_DIRSHIFT;
pub const IOC_INOUT: usize = (_IOC_WRITE | _IOC_READ) << _IOC_DIRSHIFT;
pub const IOCSIZE_MASK: usize = _IOC_SIZEMASK << _IOC_SIZESHIFT;
pub const IOCSIZE_SHIFT: usize = _IOC_SIZESHIFT;
