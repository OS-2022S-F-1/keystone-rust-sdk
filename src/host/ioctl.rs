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
pub const _IOC_DIRSHIFT: usize = _IOC_SIZESHIFT + _IOC_SIZEBITS;

pub const _IOC_NONE: usize = 0;
pub const _IOC_WRITE: usize = 1;
pub const _IOC_READ: usize = 2;

#[inline]
pub const fn _ioc(dir: usize, _type: usize, nr: usize, size: usize) -> usize {
    (dir << _IOC_DIRSHIFT) | (_type << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)
}

#[inline]
pub const fn _ior(_type: usize, nr: usize, size: usize) -> usize {
    _ioc(_IOC_READ, _type, nr, size)
}

#[inline]
pub const fn _iow(_type: usize, nr: usize, size: usize) -> usize {
    _ioc(_IOC_WRITE, _type, nr, size)
}
