//! eapp entry should be marked as #\[link_section = ".text._start"\]

extern "C" {
    pub fn EAPP_RETURN(rval: usize);
}
