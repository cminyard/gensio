use std::ffi;

pub const GE_NOERR:			ffi::c_int = 0;
pub const GE_NOMEM:			ffi::c_int = 1;
pub const GE_NOTSUP:			ffi::c_int = 2;
pub const GE_INVAL:			ffi::c_int = 3;
pub const GE_NOTFOUND:			ffi::c_int = 4;
pub const GE_EXISTS:			ffi::c_int = 5;
pub const GE_OUTOFRANGE:		ffi::c_int = 6;
pub const GE_INCONSISTENT:		ffi::c_int = 7;
pub const GE_NODATA:			ffi::c_int = 8;
pub const GE_OSERR:			ffi::c_int = 9;
pub const GE_INUSE:			ffi::c_int = 10;
pub const GE_INPROGRESS:		ffi::c_int = 11;
pub const GE_NOTREADY:			ffi::c_int = 12;
pub const GE_TOOBIG:			ffi::c_int = 13;
pub const GE_TIMEDOUT:			ffi::c_int = 14;
pub const GE_RETRY:			ffi::c_int = 15;
pub const GE_KEYNOTFOUND:		ffi::c_int = 17;
pub const GE_CERTREVOKED:		ffi::c_int = 18;
pub const GE_CERTEXPIRED:		ffi::c_int = 19;
pub const GE_KEYINVALID:		ffi::c_int = 20;
pub const GE_NOCERT:			ffi::c_int = 21;
pub const GE_CERTINVALID:		ffi::c_int = 22;
pub const GE_PROTOERR:			ffi::c_int = 23;
pub const GE_COMMERR:			ffi::c_int = 24;
pub const GE_IOERR:			ffi::c_int = 25;
pub const GE_REMCLOSE:			ffi::c_int = 26;
pub const GE_HOSTDOWN:			ffi::c_int = 27;
pub const GE_CONNREFUSE:		ffi::c_int = 28;
pub const GE_DATAMISSING:		ffi::c_int = 29;
pub const GE_CERTNOTFOUND:		ffi::c_int = 30;
pub const GE_AUTHREJECT:		ffi::c_int = 31;
pub const GE_ADDRINUSE:			ffi::c_int = 32;
pub const GE_INTERRUPTED:		ffi::c_int = 33;
pub const GE_SHUTDOWN:			ffi::c_int = 34;
pub const GE_LOCALCLOSED:		ffi::c_int = 35;
pub const GE_PERM:			ffi::c_int = 36;
pub const GE_APPERR:			ffi::c_int = 37;
pub const GE_UNKNOWN_NAME_ERROR:	ffi::c_int = 38;
pub const GE_NAME_ERROR:		ffi::c_int = 39;
pub const GE_NAME_SERVER_FAILURE:	ffi::c_int = 40;
pub const GE_NAME_INVALID:		ffi::c_int = 41;
pub const GE_NAME_NET_NOT_UP:		ffi::c_int = 42;

#[repr(C)]
pub struct gensio_time {
    pub secs: i64,
    pub nsecs: i32
}

#[allow(non_camel_case_types)]
pub type gensiods = ffi::c_ulong;

#[repr(C)]
pub struct gensio_waiter;

#[repr(C)]
pub struct gensio_os_funcs;

#[link(name = "gensioosh")]
extern "C" {
    #[allow(improper_ctypes)]
    pub fn gensio_default_os_hnd(wake_sig: ffi::c_int,
				 o: *const *const gensio_os_funcs)
				 -> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_os_funcs_alloc_waiter(o: *const gensio_os_funcs)
					-> *const gensio_waiter;

    #[allow(improper_ctypes)]
    pub fn gensio_os_funcs_wait(o: *const gensio_os_funcs,
				w: *const gensio_waiter, count: ffi::c_uint,
				timeout: &gensio_time) -> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_os_funcs_wake(o: *const gensio_os_funcs,
				w: *const gensio_waiter) -> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_os_funcs_free_waiter(o: *const gensio_os_funcs,
				       w: *const gensio_waiter);

    #[allow(improper_ctypes)]
    pub fn gensio_os_funcs_free(o: *const gensio_os_funcs);
}
