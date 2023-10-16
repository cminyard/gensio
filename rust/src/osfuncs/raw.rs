use std::ffi;

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

#[repr(C)]
pub struct gensio_os_proc_data;

#[link(name = "gensioosh")]
extern "C" {
    #[allow(improper_ctypes)]
    pub fn gensio_default_os_hnd(wake_sig: ffi::c_int,
				 o: *const *const gensio_os_funcs)
				 -> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_os_proc_setup(o: *const gensio_os_funcs,
				data: *const *const gensio_os_proc_data)
				-> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_os_proc_cleanup(data: *const gensio_os_proc_data);

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
