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
pub struct gensio;

#[allow(non_camel_case_types)]
pub type gensio_event = extern "C" fn (io: *const gensio,
				       user_data: *const ffi::c_void,
				       event: ffi::c_int, err: ffi::c_int,
				       buf: *const ffi::c_void,
				       buflen: *mut gensiods,
				       auxdata: *const *const ffi::c_char)
				       -> ffi::c_int;

#[allow(non_camel_case_types)]
pub type gensio_done_err = extern "C" fn (io: *const gensio,
					  err: ffi::c_int,
					  user_data: *mut ffi::c_void);

#[repr(C)]
pub struct gensio_os_funcs;

#[link(name = "gensio")]
#[link(name = "gensioosh")]
extern "C" {

    fn printf(s: *const ffi::c_char);

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
    pub fn str_to_gensio(s: *const ffi::c_char,
			 o: *const gensio_os_funcs,
			 cb: gensio_event,
			 user_data: *const ffi::c_void,
			 rgensio: *const *const gensio
    ) -> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_set_user_data(g: *const gensio, data: *const ffi::c_void);

    #[allow(improper_ctypes)]
    pub fn gensio_open(io: *const gensio, open_done: gensio_done_err,
		       open_data: *mut ffi::c_void) -> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_write(io: *const gensio, count: &mut gensiods,
			buf: *const ffi::c_void, buflen: gensiods,
			auxdata: *const *const ffi::c_char) -> ffi::c_int;

    #[allow(improper_ctypes)]
    pub fn gensio_set_read_callback_enable(g: *const gensio,
					   enabled: ffi::c_int);
}

pub fn printfit(s: &str) {
    let s1 = ffi::CString::new(s).expect("CString::new failed");
    unsafe {
	printf(s1.as_ptr());
    }
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn printf_test() {
	printfit("Hello There\n");
    }

    struct GData {
	o: *const gensio_os_funcs,
 	w: *const gensio_waiter,
	g: *const gensio
    }

    extern "C" fn evhndl(_io: *const gensio, user_data: *const ffi::c_void,
			 _event: ffi::c_int, _err: ffi::c_int,
			 buf: *const ffi::c_void, buflen: *mut gensiods,
			 _auxdata: *const *const ffi::c_char) -> ffi::c_int
    {
	let b = buf as *mut i8;

	let s;
	unsafe {
	    assert_eq!(*buflen, 8);
	    s = ffi::CString::from_raw(b);
	}
	assert_eq!(s.into_string().expect("into_string() call failed"),
		   "teststr");
	unsafe {
	    let d = user_data as *const GData;

	    let err = gensio_os_funcs_wake((*d).o, (*d).w);
	    assert_eq!(err, 0);
	}
	0
    }

    extern "C" fn opened(_io: *const gensio, _err: ffi::c_int,
			 open_data: *mut ffi::c_void)
    {
	unsafe {
	    //let d = unsafe { Box::<GData>::from_raw(open_data as *mut GData); };
	    let d = open_data as *const GData;

	    let err = gensio_os_funcs_wake((*d).o, (*d).w);
	    assert_eq!(err, 0);
	}
    }

    #[test]
    fn basic_gensio() {
	let mut err: ffi::c_int;

	let o: *const gensio_os_funcs = std::ptr::null();
	unsafe {
	    err = gensio_default_os_hnd(0, &o);
	}
	assert_eq!(err, 0);
	let w;
	unsafe {
	    w = gensio_os_funcs_alloc_waiter(o);
	}
	assert_eq!(err, 0);
	let g: *const gensio = std::ptr::null();
	unsafe {
	    let s = ffi::CString::new("echo").expect("CString::new failed");
	    err = str_to_gensio(s.as_ptr(), o, evhndl,
				std::ptr::null(), &g);
	}
	assert_eq!(err, 0);
	let d = Rc::new(GData { o: o, w: w, g: g });
	unsafe {
	    gensio_set_user_data(g, Rc::as_ptr(&d) as *mut ffi::c_void);
	}

	unsafe {
	    err = gensio_open(d.g, opened, Rc::as_ptr(&d) as *mut ffi::c_void);
	}
	assert_eq!(err, 0);
	unsafe {
	    err = gensio_os_funcs_wait(d.o, d.w, 1,
				       &mut gensio_time{secs: 1, nsecs: 0});
	}
	assert_eq!(err, 0);
	unsafe {
	    let s = ffi::CString::new("teststr").expect("CString::new failed");
	    let mut count = 0;
	    err = gensio_write(d.g, &mut count,
			       s.as_ptr() as *const ffi::c_void, 8,
			       std::ptr::null());
	    assert_eq!(err, 0);
	    assert_eq!(count, 8);
	}
	unsafe {
	    gensio_set_read_callback_enable(d.g, 1);
	    err = gensio_os_funcs_wait(d.o, d.w, 1,
				       &mut gensio_time{secs: 1, nsecs: 0});
	}
	assert_eq!(err, 0);
    }
}
