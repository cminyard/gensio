use std::sync::Arc;
use std::time::Duration;
use std::ffi;
pub mod raw;

/// Used to refcount gensio_os_funcs.
pub struct IOsFuncs {
    log_data: *mut GensioLogHandlerData,
    pub o: *const raw::gensio_os_funcs
}

impl Drop for IOsFuncs {
    fn drop(&mut self) {
	unsafe {
	    if self.log_data != std::ptr::null_mut() {
		drop(Box::from_raw(self.log_data));
	    }
	    raw::gensio_rust_cleanup(self.o);
	    raw::gensio_os_funcs_free(self.o);
	}
    }
}

/// Os Handling functions for gensio You need one of these to do
/// pretty much anything with gensio.
pub struct OsFuncs {
    o: Arc<IOsFuncs>,
    proc_data: *const raw::gensio_os_proc_data,
}

/// Allocate an OsFuncs structure.  This takes a log handler for
/// handling internal logs from gensios and osfuncs.
pub fn new(log_func: Arc<dyn GensioLogHandler>) -> Result<Arc<OsFuncs>, i32> {
    let err;
    let o: *const raw::gensio_os_funcs = std::ptr::null();

    unsafe {
	err = raw::gensio_alloc_os_funcs(-198234, &o);
    }
    match err {
	0 => {
	    let d = Box::new(GensioLogHandlerData { cb: log_func });
	    let d = Box::into_raw(d);
	    unsafe {
		raw::gensio_rust_set_log(o, log_handler,
					 d as *mut ffi::c_void);
	    }
		let rv = Arc::new(
		    OsFuncs { o: Arc::new(IOsFuncs {log_data: d, o: o}),
			      proc_data: std::ptr::null()});
	    Ok(rv)
	}
	_ => Err(err)
    }
}

/// Used for OsFuncs to handle logs.
pub trait GensioLogHandler {
    /// Used to report internal logs from the system that couldn't be
    /// propagated back other ways.
    fn log(&self, s: String);
}

struct GensioLogHandlerData {
    cb: Arc<dyn GensioLogHandler>
}

extern "C" fn log_handler(log: *const ffi::c_char,
			  data: *mut ffi::c_void) {
    let d = data as *mut GensioLogHandlerData;
    let s = unsafe { ffi::CStr::from_ptr(log) };
    let s = s.to_str().expect("Invalid log string").to_string();

    unsafe { (*d).cb.log(s); }
}

impl OsFuncs {
    /// Called to setup the task (signals, shutdown handling, etc.)
    /// for a process.  This should be called on the first OsFuncs
    /// (and only the first one, this should only be called once
    /// unless all OsFucns have been freed and a new one allocated)
    /// and that OsFuncs should be kept around until you are done with
    /// all other OsFuncs.  You almost certainly should call this.
    /// The cleanup function is called automatically as part of the
    /// OsFuncs automatic cleanup.
    pub fn proc_setup(&self) -> Result<(), i32> {
	let err = unsafe { raw::gensio_os_proc_setup(self.o.o,
						     &self.proc_data) };
	match err {
	    0 => Ok(()),
	    _ => Err(err)
	}
    }

    /// Allocate a new Waiter function for the OsFuncs.
    pub fn new_waiter(&self) -> Option<Waiter> {
	let w;

	unsafe {
	    w = raw::gensio_os_funcs_alloc_waiter(self.o.o);
	}
	if w == std::ptr::null() {
	    None
	} else {
	    Some(Waiter { o: self.o.clone() , w: w })
	}
    }

    /// Get a reference to the os_funcs that we can keep and use.  For
    /// internal use only.
    pub fn raw(&self) -> Arc<IOsFuncs> {
	self.o.clone()
    }
}

impl Drop for OsFuncs {
    fn drop(&mut self) {
	unsafe {
	    if self.proc_data != std::ptr::null() {
		raw::gensio_os_proc_cleanup(self.proc_data);
	    }
	    // o will be freed by the Arc<>
	}
    }
}

/// A type used to wait for things to complete.  The wait call will do
/// gensio background processing as you would expect.
pub struct Waiter {
    o: Arc<IOsFuncs>,
    w: *const raw::gensio_waiter
}

impl Waiter {
    /// Decrement the wakeup count on a wait() call.  When the count
    /// reaches 0, that function will return success.
    pub fn wake(&self) -> Result<(), i32> {
	let err = unsafe { raw::gensio_os_funcs_wake(self.o.o, self.w) };
	match err {
	    0 => Ok(()),
	    _ => Err(err)
	}
    }

    /// Wait for a given number of wake calls to occur, or a timeout.
    /// If that many wake calls occur, this returns success with a
    /// duration of how much time is left.  On a timeout it returns a
    /// GE_TIMEDOUT error.  Other errors may occur.
    pub fn wait(&self, count: u32, timeout: &Duration)
		-> Result<Duration, i32> {
	let t = raw::gensio_time{ secs: timeout.as_secs() as i64,
				  nsecs: timeout.subsec_nanos() as i32 };
	let err = unsafe { raw::gensio_os_funcs_wait(self.o.o, self.w,
						     count, &t) };
	match err {
	    0 => Ok(Duration::new(t.secs as u64, t.nsecs as u32)),
	    _ => Err(err)
	}
    }

    /// Like wait, but if a signal is received, this will return a
    /// GE_INTERRUPTED error.
    pub fn wait_intr(&self, count: u32, timeout: &Duration)
		-> Result<Duration, i32> {
	let t = raw::gensio_time{ secs: timeout.as_secs() as i64,
				  nsecs: timeout.subsec_nanos() as i32 };
	let err = unsafe { raw::gensio_os_funcs_wait_intr(self.o.o, self.w,
							  count, &t) };
	match err {
	    0 => Ok(Duration::new(t.secs as u64, t.nsecs as u32)),
	    _ => Err(err)
	}
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
	unsafe {
	    raw::gensio_os_funcs_free_waiter(self.o.o, self.w);
	}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct LogHandler;

    impl GensioLogHandler for LogHandler {
	fn log(&self, _logstr: String) {
	    
	}
    }

    #[test]
    #[serial]
    fn wait_test() {
	let o = new(Arc::new(LogHandler)).expect("Couldn't allocate OsFuncs");
	let _o2 = new(Arc::new(LogHandler)).expect("Couldn't allocate OsFuncs");
	o.proc_setup().expect("Couldn't set up OsFuncs");
	let w = o.new_waiter().expect("Couldn't allocate Waiter");

	drop(o);
	assert_eq!(w.wait(1, &Duration::new(0, 0)), Err(crate::GE_TIMEDOUT));
    }
}
