use std::sync::Arc;
use std::time::Duration;
pub mod raw;

/// Used to refcount gensio_os_funcs.
pub struct IOsFuncs {
    pub o: *const raw::gensio_os_funcs
}

impl Drop for IOsFuncs {
    fn drop(&mut self) {
	unsafe {
	    raw::gensio_os_funcs_free(self.o);
	}
    }
}

/// Os Handling functions for gensio You need one of these to do
/// pretty much anything with gensio.
pub struct OsFuncs {
    o: Arc<IOsFuncs>,
    p: *const raw::gensio_os_proc_data
}

/// Allocate an OsFuncs structure
pub fn new() -> Result<OsFuncs, i32> {
    let err;
    let o: *const raw::gensio_os_funcs = std::ptr::null();

    unsafe {
	err = raw::gensio_default_os_hnd(-198234, &o);
    }
    match err {
	0 => Ok(OsFuncs { o: Arc::new(IOsFuncs {o: o}), p:std::ptr::null() }),
	_ => Err(err)
    }
}

impl OsFuncs {
    /// Called to setup the task (signals, shutdown handling, etc.)
    /// for a process.  This should be called on the first OsFuncs and
    /// that OsFuncs should be kept around until you are done with all
    /// other OsFuncs.  You almost certainly should call this.  The
    /// cleanup function is called automatically as part of the
    /// OsFuncs automatic cleanup.
    pub fn proc_setup(&self) -> Result<(), i32> {
	let err = unsafe { raw::gensio_os_proc_setup(self.o.o, &self.p) };
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
	    if self.p != std::ptr::null() {
		raw::gensio_os_proc_cleanup(self.p);
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

    #[test]
    fn wait_test() {
	let o = new().expect("Couldn't allocate OsFuncs");
	o.proc_setup().expect("Couldn't set up OsFuncs");
	let w = o.new_waiter().expect("Couldn't allocate Waiter");

	drop(o);
	assert_eq!(w.wait(1, &Duration::new(0, 0)), Err(crate::GE_TIMEDOUT));
    }
}
