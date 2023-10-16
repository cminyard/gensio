use std::sync::Arc;
use std::time::Duration;
pub mod raw;

// Used to refcount gensio_os_funcs
struct IOsFuncs {
    o: *const raw::gensio_os_funcs
}

impl Drop for IOsFuncs {
    fn drop(&mut self) {
	unsafe {
	    raw::gensio_os_funcs_free(self.o);
	}
    }
}

pub struct OsFuncs {
    o: Arc<IOsFuncs>,
    p: *const raw::gensio_os_proc_data
}

pub struct Waiter {
    o: Arc<IOsFuncs>,
    w: *const raw::gensio_waiter
}

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
    pub fn proc_setup(&self) -> Result<(), i32> {
	let err = unsafe { raw::gensio_os_proc_setup(self.o.o, &self.p) };
	match err {
	    0 => Ok(()),
	    _ => Err(err)
	}
    }

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

impl Waiter {
    pub fn wake(self) -> Result<(), i32> {
	let err = unsafe { raw::gensio_os_funcs_wake(self.o.o, self.w) };
	match err {
	    0 => Ok(()),
	    _ => Err(err)
	}
    }

    pub fn wait(self, count: u32, timeout: &Duration)
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
