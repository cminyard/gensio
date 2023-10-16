pub mod raw;

pub struct OsFuncs {
    o: *const raw::gensio_os_funcs
}

pub struct Waiter {
    o: *const raw::gensio_os_funcs,
    w: *const raw::gensio_waiter
}

pub fn new() -> Result<OsFuncs, i32>
{
    let err;
    let o: *const raw::gensio_os_funcs = std::ptr::null();

    unsafe {
	err = raw::gensio_default_os_hnd(0, &o);
    }
    if err != 0 {
	Err(err)
    } else {
	Ok(OsFuncs { o: o })
    }
}

impl OsFuncs {
    pub fn free(self)
    {
	unsafe { raw::gensio_os_funcs_free(self.o); }
    }

    pub fn new_waiter(&self) -> Option<Waiter>
    {
	let w;

	unsafe {
	    w = raw::gensio_os_funcs_alloc_waiter(self.o);
	}
	if w == std::ptr::null() {
	    None
	} else {
	    Some(Waiter { o: self.o, w: w })
	}
    }
}

impl Waiter {
    pub fn wake(self) -> i32
    {
	unsafe { raw::gensio_os_funcs_wake(self.o, self.w) }
    }

    pub fn wait(self, count: u32, timeout: i64) -> i32
    {
	let t = raw::gensio_time{ secs:timeout / 1000000000,
				  nsecs: (timeout % 1000000000) as i32 };
	unsafe { raw::gensio_os_funcs_wait(self.o, self.w, count, &t) }
    }
}
