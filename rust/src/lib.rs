//! # gensio
//!
//! `gensio` is a tool for handling all sort of I/O.

use std::ffi;
use std::sync::Arc;
use std::rc::Rc;

pub mod osfuncs;
pub mod raw;

pub const GE_NOERR:			i32 = 0;
pub const GE_NOMEM:			i32 = 1;
pub const GE_NOTSUP:			i32 = 2;
pub const GE_INVAL:			i32 = 3;
pub const GE_NOTFOUND:			i32 = 4;
pub const GE_EXISTS:			i32 = 5;
pub const GE_OUTOFRANGE:		i32 = 6;
pub const GE_INCONSISTENT:		i32 = 7;
pub const GE_NODATA:			i32 = 8;
pub const GE_OSERR:			i32 = 9;
pub const GE_INUSE:			i32 = 10;
pub const GE_INPROGRESS:		i32 = 11;
pub const GE_NOTREADY:			i32 = 12;
pub const GE_TOOBIG:			i32 = 13;
pub const GE_TIMEDOUT:			i32 = 14;
pub const GE_RETRY:			i32 = 15;
pub const GE_KEYNOTFOUND:		i32 = 17;
pub const GE_CERTREVOKED:		i32 = 18;
pub const GE_CERTEXPIRED:		i32 = 19;
pub const GE_KEYINVALID:		i32 = 20;
pub const GE_NOCERT:			i32 = 21;
pub const GE_CERTINVALID:		i32 = 22;
pub const GE_PROTOERR:			i32 = 23;
pub const GE_COMMERR:			i32 = 24;
pub const GE_IOERR:			i32 = 25;
pub const GE_REMCLOSE:			i32 = 26;
pub const GE_HOSTDOWN:			i32 = 27;
pub const GE_CONNREFUSE:		i32 = 28;
pub const GE_DATAMISSING:		i32 = 29;
pub const GE_CERTNOTFOUND:		i32 = 30;
pub const GE_AUTHREJECT:		i32 = 31;
pub const GE_ADDRINUSE:			i32 = 32;
pub const GE_INTERRUPTED:		i32 = 33;
pub const GE_SHUTDOWN:			i32 = 34;
pub const GE_LOCALCLOSED:		i32 = 35;
pub const GE_PERM:			i32 = 36;
pub const GE_APPERR:			i32 = 37;
pub const GE_UNKNOWN_NAME_ERROR:	i32 = 38;
pub const GE_NAME_ERROR:		i32 = 39;
pub const GE_NAME_SERVER_FAILURE:	i32 = 40;
pub const GE_NAME_INVALID:		i32 = 41;
pub const GE_NAME_NET_NOT_UP:		i32 = 42;

type GensioDS = osfuncs::raw::gensiods;

extern "C" {
    fn printf(s: *const ffi::c_char);
}

pub fn printfit(s: &str) {
    let s1 = ffi::CString::new(s).expect("CString::new failed");
    unsafe {
	printf(s1.as_ptr());
    }
}

/// Open callbacks will need to implement this trait.
pub trait OpDoneErr {
    /// Report an error.  Unlike most other gensio interfaces,
    /// which combine the error with the read() method, the error
    /// report is done separately here.
    fn done_err(&self, err: i32);

    /// Report some received data.  The i32 return (first value in
    /// tuble) return is the error return, normally 0, and the u64
    /// (second value) is the number of bytes consumed.
    fn done(&self);
}

struct OpDoneErrData<'a> {
    cb: &'a dyn OpDoneErr
}

extern "C" fn op_done_err(_io: *const raw::gensio, err: ffi::c_int,
			  user_data: *mut ffi::c_void) {
    let d = user_data as *mut OpDoneErrData;
    let d = unsafe { Box::from_raw(d) }; // Use from_raw so it will be freed
    let cb = d.cb;
    if err == 0 {
	cb.done();
    } else {
	cb.done_err(err);
    }
}

/// Close callbacks will need to implement this trait.
pub trait OpDone {
    /// Report some received data.  The i32 return (first value in
    /// tuble) return is the error return, normally 0, and the u64
    /// (second value) is the number of bytes consumed.
    fn done(&self);
}

struct OpDoneData<'a> {
    cb: &'a dyn OpDone
}

impl Drop for OpDoneData<'_> {
    fn drop(&mut self) {
	printfit("drop OpDoneData\n");
    }
}

extern "C" fn op_done(_io: *const raw::gensio,
		      user_data: *mut ffi::c_void) {
    let d = user_data as *mut OpDoneData;
    let d = unsafe { Box::from_raw(d) }; // Use from_raw so it will be freed
    let cb = d.cb;
    cb.done();
}

/// The struct that gets callbacks from a gensio will need to
/// implement this trait.
pub trait GensioEvent {
    /// Report a read error.  Unlike most other gensio interfaces,
    /// which combine the error with the read() method, the error
    /// report is done separately here.
    fn err(&self, err: i32) -> i32;

    /// Report some received data.  The i32 return (first value in
    /// tuble) return is the error return, normally 0, and the u64
    /// (second value) is the number of bytes consumed.
    fn read(&self, buf: &[u8], auxdata: Option<Vec<String>>) -> (i32, u64);
}

/// A gensio
pub struct Gensio<'a> {
    _o: Arc<osfuncs::IOsFuncs>, // Used to keep the os funcs alive.
    g: *const raw::gensio,
    cb: &'a dyn GensioEvent
}

impl std::fmt::Debug for Gensio<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
	write!(f, "gensio")
    }
}

extern "C" fn evhndl(_io: *const raw::gensio, user_data: *const ffi::c_void,
		     event: ffi::c_int, err: ffi::c_int,
		     buf: *const ffi::c_void, buflen: *mut GensioDS,
		     _auxdata: *const *const ffi::c_char) -> ffi::c_int
{
    let g = user_data as *mut Gensio;
    let cb = unsafe { (*g).cb };

    if err != 0 {
	return cb.err(err);
    }

    let err;
    match event {
	raw::GENSIO_EVENT_READ => {
	    // Convert the buffer into a slice.  You can't use it directly as
	    // a pointer to create a CString with from_raw() because then Rust
	    // takes over ownership of the data, and will free it when this
	    // function exits.
	    let b = unsafe {
		std::slice::from_raw_parts(buf as *mut u8, *buflen as usize)
	    };
	    let count;
	    (err, count) = cb.read(b, None);
	    unsafe { *buflen = count as GensioDS; }
	}
	_ => err = GE_NOTSUP
    }
    err
}

/// Allocate a new gensio based upon the given string
pub fn new<'a>(s: String, o: &osfuncs::OsFuncs, cb: &'a impl GensioEvent)
	       -> Result<Gensio<'a>, i32>
{
    let or = o.raw().clone();
    let g: *const raw::gensio = std::ptr::null();
    let s = match ffi::CString::new(s) {
	Ok(s) => s,
	Err(_) => return Err(GE_INVAL)
    };
    let err = unsafe {
	raw::str_to_gensio(s.as_ptr(), or.o, evhndl,
			   std::ptr::null(), &g)
    };
    match err {
	0 => {
	    let d = Rc::new(Gensio { _o: or, g: g, cb: cb });
	    unsafe {
		raw::gensio_set_user_data(d.g,
					  Rc::as_ptr(&d) as *mut ffi::c_void);
	    }
	    let g = Rc::try_unwrap(d).expect("Error unwrapping Rc");
	    Ok(g)
	}
	_ => Err(GE_INVAL)
    }
}

impl<'a> Gensio<'a> {
    pub fn open<'c>(&self, cb: &'c impl OpDoneErr)
		    -> Result<&'c impl OpDoneErr, i32> {
	let d = Box::new(OpDoneErrData { cb : cb });
	let d = Box::into_raw(d);
	let err = unsafe {
	    raw::gensio_open(self.g, op_done_err, d as *mut ffi::c_void)
	};
	match err {
	    0 => Ok(cb),
	    _ => {
		unsafe { drop(Box::from_raw(d)); } // Free the data
		Err(err)
	    }
	}
    }

    pub fn close<'b>(&self, cb: &'b impl OpDone)
		     -> Result<&'b impl OpDone, i32> {
	let d = Box::new(OpDoneData { cb : cb });
	let d = Box::into_raw(d);
	let err = unsafe {
	    raw::gensio_close(self.g, op_done, d as *mut ffi::c_void)
	};
	match err {
	    0 => Ok(cb),
	    _ => {
		unsafe { drop(Box::from_raw(d)); } // Free the data
		Err(err)
	    }
	}
    }

    pub fn write(&self, data: &[u8], _auxdata: Option<Vec<String>>)
		 -> Result<u64, i32> {
	let mut count: GensioDS = 0;

	let err = unsafe {
	    raw::gensio_write(self.g, &mut count,
			      data.as_ptr() as *const ffi::c_void,
			      data.len() as GensioDS,
			      std::ptr::null())
	};
	match err {
	    0 => Ok(count),
	    _ => Err(err)
	}
    }

    pub fn read_enable(&self, enable: bool) {
	let enable = match enable { true => 1, false => 0 };
	unsafe {
	    raw::gensio_set_read_callback_enable(self.g, enable);
	}
    }
}

impl Drop for Gensio<'_> {
    fn drop(&mut self) {
	unsafe {
	    raw::gensio_close_s(self.g);
	    raw::gensio_free(self.g);
	}
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;

    struct EvStruct {
	w: osfuncs::Waiter
    }

    impl GensioEvent for EvStruct {
	fn err(&self, err: i32) -> i32 {
	    assert_eq!(err, 0);
	    0
	}

	fn read(&self, buf: &[u8], _auxdata: Option<Vec<String>>)
		-> (i32, u64) {
	    assert_eq!(buf.len(), 7);
	    let s = unsafe { std::str::from_utf8_unchecked(buf) };
	    assert_eq!(s, "teststr");
	    self.w.wake().expect("Wake open done failed");
	    (0, buf.len() as u64)
	}
    }

    impl OpDoneErr for EvStruct {
	fn done_err(&self, err: i32) {
	    assert_eq!(err, 0);
	}

	fn done(&self) {
	    self.w.wake().expect("Wake open done failed");
	}
    }

    impl OpDone for EvStruct {
	fn done(&self) {
	    printfit("Close done\n");
	    self.w.wake().expect("Wake close done failed");
	}
    }

    #[test]
    fn basic_gensio() {
	let o = osfuncs::new().expect("Couldn't allocate os funcs");
	o.proc_setup().expect("Couldn't setup proc");
	let w = o.new_waiter().expect("Couldn't allocate waiter");
	let e = EvStruct { w: w };
	let g = new("echo".to_string(), &o, &e).expect("Couldn't alloc gensio");
	g.open(&e).expect("Couldn't open genio");
	e.w.wait(1, &Duration::new(1, 0)).expect("Wait failed");
	g.read_enable(true);
	let count = g.write(&b"teststr".to_vec()[..], None).expect("Write failed");
	assert_eq!(count, 7);
	e.w.wait(1, &Duration::new(1, 0)).expect("Wait failed");
	g.close(&e).expect("Couldn't close gensio");
	e.w.wait(1, &Duration::new(1, 0)).expect("Wait failed");
    }
}
