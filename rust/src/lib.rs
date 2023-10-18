//! # gensio
//!
//! `gensio` is a tool for handling all sort of I/O.

use std::ffi;
use std::sync::Arc;

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
    /// Report an error on th eoperation.  Unlike most other gensio
    /// interfaces, which pass the error in the done() method, the
    /// error report is done separately here.
    fn done_err(&self, err: i32);

    /// Report that the operation (open) has completed.
    fn done(&self);
}

struct OpDoneErrData {
    cb: Arc<dyn OpDoneErr>
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
    /// Report that the operation (close) has completed.
    fn done(&self);
}

struct OpDoneData {
    cb: Arc<dyn OpDone>
}

extern "C" fn op_done(_io: *const raw::gensio,
		      user_data: *mut ffi::c_void) {
    let d = user_data as *mut OpDoneData;
    let d = unsafe { Box::from_raw(d) }; // Use from_raw so it will be freed
    d.cb.done();
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
pub struct Gensio {
    _o: Arc<osfuncs::IOsFuncs>, // Used to keep the os funcs alive.
    g: *const raw::gensio,
    cb: Arc<dyn GensioEvent>,

    // Points to the structure that is passed to the callback, which
    // is different than what is returned to the user.
    myptr: *mut Gensio
}

impl std::fmt::Debug for Gensio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
	write!(f, "gensio {:?}", self.g)
    }
}

// Convert an auxdata, like from a read call, to a vector of strings.
fn auxtovec(auxdata: *const *const ffi::c_char) -> Option<Vec<String>> {
    if auxdata == std::ptr::null() {
	None
    } else {
	let sl = unsafe { std::slice::from_raw_parts(auxdata, 10000) };
	let mut i = 0;
	let mut v: Vec<String> = Vec::new();
	while sl[i] != std::ptr::null() {
	    let cs = unsafe { ffi::CStr::from_ptr(sl[i]) };
	    v.push(cs.to_str().expect("Invalid string").to_string());
	    i += 1;
	}
	if i == 0 {
	    None
	} else {
	    Some(v)
	}
    }
}

// Convert a vector of strings to a vector of pointers to CString raw
// values.  You use as_ptr() to get a pointer to the array for
// something to pass into a C function that takes char **.  You must
// call auxfree() with the returned value, which will consume it and
// free the data.
fn vectoaux(vi: &[String]) -> Result<Vec<*mut ffi::c_char>, i32> {
    let mut vo: Vec<*mut ffi::c_char> = Vec::new();
    for i in vi {
	let cs = match ffi::CString::new(i.clone()) {
	    Ok(v) => v,
	    Err(_) => return Err(GE_INVAL)
	};
	vo.push(ffi::CString::into_raw(cs));
    }
    return Ok(vo);
}

// Free the value returned by vectoaux().
fn auxfree(v: Option<Vec<*mut ffi::c_char>>) {
    match v {
	None => (),
	Some(x) => {
	    for i in x {
		let cs = unsafe { ffi::CString::from_raw(i) };
		drop(cs);
	    }
	}
    }
}

extern "C" fn evhndl(_io: *const raw::gensio, user_data: *const ffi::c_void,
		     event: ffi::c_int, err: ffi::c_int,
		     buf: *const ffi::c_void, buflen: *mut GensioDS,
		     auxdata: *const *const ffi::c_char) -> ffi::c_int
{
    let g = user_data as *mut Gensio;

    if err != 0 {
	return unsafe {(*g).cb.err(err)};
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
	    let a = auxtovec(auxdata);
	    let count;
	    (err, count) = unsafe { (*g).cb.read(b, a) };
	    unsafe { *buflen = count as GensioDS; }
	}
	_ => err = GE_NOTSUP
    }
    err
}

/// Allocate a new gensio based upon the given string.  We pass in an
/// Arc holding the reference to the event handler.  This function
/// clones it so it can make sure the data stays around until the
/// gensio is closed.
pub fn new(s: String, o: &osfuncs::OsFuncs, cb: Arc<dyn GensioEvent>)
	   -> Result<Gensio, i32>
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
	    let d = Box::new(Gensio { _o: or.clone(), g: g, cb: cb.clone(),
				       myptr: std::ptr::null_mut() });
	    let d = Box::into_raw(d);
	    unsafe {
		raw::gensio_set_user_data((*d).g, d as *mut ffi::c_void);
	    }
	    Ok(Gensio { _o: or, g: g, cb: cb, myptr: d })
	}
	_ => Err(GE_INVAL)
    }
}

impl Gensio {
    /// Open the gensio.  The cb will be called when the operation
    /// completes.  Note that the Arc holding the callback is done so
    /// the callback data can be kept around until the callback is
    /// complete.
    ///
    /// Note that the gensio is not open until the callback is called.
    pub fn open(&self, cb: Arc<dyn OpDoneErr>) -> Result<(), i32> {
	let d = Box::new(OpDoneErrData { cb : cb });
	let d = Box::into_raw(d);
	let err = unsafe {
	    raw::gensio_open(self.g, op_done_err, d as *mut ffi::c_void)
	};
	match err {
	    0 => Ok(()),
	    _ => {
		unsafe { drop(Box::from_raw(d)); } // Free the data
		Err(err)
	    }
	}
    }

    /// Close the gensio.  The cb will be called when the operation
    /// completes.  Note that the Arc holding the callback is done so
    /// the callback data can be kept around until the callback is
    /// complete.
    ///
    /// Note that the gensio is not closed until the callback is called.
    pub fn close(&self, cb: Arc<dyn OpDone>) -> Result<(), i32> {
	let d = Box::new(OpDoneData { cb : cb });
	let d = Box::into_raw(d);
	let err = unsafe {
	    raw::gensio_close(self.g, op_done, d as *mut ffi::c_void)
	};
	match err {
	    0 => Ok(()),
	    _ => {
		unsafe { drop(Box::from_raw(d)); } // Free the data
		Err(err)
	    }
	}
    }

    /// Write some data to the gensio.  On success, the number of
    /// bytes written is returned.  On failure an error code is
    /// returned.
    pub fn write(&self, data: &[u8], auxdata: Option<&[String]>)
		 -> Result<u64, i32> {
	let mut count: GensioDS = 0;
	let a1 = match auxdata {
	    None => None,
	    Some(ref v) => Some(vectoaux(v)?)
	};
	let a2: *mut *mut ffi::c_char = match a1 {
	    None => std::ptr::null_mut(),
	    Some(ref v) => v.as_ptr() as *mut *mut ffi::c_char
	};

	let err = unsafe {
	    raw::gensio_write(self.g, &mut count,
			      data.as_ptr() as *const ffi::c_void,
			      data.len() as GensioDS,
			      a2 as *const *const ffi::c_char)
	};
	auxfree(a1);
	match err {
	    0 => Ok(count),
	    _ => Err(err)
	}
    }

    /// Enable or disable the read callback.
    pub fn read_enable(&self, enable: bool) {
	let enable = match enable { true => 1, false => 0 };
	unsafe {
	    raw::gensio_set_read_callback_enable(self.g, enable);
	}
    }
}

impl Drop for Gensio {
    fn drop(&mut self) {
	unsafe {
	    // Only the Gensio given to the user has a pointer set in
	    // myptr, so we clean when the main gensio is freed then
	    // free the one passed to the callbacks.
	    if self.myptr != std::ptr::null_mut() {
		raw::gensio_close_s(self.g);
		raw::gensio_free(self.g);
		drop(Box::from_raw(self.myptr));
	    }
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
	    self.w.wake().expect("Wake close done failed");
	}
    }

    struct LogHandler;

    impl osfuncs::GensioLogHandler for LogHandler {
	fn log(&self, _logstr: String) {
	    
	}
    }

    #[test]
    fn basic_gensio() {
	let o = osfuncs::new(Arc::new(LogHandler))
	    .expect("Couldn't allocate os funcs");
	o.proc_setup().expect("Couldn't setup proc");
	let w = o.new_waiter().expect("Couldn't allocate waiter");
	let e = Arc::new(EvStruct { w: w });
	let g = new("echo".to_string(), &o, e.clone())
	    .expect("Couldn't alloc gensio");
	g.open(e.clone()).expect("Couldn't open genio");
	e.w.wait(1, &Duration::new(1, 0)).expect("Wait failed");
	g.read_enable(true);
	let v1 = vec!["t1".to_string(), "t2".to_string()];
	let count = g.write(&b"teststr".to_vec()[..], Some(&v1))
			    .expect("Write failed");
	assert_eq!(count, 7);
	e.w.wait(1, &Duration::new(1, 0)).expect("Wait failed");
	g.close(e.clone()).expect("Couldn't close gensio");
	e.w.wait(1, &Duration::new(1, 0)).expect("Wait failed");
    }
}
