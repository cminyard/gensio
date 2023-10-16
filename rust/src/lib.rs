use std::ffi;

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

extern "C" {
    fn printf(s: *const ffi::c_char);
}

pub fn printfit(s: &str) {
    let s1 = ffi::CString::new(s).expect("CString::new failed");
    unsafe {
	printf(s1.as_ptr());
    }
}

pub trait GensioEvent {
    fn read(err: i32, buf: &[u8], auxdata: Option<Vec<String>>) -> (i32, u64);
}

pub struct Gensio {
    g: *const raw::gensio
}

pub fn new(_s: String, _o: osfuncs::OsFuncs, _cb: &impl GensioEvent)
	   -> Result<Gensio, i32>
{
    Err(GE_NOTSUP)
}

impl Gensio {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printf_test() {
	printfit("Hello There\n");
    }
}
