use std::ffi;

pub mod osfuncs;
pub mod raw;

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
    Err(osfuncs::raw::GE_NOTSUP)
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
