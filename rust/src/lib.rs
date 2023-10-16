use std::ffi;

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

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
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
}
