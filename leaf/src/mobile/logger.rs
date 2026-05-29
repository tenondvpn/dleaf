use std::{
    ffi,
    io::{self, Write},
};

use bytes::BytesMut;

#[cfg(any(target_os = "ios", target_os = "macos"))]
extern "C" {
    fn leaf_mobile_log(message: *const ffi::c_char);
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn log_out(data: &[u8]) {
    let s = match ffi::CString::new(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    unsafe {
        leaf_mobile_log(s.as_ptr());
    }
}

#[cfg(target_os = "android")]
fn log_out(data: &[u8]) {
    let _ = ffi::CString::new(data);
}

pub struct ConsoleWriter(pub BytesMut);

impl Default for ConsoleWriter {
    fn default() -> Self {
        ConsoleWriter(BytesMut::new())
    }
}

unsafe impl Send for ConsoleWriter {}

impl Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        while let Some(i) = memchr::memchr(b'\n', &self.0) {
            let line = self.0.split_to(i + 1);
            log_out(&line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.0.is_empty() {
            log_out(&self.0);
            self.0.clear();
        }
        Ok(())
    }
}
