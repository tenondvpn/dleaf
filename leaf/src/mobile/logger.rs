use std::io::{self, Write};

use bytes::BytesMut;

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn log_out(_data: &[u8]) {}

#[cfg(target_os = "android")]
fn log_out(data: &[u8]) {
    use std::ffi::CString;
    if let (Ok(tag), Ok(msg)) = (CString::new("LeafRust"), CString::new(data)) {
        extern "C" {
            fn __android_log_write(prio: i32, tag: *const std::os::raw::c_char, text: *const std::os::raw::c_char) -> i32;
        }
        unsafe {
            __android_log_write(4, tag.as_ptr(), msg.as_ptr());
        }
    }
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
            let trimmed = line.iter().rposition(|&b| b != b'\n' && b != b'\r' && b != b' ')
                .map(|i| &line[..=i])
                .unwrap_or(&[]);
            if !trimmed.is_empty() {
                log_out(trimmed);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
