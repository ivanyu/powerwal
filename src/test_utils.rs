use fastrand::alphanumeric;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[cfg(test)]
pub(crate) fn temp_file_path(dir: &Path, len: usize) -> PathBuf {
    let mut buf = OsString::with_capacity(len);
    for _ in 0..len {
        buf.push(alphanumeric().to_string());
    }
    dir.join(buf)
}
