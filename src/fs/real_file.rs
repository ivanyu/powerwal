/*
 * Copyright 2024 Ivan Yurchenko
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::fs::File as StdFile;
use std::io;
use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};

use crate::fs::file::{File, SizeableFile};

#[derive(Debug)]
pub(crate) struct RealFile {
    file: StdFile,
}

impl RealFile {
    #[inline]
    pub(crate) fn new(file: StdFile) -> RealFile {
        RealFile { file }
    }
}

impl Read for RealFile {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.file.read_vectored(bufs)
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.file.read_to_end(buf)
    }

    #[inline]
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        self.file.read_to_string(buf)
    }
}

impl Write for RealFile {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.file.write_vectored(bufs)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for RealFile {
    #[inline]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

impl SizeableFile for RealFile {
    #[inline]
    fn get_len(&self) -> io::Result<u64> {
        self.file.metadata().map(|m| m.len())
    }

    #[inline]
    fn set_len(&self, size: u64) -> io::Result<()> {
        self.file.set_len(size)
    }
}

impl File for RealFile {
    #[inline]
    fn sync_all(&self) -> io::Result<()> {
        self.file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File as StdFile;
    use std::io::{IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};

    use tempfile::NamedTempFile;

    use crate::fs::file::{File, SizeableFile};
    use crate::fs::real_file::RealFile;

    const WRITTEN: [u8; 8] = [0_u8, 1, 2, 3, 4, 5, 6, 7];

    #[test]
    fn test_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let file = RealFile::new(StdFile::create(temp_file.path()).unwrap());
        assert_eq!(file.get_len().unwrap(), 0);
    }

    #[test]
    fn test_read() {
        let temp_file = NamedTempFile::new().unwrap();
        prepare_file_for_reading(&temp_file);

        let mut file = RealFile::new(StdFile::open(temp_file.path()).unwrap());
        let mut buf = Vec::new();
        buf.resize(8, 0_u8);
        let r = file.read(&mut buf).unwrap();
        assert_eq!(r, 8);
        assert_eq!(buf, WRITTEN);
    }

    #[test]
    fn test_read_vectored() {
        let temp_file = NamedTempFile::new().unwrap();
        prepare_file_for_reading(&temp_file);

        let mut file = RealFile::new(StdFile::open(temp_file.path()).unwrap());
        let mut buf1 = Vec::new();
        buf1.resize(4, 0_u8);
        let mut buf2 = Vec::new();
        buf2.resize(4, 0_u8);

        let mut bufs = [IoSliceMut::new(&mut buf1), IoSliceMut::new(&mut buf2)];
        let r = file.read_vectored(&mut bufs).unwrap();
        assert_eq!(r, 8);
        assert_eq!(buf1, WRITTEN[0..4]);
        assert_eq!(buf2, WRITTEN[4..8]);
    }

    #[test]
    fn test_read_to_end() {
        let temp_file = NamedTempFile::new().unwrap();
        prepare_file_for_reading(&temp_file);

        let mut file = RealFile::new(StdFile::open(temp_file.path()).unwrap());
        let mut buf = Vec::new();
        let r = file.read_to_end(&mut buf).unwrap();
        assert_eq!(r, 8);
        assert_eq!(buf, WRITTEN);
    }

    #[test]
    fn test_read_to_string() {
        let temp_file = NamedTempFile::new().unwrap();
        prepare_file_for_reading(&temp_file);

        let mut file = RealFile::new(StdFile::open(temp_file.path()).unwrap());
        let mut str = String::new();
        let r = file.read_to_string(&mut str).unwrap();
        assert_eq!(r, 8);
        assert_eq!(str.as_bytes(), WRITTEN);
    }

    fn prepare_file_for_reading(temp_file: &NamedTempFile) {
        let mut std_file = StdFile::create(temp_file.path()).unwrap();
        std_file.write(&WRITTEN).unwrap();
    }

    #[test]
    fn test_write() {
        let temp_file = NamedTempFile::new().unwrap();

        let mut file = RealFile::new(StdFile::create(temp_file.path()).unwrap());
        let r = file.write(&WRITTEN).unwrap();
        assert_eq!(r, 8);

        let mut std_file = StdFile::open(temp_file.path()).unwrap();
        let mut buf = Vec::new();
        buf.resize(8, 0_u8);
        std_file.read(&mut buf).unwrap();
        assert_eq!(buf, WRITTEN);
    }

    #[test]
    fn test_write_vectored() {
        let temp_file = NamedTempFile::new().unwrap();

        let mut file = RealFile::new(StdFile::create(temp_file.path()).unwrap());
        let io_slices = [IoSlice::new(&WRITTEN[0..4]), IoSlice::new(&WRITTEN[4..8])];
        let r = file.write_vectored(&io_slices).unwrap();
        assert_eq!(r, 8);

        let mut std_file = StdFile::open(temp_file.path()).unwrap();
        let mut buf = Vec::new();
        buf.resize(8, 0_u8);
        std_file.read(&mut buf).unwrap();
        assert_eq!(buf, WRITTEN);
    }

    #[test]
    fn test_flush() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut file = RealFile::new(StdFile::create(temp_file.path()).unwrap());
        file.flush().unwrap();
        file.write(&WRITTEN).unwrap();
        file.flush().unwrap();
    }

    #[test]
    fn test_seek() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut file = RealFile::new(
            StdFile::options()
                .read(true)
                .write(true)
                .open(temp_file.path())
                .unwrap(),
        );

        assert_eq!(file.stream_position().unwrap(), 0);
        file.write(&WRITTEN).unwrap();
        assert_eq!(file.stream_position().unwrap(), 8);

        file.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(file.stream_position().unwrap(), 0);
        file.write(&WRITTEN).unwrap();
        assert_eq!(file.stream_position().unwrap(), 8);
    }

    #[test]
    fn test_sync_all() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let mut file = RealFile::new(StdFile::create(temp_file.path()).unwrap());
        file.write(&WRITTEN).unwrap();
        // It's hard to automatically test the underlying sync_all is really called,
        // so just checking this is not failing.
        file.sync_all().unwrap();
    }

    #[test]
    fn test_get_and_set_len() {
        let temp_file = NamedTempFile::new().unwrap();
        let file = RealFile::new(StdFile::create(temp_file.path()).unwrap());
        assert_eq!(file.get_len().unwrap(), 0);
        file.set_len(4096).unwrap();
        assert_eq!(file.get_len().unwrap(), 4096);

        let std_file = StdFile::open(temp_file.path()).unwrap();
        assert_eq!(std_file.metadata().unwrap().len(), 4096);
    }

    #[test]
    // for coverage
    fn test_debug() {
        let temp_file = NamedTempFile::new().unwrap();
        format!(
            "{:?}",
            RealFile::new(StdFile::create(temp_file.path()).unwrap())
        );
    }
}
