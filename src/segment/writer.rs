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

use crate::entry::Entry;
use crate::fs::file::File;
use crate::preallocator::Preallocator;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum SegmentWriteError {
    #[error("IO error")]
    IO {
        #[from]
        source: io::Error,
    },
}

#[derive(Debug)]
pub(crate) struct SegmentWriter<TFile: File, TPreallocator: Preallocator> {
    pub(super) file: TFile,
    pub(super) preallocator: TPreallocator,
}

impl<TFile: File, TPreallocator: Preallocator> SegmentWriter<TFile, TPreallocator> {
    pub(super) fn write(&mut self, entry: &Entry) -> Result<usize, SegmentWriteError> {
        let buf = entry.serialize();
        self.preallocator
            .preallocate_if_needed(&mut self.file, buf.len() as u64)?;
        let result = self.file.write(&buf)?;
        self.file.sync_all()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::Entry;
    use crate::fs::mock_file::MockTestFile;
    use crate::preallocator::MockTestPreallocator;
    use crate::segment::writer::{SegmentWriteError, SegmentWriter};
    use assert_matches::assert_matches;
    use std::error::Error;
    use std::io::ErrorKind;

    #[test]
    fn successful() {
        let mut writer = SegmentWriter {
            file: MockTestFile::new(),
            preallocator: MockTestPreallocator::new(),
        };
        writer
            .preallocator
            .expect_preallocate_if_needed()
            .withf(|_, size| *size == 1036)
            .return_once(|_, _| Ok(()));
        writer.file.expect_write().return_once(|b| Ok(b.len()));
        writer.file.expect_sync_all().return_once(|| Ok(()));

        let entry = Entry::new(0, vec![0_u8; 1024]);
        let result = writer.write(&entry).unwrap();
        assert_eq!(result, 1024);
    }

    #[test]
    fn io_error_preallocation() {
        let mut writer = SegmentWriter {
            file: MockTestFile::new(),
            preallocator: MockTestPreallocator::new(),
        };
        writer
            .preallocator
            .expect_preallocate_if_needed()
            .return_once(|_, _| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

        let entry = Entry::new(0, vec![0_u8; 1024]);
        let error = writer.write(&entry).unwrap_err();
        assert_matches!(error, SegmentWriteError::IO { source: _ });
        let source = error.source().unwrap();
        let source_error = source.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(source_error.kind(), ErrorKind::Other);
        assert_eq!(format!("{}", source_error), "test_error");
    }

    #[test]
    fn io_error_write() {
        let mut writer = SegmentWriter {
            file: MockTestFile::new(),
            preallocator: MockTestPreallocator::new(),
        };
        writer
            .preallocator
            .expect_preallocate_if_needed()
            .withf(|_, size| *size == 1036)
            .return_once(|_, _| Ok(()));
        writer
            .file
            .expect_write()
            .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

        let entry = Entry::new(0, vec![0_u8; 1024]);
        let error = writer.write(&entry).unwrap_err();
        assert_matches!(error, SegmentWriteError::IO { source: _ });
        let source = error.source().unwrap();
        let source_error = source.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(source_error.kind(), ErrorKind::Other);
        assert_eq!(format!("{}", source_error), "test_error");
    }

    #[test]
    fn io_error_sync() {
        let mut writer = SegmentWriter {
            file: MockTestFile::new(),
            preallocator: MockTestPreallocator::new(),
        };
        writer
            .preallocator
            .expect_preallocate_if_needed()
            .withf(|_, size| *size == 1036)
            .return_once(|_, _| Ok(()));
        writer.file.expect_write().return_once(|b| Ok(b.len()));
        writer
            .file
            .expect_sync_all()
            .return_once(|| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

        let entry = Entry::new(0, vec![0_u8; 1024]);
        let error = writer.write(&entry).unwrap_err();
        assert_matches!(error, SegmentWriteError::IO { source: _ });
        let source = error.source().unwrap();
        let source_error = source.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(source_error.kind(), ErrorKind::Other);
        assert_eq!(format!("{}", source_error), "test_error");
    }
}
