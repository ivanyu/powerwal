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

use crate::fs::file::File;
use crate::fs::file_system::FileSystem;
use crate::preallocator::Preallocator;
use crate::segment::constants::{MAGIC, MAGIC_SIZE, VERSION, VERSION_SIZE};
use crate::segment::file_names::get_base_offset_from_segment_log_file_name;
use byteorder::{BigEndian, ReadBytesExt};
use std::io;
use std::io::ErrorKind;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum SegmentFileError {
    #[error("file not found")]
    NotFound,

    #[error("segment file is invalid: either magic or version is invalid")]
    InvalidSegmentFile,

    #[error("IO error")]
    IO {
        #[from]
        source: io::Error,
    },
}

pub(super) fn create_file_for_read_write<T>(
    fs: &impl FileSystem<T>,
    path: &Path,
    preallocator: impl Preallocator,
) -> Result<T, SegmentFileError>
where
    T: File,
{
    let mut file = fs
        .create_for_read_write(path)
        .map_err(SegmentFileError::from)?;
    init_segment_file(&mut file, preallocator).map_err(SegmentFileError::from)?;
    Ok(file)
}

fn init_segment_file(file: &mut impl File, preallocator: impl Preallocator) -> io::Result<()> {
    preallocator.preallocate_if_needed(file, (MAGIC_SIZE + VERSION_SIZE) as u64)?;
    file.write(&MAGIC)?;
    file.write_u16::<BigEndian>(VERSION)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn open_file_for_read_write<T>(
    fs: &impl FileSystem<T>,
    path: &Path,
) -> Result<T, SegmentFileError>
where
    T: File,
{
    match fs.open_for_read_write(path) {
        Ok(mut file) => {
            let valid = check_segment_file_initialized_validly(&mut file)
                .map_err(SegmentFileError::from)?;
            if valid {
                Ok(file)
            } else {
                Err(SegmentFileError::InvalidSegmentFile)
            }
        }

        Err(e) if e.kind() == ErrorKind::NotFound => Err(SegmentFileError::NotFound),

        Err(e) => Err(SegmentFileError::from(e)),
    }
}

pub(super) fn open_file_for_read<T>(
    fs: &impl FileSystem<T>,
    path: &Path,
) -> Result<T, SegmentFileError>
where
    T: File,
{
    match fs.open_for_read(path) {
        Ok(mut file) => {
            let valid = check_segment_file_initialized_validly(&mut file)
                .map_err(SegmentFileError::from)?;
            if valid {
                Ok(file)
            } else {
                Err(SegmentFileError::InvalidSegmentFile)
            }
        }

        Err(e) if e.kind() == ErrorKind::NotFound => Err(SegmentFileError::NotFound),

        Err(e) => Err(SegmentFileError::from(e)),
    }
}

fn check_segment_file_initialized_validly(file: &mut impl File) -> io::Result<bool> {
    let mut buf = vec![0_u8; MAGIC_SIZE];
    match file.read_exact(&mut buf) {
        Ok(_) if buf != MAGIC => {
            // Invalid magic.
            return Ok(false);
        }

        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            // Not enough bytes in the magic.
            return Ok(false);
        }

        Err(e) => return Err(e),

        Ok(_) => {
            match file.read_u16::<BigEndian>() {
                Ok(v) => Ok(v == VERSION),

                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    // Not enough bytes in the version.
                    Ok(false)
                }

                Err(e) => Err(e),
            }
        }
    }
}

fn list_log_segments<T>(fs: impl FileSystem<T>, dir: &Path) -> Vec<u64>
where
    T: File,
{
    let mut result: Vec<u64> = fs
        .read_dir(dir)
        .unwrap()
        .map(|e| get_base_offset_from_segment_log_file_name(e.unwrap().file_name()))
        .flatten()
        .collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    mod test_init_segment {
        use std::fs::File as StdFile;
        use std::io::ErrorKind;

        use tempfile::NamedTempFile;

        use crate::fs::file::File;
        use crate::fs::mock_file::MockTestFile;
        use crate::fs::real_file::RealFile;
        use crate::preallocator::NormalPreallocator;
        use crate::segment::files::{check_segment_file_initialized_validly, init_segment_file};

        #[test]
        fn successfully() {
            let temp_file = NamedTempFile::new().unwrap();

            {
                let mut file = RealFile::new(
                    StdFile::options()
                        .write(true)
                        .open(temp_file.path())
                        .unwrap(),
                );
                init_segment_file(
                    &mut file,
                    NormalPreallocator {
                        preallocate_size: 1024,
                    },
                )
                .unwrap();
            }

            let mut file = RealFile::new(StdFile::open(temp_file.path()).unwrap());
            check_segment_initialized(&mut file, 1024);
        }

        pub(super) fn check_segment_initialized(file: &mut impl File, expected_len: u64) {
            assert_eq!(file.get_len().unwrap(), expected_len);
            assert_eq!(check_segment_file_initialized_validly(file).unwrap(), true);
        }

        #[test]
        fn init_segment_sync_called() {
            let mut file = MockTestFile::new();
            file.expect_get_len().return_once(|| Ok(0_u64));
            file.expect_seek().return_once(|_| Ok(0_u64));
            file.expect_set_len().return_once(|_| Ok(()));
            file.expect_write().returning(|b| Ok(b.len()));

            // Checking this.
            file.expect_sync_all().times(1).return_once(|| Ok(()));

            init_segment_file(
                &mut file,
                NormalPreallocator {
                    preallocate_size: 1024,
                },
            )
            .unwrap();
        }

        #[test]
        fn init_segment_error_returned() {
            fn test_error<T>() -> Result<T, std::io::Error> {
                Err(std::io::Error::new(ErrorKind::Other, "test_error"))
            }

            let mut file = MockTestFile::new();
            file.expect_get_len().return_once(test_error);
            let result = init_segment_file(
                &mut file,
                NormalPreallocator {
                    preallocate_size: 1024,
                },
            )
            .unwrap_err();
            assert_eq!(result.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", result), "test_error");

            let mut file = MockTestFile::new();
            file.expect_get_len().return_once(|| Ok(0_u64));
            file.expect_seek().return_once(|_| test_error());
            assert_eq!(result.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", result), "test_error");

            let mut file = MockTestFile::new();
            file.expect_get_len().return_once(|| Ok(0_u64));
            file.expect_seek().return_once(|_| Ok(0_u64));
            file.expect_set_len().return_once(|_| test_error());
            assert_eq!(result.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", result), "test_error");

            let mut file = MockTestFile::new();
            file.expect_get_len().return_once(|| Ok(0_u64));
            file.expect_seek().return_once(|_| Ok(0_u64));
            file.expect_set_len().return_once(|_| Ok(()));
            file.expect_write().return_once(|_| test_error());
            assert_eq!(result.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", result), "test_error");
        }
    }

    mod test_check_segment_file_initialized_validly {
        use std::io::{ErrorKind, Seek, SeekFrom, Write};

        use byteorder::{BigEndian, WriteBytesExt};
        use mockall::Sequence;

        use crate::fs::mock_file::MockTestFile;
        use crate::fs::real_file::RealFile;
        use crate::segment::constants::{MAGIC, VERSION};
        use crate::segment::files::check_segment_file_initialized_validly;

        #[test]
        fn not_enough_bytes_for_magic() {
            let mut file: RealFile = RealFile::new(tempfile::tempfile().unwrap());
            file.write_u8(10).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();

            assert_eq!(
                check_segment_file_initialized_validly(&mut file).unwrap(),
                false
            );
        }

        #[test]
        fn invalid_magic() {
            let mut file: RealFile = RealFile::new(tempfile::tempfile().unwrap());
            let broken_magic: [u8; 4] = [80 + 1, 87, 65, 76];
            file.write(&broken_magic).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();

            assert_eq!(
                check_segment_file_initialized_validly(&mut file).unwrap(),
                false
            );
        }

        #[test]
        fn not_enough_bytes_for_version() {
            let mut file: RealFile = RealFile::new(tempfile::tempfile().unwrap());
            file.write(&MAGIC).unwrap();
            file.write_u8(10).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();

            assert_eq!(
                check_segment_file_initialized_validly(&mut file).unwrap(),
                false
            );
        }

        #[test]
        fn unsupported_version() {
            let mut file: RealFile = RealFile::new(tempfile::tempfile().unwrap());
            file.write(&MAGIC).unwrap();
            let unsupported_version = VERSION + 1;
            file.write_u16::<BigEndian>(unsupported_version).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();

            assert_eq!(
                check_segment_file_initialized_validly(&mut file).unwrap(),
                false
            );
        }

        #[test]
        fn valid() {
            let mut file: RealFile = RealFile::new(tempfile::tempfile().unwrap());
            file.write(&MAGIC).unwrap();
            file.write_u16::<BigEndian>(VERSION).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();

            assert_eq!(
                check_segment_file_initialized_validly(&mut file).unwrap(),
                true
            );
        }

        #[test]
        fn io_error_in_magic() {
            let mut file = MockTestFile::new();
            file.expect_read()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let result = check_segment_file_initialized_validly(&mut file).unwrap_err();
            assert_eq!(result.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", result), "test_error");
        }

        #[test]
        fn io_error_in_version() {
            let mut file = MockTestFile::new();

            let mut seq = Sequence::new();
            file.expect_read()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|mut b| {
                    b.write(&MAGIC).unwrap();
                    Ok(MAGIC.len())
                });
            file.expect_read()
                .times(1)
                .in_sequence(&mut seq)
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let result = check_segment_file_initialized_validly(&mut file).unwrap_err();
            assert_eq!(result.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", result), "test_error");
        }
    }

    mod test_create_file_for_read_write {
        use std::error::Error;
        use std::fs::File as StdFile;
        use std::io::ErrorKind;
        use std::path::Path;

        use assert_matches::assert_matches;
        use tempfile::NamedTempFile;

        use crate::fs::mock_file::MockTestFile;
        use crate::fs::mock_file_system::MockTestFileSystem;
        use crate::fs::real_file::RealFile;
        use crate::fs::real_file_system::RealFileSystem;
        use crate::preallocator::NormalPreallocator;
        use crate::segment::files::tests::test_init_segment::check_segment_initialized;
        use crate::segment::files::{create_file_for_read_write, SegmentFileError};
        use crate::test_utils::temp_file_path;

        #[test]
        fn successfully_create_and_init() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);

            // Open, initialize, and immediately close.
            {
                let preallocator = NormalPreallocator {
                    preallocate_size: 1024,
                };
                create_file_for_read_write(&fs, &temp_file, preallocator).unwrap();
            }

            let mut file = RealFile::new(StdFile::open(temp_file.as_path()).unwrap());
            check_segment_initialized(&mut file, 1024);
        }

        #[test]
        fn existing_file() {
            let fs = RealFileSystem::new();
            let temp_file = NamedTempFile::new().unwrap();

            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };
            let error =
                create_file_for_read_write(&fs, temp_file.path(), preallocator).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let io_error = error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap();
            assert_eq!(io_error.kind(), ErrorKind::AlreadyExists);
            assert_eq!(format!("{}", io_error), "File exists (os error 17)");
        }

        #[test]
        fn io_errors_on_creating() {
            let mut fs = MockTestFileSystem::new();
            fs.expect_create_for_read_write()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };
            let error =
                create_file_for_read_write(&fs, Path::new("aaa"), preallocator).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let io_error = error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap();
            assert_eq!(io_error.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", io_error), "test_error");
        }

        #[test]
        fn io_errors_on_preallocate() {
            let mut file = MockTestFile::new();
            file.expect_get_len().return_once(|| Ok(0));
            file.expect_seek().return_once(|_| Ok(0));
            file.expect_set_len()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let mut fs = MockTestFileSystem::new();
            fs.expect_create_for_read_write()
                .return_once(move |_| Ok(file));

            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };
            let error =
                create_file_for_read_write(&fs, Path::new("aaa"), preallocator).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let io_error = error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap();
            assert_eq!(io_error.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", io_error), "test_error");
        }

        #[test]
        fn io_errors_on_init() {
            let mut file = MockTestFile::new();
            file.expect_get_len().return_once(|| Ok(0));
            file.expect_seek().return_once(|_| Ok(0));
            file.expect_set_len().return_once(|_| Ok(()));
            file.expect_write()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let mut fs = MockTestFileSystem::new();
            fs.expect_create_for_read_write()
                .return_once(move |_| Ok(file));

            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };
            let error =
                create_file_for_read_write(&fs, Path::new("aaa"), preallocator).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let io_error = error
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap();
            assert_eq!(io_error.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", io_error), "test_error");
        }
    }

    mod test_open_file_for_read_write {
        use std::error::Error;
        use std::io::{ErrorKind, Seek, SeekFrom};
        use std::path::Path;

        use assert_matches::assert_matches;
        use byteorder::{ReadBytesExt, WriteBytesExt};

        use crate::fs::mock_file::MockTestFile;
        use crate::fs::mock_file_system::MockTestFileSystem;
        use crate::fs::real_file_system::RealFileSystem;
        use crate::preallocator::NormalPreallocator;
        use crate::segment::files::{
            create_file_for_read_write, open_file_for_read_write, SegmentFileError,
        };
        use crate::test_utils::temp_file_path;

        #[test]
        fn successfully_opened_correctly_initialized_file() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);

            // Open, initialize, and immediately close.
            {
                let preallocator = NormalPreallocator {
                    preallocate_size: 1024,
                };
                create_file_for_read_write(&fs, &temp_file.as_path(), preallocator).unwrap();
            }

            let mut file = open_file_for_read_write(&fs, temp_file.as_path()).unwrap();
            // Since we preallocate, a bunch of 0s are readable.
            let r = file.read_u8().unwrap();
            assert_eq!(r, 0);

            // Should be writable.
            assert!(file.write_u8(0).is_ok());
        }

        #[test]
        fn invalidly_initialized() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);

            // Open, initialize, break the magic, and close.
            {
                let preallocator = NormalPreallocator {
                    preallocate_size: 1024,
                };
                let mut file =
                    create_file_for_read_write(&fs, &temp_file.as_path(), preallocator).unwrap();
                file.seek(SeekFrom::Start(0)).unwrap();
                file.write_u8(0).unwrap();
            }

            let error = open_file_for_read_write(&fs, temp_file.as_path()).unwrap_err();
            assert_matches!(error, SegmentFileError::InvalidSegmentFile);
        }

        #[test]
        fn non_existent_file() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);
            let error = open_file_for_read_write(&fs, temp_file.as_path()).unwrap_err();
            assert_matches!(error, SegmentFileError::NotFound);
        }

        #[test]
        fn io_error_open() {
            let mut fs = MockTestFileSystem::new();
            fs.expect_open_for_read_write()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let error = open_file_for_read_write(&fs, Path::new("aaa")).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let source = error.source().unwrap();
            let source_error = source.downcast_ref::<std::io::Error>().unwrap();
            assert_eq!(source_error.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", source_error), "test_error");
        }

        #[test]
        fn io_error_read() {
            let mut file = MockTestFile::new();
            file.expect_read()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let mut fs = MockTestFileSystem::new();
            fs.expect_open_for_read_write()
                .return_once(move |_| Ok(file));

            let error = open_file_for_read_write(&fs, Path::new("aaa")).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let source = error.source().unwrap();
            let source_error = source.downcast_ref::<std::io::Error>().unwrap();
            assert_eq!(source_error.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", source_error), "test_error");
        }
    }

    mod test_open_file_for_read {
        use std::error::Error;
        use std::io::{ErrorKind, Seek, SeekFrom};
        use std::path::Path;

        use assert_matches::assert_matches;
        use byteorder::{ReadBytesExt, WriteBytesExt};

        use crate::fs::mock_file::MockTestFile;
        use crate::fs::mock_file_system::MockTestFileSystem;
        use crate::fs::real_file_system::RealFileSystem;
        use crate::preallocator::NormalPreallocator;
        use crate::segment::files::{
            create_file_for_read_write, open_file_for_read, SegmentFileError,
        };
        use crate::test_utils::temp_file_path;

        #[test]
        fn successfully_opened_correctly_initialized_file() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);

            // Open, initialize, and immediately close.
            {
                let preallocator = NormalPreallocator {
                    preallocate_size: 1024,
                };
                create_file_for_read_write(&fs, &temp_file.as_path(), preallocator).unwrap();
            }

            let mut file = open_file_for_read(&fs, temp_file.as_path()).unwrap();
            // Since we preallocate, a bunch of 0s are readable.
            let r = file.read_u8().unwrap();
            assert_eq!(r, 0);

            // Should be read-only.
            let error = file.write_u8(0).unwrap_err();
            // The Uncategorized kind is inaccessible.
            assert_eq!(format!("{}", error), "Bad file descriptor (os error 9)");
        }

        #[test]
        fn invalidly_initialized() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);

            // Open, initialize, break the magic, and close.
            {
                let preallocator = NormalPreallocator {
                    preallocate_size: 1024,
                };
                let mut file =
                    create_file_for_read_write(&fs, &temp_file.as_path(), preallocator).unwrap();
                file.seek(SeekFrom::Start(0)).unwrap();
                file.write_u8(0).unwrap();
            }

            let error = open_file_for_read(&fs, temp_file.as_path()).unwrap_err();
            assert_matches!(error, SegmentFileError::InvalidSegmentFile);
        }

        #[test]
        fn non_existent_file() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);
            let error = open_file_for_read(&fs, temp_file.as_path()).unwrap_err();
            assert_matches!(error, SegmentFileError::NotFound);
        }

        #[test]
        fn io_error_open() {
            let mut fs = MockTestFileSystem::new();
            fs.expect_open_for_read()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let error = open_file_for_read(&fs, Path::new("aaa")).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let source = error.source().unwrap();
            let source_error = source.downcast_ref::<std::io::Error>().unwrap();
            assert_eq!(source_error.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", source_error), "test_error");
        }

        #[test]
        fn io_error_read() {
            let mut file = MockTestFile::new();
            file.expect_read()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let mut fs = MockTestFileSystem::new();
            fs.expect_open_for_read().return_once(move |_| Ok(file));

            let error = open_file_for_read(&fs, Path::new("aaa")).unwrap_err();
            assert_matches!(error, SegmentFileError::IO { source: _ });
            let source = error.source().unwrap();
            let source_error = source.downcast_ref::<std::io::Error>().unwrap();
            assert_eq!(source_error.kind(), ErrorKind::Other);
            assert_eq!(format!("{}", source_error), "test_error");
        }
    }

    mod test_list_log_segments {
        use std::fs::File as StdFile;
        use std::io::ErrorKind;
        use std::path::Path;

        use crate::fs::mock_file_system::MockTestFileSystem;
        use crate::fs::real_file_system::RealFileSystem;
        use crate::segment::files::list_log_segments;

        #[test]
        fn success() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            StdFile::create(temp_dir.path().join("aaa.bbb")).unwrap();
            StdFile::create(temp_dir.path().join("00000000000000000000.log")).unwrap();
            StdFile::create(temp_dir.path().join("00000000000000010000.log")).unwrap();
            StdFile::create(temp_dir.path().join("00000000000000050708.log")).unwrap();
            StdFile::create(temp_dir.path().join("00000000000010067880.log")).unwrap();
            StdFile::create(temp_dir.path().join("29999999999999999999.log")).unwrap();
            StdFile::create(temp_dir.path().join("00000000000099999999.xxx")).unwrap();
            assert_eq!(
                list_log_segments(fs, temp_dir.path()),
                vec![0, 10000, 50708, 10067880]
            );
        }

        #[test]
        #[should_panic(
            expected = "called `Result::unwrap()` on an `Err` value: Custom { kind: Other, error: \"test_error\" }"
        )]
        fn io_error() {
            let mut fs = MockTestFileSystem::new();
            fs.expect_read_dir()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));
            list_log_segments(fs, Path::new("aaa"));
        }
    }
}
