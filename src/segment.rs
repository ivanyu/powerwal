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

use std::ffi::OsString;
use std::io;
use std::io::ErrorKind;
use std::mem::size_of;
use std::path::Path;
use std::str::FromStr;

use byteorder::{BigEndian, ReadBytesExt};
use lazy_static::lazy_static;
use log::error;
use regex::Regex;
use thiserror::Error;

use crate::fs::file::File;
use crate::fs::file_system::FileSystem;
use crate::preallocator::Preallocator;

lazy_static! {
    static ref LOG_FILE_NAME_RE: Regex = Regex::new(r"^(\d{20})\.log$").unwrap();
}

#[derive(Error, Debug)]
enum SegmentError {
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

const MAGIC_SIZE: usize = size_of::<u8>() * 4;

// PWAL
const MAGIC: [u8; 4] = [80, 87, 65, 76];

const VERSION_SIZE: usize = size_of::<u16>();
const VERSION: u16 = 0;

pub(crate) struct Segment {
    base_offset: u64,
    size: u64,
}

impl Segment {
    const PREALLOCATE_SIZE: u64 = 64 * 1024 * 1024; // TODO make configurable

    //     fn new(dir: &Path, base_offset: u64, active: bool) -> Segment {
    //         let filename = dir.join(log_file_name(base_offset));
    //
    //         let file_for_read = match fs::File::open(filename) {
    //             Ok(f) => f,
    //
    //             Err(e) if e.kind() == NotFound && active => {
    //                 // TODO: Create and init
    //
    //                 unimplemented!()
    //             }
    //
    //             Err(e) if e.kind() == NotFound && !active => {
    //                 unimplemented!()
    //             }
    //
    //             Err(e) => {
    //                 println!("{:?}", e.kind());
    //                 unimplemented!()
    //             }
    //         };
    //
    //         Segment {
    //             base_offset,
    //             size: 0,
    //         }
    //     }
}

fn create_file_for_read_write<T>(
    fs: &impl FileSystem<T>,
    path: &Path,
    preallocator: impl Preallocator,
) -> Result<T, SegmentError>
where
    T: File,
{
    let mut file = fs.create_for_read_write(path).map_err(SegmentError::from)?;
    init_segment_file(&mut file, preallocator).map_err(SegmentError::from)?;
    Ok(file)
}

fn init_segment_file(file: &mut impl File, preallocator: impl Preallocator) -> io::Result<()> {
    preallocator.preallocate_if_needed(file, (MAGIC_SIZE + VERSION_SIZE) as u64)?;
    file.write(&MAGIC)?;
    file.write_u16::<BigEndian>(VERSION)?;
    file.sync_all()?;
    Ok(())
}

fn open_file_for_read_write<T>(fs: &impl FileSystem<T>, path: &Path) -> Result<T, SegmentError>
where
    T: File,
{
    match fs.open_for_read_write(path) {
        Ok(mut file) => {
            let valid =
                check_segment_file_initialized_validly(&mut file).map_err(SegmentError::from)?;
            if valid {
                Ok(file)
            } else {
                Err(SegmentError::InvalidSegmentFile)
            }
        }

        Err(e) if e.kind() == ErrorKind::NotFound => Err(SegmentError::NotFound),

        Err(e) => Err(SegmentError::from(e)),
    }
}

fn open_file_for_read<T>(fs: &impl FileSystem<T>, path: &Path) -> Result<T, SegmentError>
where
    T: File,
{
    match fs.open_for_read(path) {
        Ok(mut file) => {
            let valid =
                check_segment_file_initialized_validly(&mut file).map_err(SegmentError::from)?;
            if valid {
                Ok(file)
            } else {
                Err(SegmentError::InvalidSegmentFile)
            }
        }

        Err(e) if e.kind() == ErrorKind::NotFound => Err(SegmentError::NotFound),

        Err(e) => Err(SegmentError::from(e)),
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

fn log_file_name(base_offset: u64) -> String {
    return format!("{:0>20}.log", base_offset);
}

fn get_base_offset_from_segment_log_file_name(file_name: OsString) -> Option<u64> {
    match file_name.to_str() {
        Some(s) => match LOG_FILE_NAME_RE.captures(s) {
            Some(captures) => {
                // Safe to unwrap: we know the group 1 exists.
                let r = captures.get(1).unwrap().as_str();
                u64::from_str(r).ok()
            }

            None => None,
        },

        // Unsupported symbols -- for sure it's not what we're looking for, skipping.
        None => None,
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
    use std::ffi::OsString;

    use rstest::rstest;

    use crate::segment::{get_base_offset_from_segment_log_file_name, log_file_name};

    mod test_init_segment {
        use std::fs::File as StdFile;
        use std::io::ErrorKind;

        use tempfile::NamedTempFile;

        use crate::fs::file::File;
        use crate::fs::mock_file::MockTestFile;
        use crate::fs::real_file::RealFile;
        use crate::preallocator::NormalPreallocator;
        use crate::segment::{check_segment_file_initialized_validly, init_segment_file};

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
        use crate::segment::{check_segment_file_initialized_validly, MAGIC, VERSION};

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
        use crate::segment::tests::test_init_segment::check_segment_initialized;
        use crate::segment::{create_file_for_read_write, SegmentError};
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
            assert_matches!(error, SegmentError::IO { source: _ });
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
            assert_matches!(error, SegmentError::IO { source: _ });
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
            assert_matches!(error, SegmentError::IO { source: _ });
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
            assert_matches!(error, SegmentError::IO { source: _ });
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
        use crate::segment::{create_file_for_read_write, open_file_for_read_write, SegmentError};
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
            assert_matches!(error, SegmentError::InvalidSegmentFile);
        }

        #[test]
        fn non_existent_file() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);
            let error = open_file_for_read_write(&fs, temp_file.as_path()).unwrap_err();
            assert_matches!(error, SegmentError::NotFound);
        }

        #[test]
        fn io_error_open() {
            let mut fs = MockTestFileSystem::new();
            fs.expect_open_for_read_write()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let error = open_file_for_read_write(&fs, Path::new("aaa")).unwrap_err();
            assert_matches!(error, SegmentError::IO { source: _ });
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
            assert_matches!(error, SegmentError::IO { source: _ });
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
        use crate::segment::{create_file_for_read_write, open_file_for_read, SegmentError};
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
            assert_matches!(error, SegmentError::InvalidSegmentFile);
        }

        #[test]
        fn non_existent_file() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);
            let error = open_file_for_read(&fs, temp_file.as_path()).unwrap_err();
            assert_matches!(error, SegmentError::NotFound);
        }

        #[test]
        fn io_error_open() {
            let mut fs = MockTestFileSystem::new();
            fs.expect_open_for_read()
                .return_once(|_| Err(std::io::Error::new(ErrorKind::Other, "test_error")));

            let error = open_file_for_read(&fs, Path::new("aaa")).unwrap_err();
            assert_matches!(error, SegmentError::IO { source: _ });
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
            assert_matches!(error, SegmentError::IO { source: _ });
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
        use crate::segment::list_log_segments;

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

    #[rstest]
    #[case(0, "00000000000000000000.log")]
    #[case(1234, "00000000000000001234.log")]
    #[case(12345123451234512345, "12345123451234512345.log")]
    fn test_log_file_name(#[case] base_offset: u64, #[case] expected: String) {
        assert_eq!(log_file_name(base_offset), expected);
    }

    #[rstest]
    #[case("00000000000000000000.xxx", None)]
    #[case("00000000000000000000.log1", None)]
    #[case("00000000000000000000.log", Some(0))]
    #[case("00000000000000001234.log", Some(1234))]
    #[case("12345123451234512345.log", Some(12345123451234512345))]
    #[case("a.log", None)]
    #[case("0000000000000000000a.log", None)]
    #[case("1.log", None)]
    #[case("0000000000000000123.log", None)]
    #[case("9999999999999999999.log", None)] // too big
    #[case(unsafe { OsString::from_encoded_bytes_unchecked(vec ! [0x9f]) }, None)] // invalid UTF
    fn test_get_base_offset_from_segment_log_file_name(
        #[case] input: OsString,
        #[case] expected: Option<u64>,
    ) {
        assert_eq!(get_base_offset_from_segment_log_file_name(input), expected);
    }
}
