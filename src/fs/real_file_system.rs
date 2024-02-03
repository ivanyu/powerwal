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

use std::fs::{File as StdFile, ReadDir};
use std::io;
use std::path::Path;

use crate::fs::file_system::FileSystem;
use crate::fs::real_file::RealFile;

#[derive(Debug)]
pub(crate) struct RealFileSystem {}

impl RealFileSystem {
    pub(crate) fn new() -> RealFileSystem {
        RealFileSystem {}
    }
}

impl FileSystem<RealFile> for RealFileSystem {
    fn read_dir<P: AsRef<Path>>(&self, path: P) -> io::Result<ReadDir> {
        std::fs::read_dir(path)
    }

    fn create_for_read_write<P: AsRef<Path>>(&self, path: P) -> io::Result<RealFile> {
        StdFile::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .map(RealFile::new)
    }

    fn open_for_read_write<P: AsRef<Path>>(&self, path: P) -> io::Result<RealFile> {
        StdFile::options()
            .read(true)
            .write(true)
            .open(path)
            .map(RealFile::new)
    }

    fn open_for_read<P: AsRef<Path>>(&self, path: P) -> io::Result<RealFile> {
        StdFile::options().read(true).open(path).map(RealFile::new)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs::File as StdFile;

    use crate::fs::file_system::FileSystem;
    use crate::fs::real_file_system::RealFileSystem;

    const WRITTEN: [u8; 8] = [0_u8, 1, 2, 3, 4, 5, 6, 7];

    #[test]
    fn test_read_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        StdFile::create(temp_dir.path().join("aaa1")).unwrap();
        StdFile::create(temp_dir.path().join("bbb1")).unwrap();
        StdFile::create(temp_dir.path().join("ccc1")).unwrap();
        let fs = RealFileSystem::new();
        let result = fs.read_dir(temp_dir.path()).unwrap();
        let mut entries: Vec<OsString> = result.flatten().map(|d| d.file_name()).collect();
        entries.sort();
        assert_eq!(entries, vec!["aaa1", "bbb1", "ccc1"]);
    }

    mod test_create_for_rw {
        use std::io::{ErrorKind, Seek, SeekFrom};

        use byteorder::{ReadBytesExt, WriteBytesExt};
        use tempfile::NamedTempFile;

        use crate::fs::file_system::FileSystem;
        use crate::fs::real_file_system::RealFileSystem;
        use crate::test_utils::temp_file_path;

        #[test]
        fn non_existent() {
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);
            let fs = RealFileSystem::new();
            let mut file = fs.create_for_read_write(temp_file).unwrap();
            // check writable
            file.write_u8(42).unwrap();
            // check readable
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.read_u8().unwrap(), 42);
        }

        #[test]
        fn existing() {
            let temp_file = NamedTempFile::new().unwrap();
            let fs = RealFileSystem::new();
            let error = fs.create_for_read_write(temp_file.path()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::AlreadyExists);
            assert_eq!(format!("{}", error), "File exists (os error 17)");
        }
    }

    mod test_open_for_rw {
        use std::io::{ErrorKind, Seek, SeekFrom};

        use byteorder::{ReadBytesExt, WriteBytesExt};
        use tempfile::NamedTempFile;

        use crate::fs::file_system::FileSystem;
        use crate::fs::real_file_system::RealFileSystem;
        use crate::test_utils::temp_file_path;

        #[test]
        fn non_existent() {
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);
            let fs = RealFileSystem::new();
            let error = fs.open_for_read_write(temp_file.as_path()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound);
            assert_eq!(
                format!("{}", error),
                "No such file or directory (os error 2)"
            );
        }

        #[test]
        fn existing() {
            let temp_file = NamedTempFile::new().unwrap();
            let fs = RealFileSystem::new();
            let mut file = fs.open_for_read_write(temp_file).unwrap();
            // check writable
            file.write_u8(42).unwrap();
            // check readable
            file.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(file.read_u8().unwrap(), 42);
        }
    }

    mod test_open_for_read {
        use std::fs::File as StdFile;
        use std::io::{ErrorKind, Read, Write};

        use byteorder::WriteBytesExt;
        use tempfile::NamedTempFile;

        use crate::fs::file_system::FileSystem;
        use crate::fs::real_file_system::tests::WRITTEN;
        use crate::fs::real_file_system::RealFileSystem;
        use crate::test_utils::temp_file_path;

        #[test]
        fn non_existent() {
            let temp_dir = tempfile::tempdir().unwrap();
            let temp_file = temp_file_path(temp_dir.path(), 10);
            let fs = RealFileSystem::new();
            let error = fs.open_for_read(temp_file.as_path()).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound);
            assert_eq!(
                format!("{}", error),
                "No such file or directory (os error 2)"
            );
        }

        #[test]
        fn existing() {
            let temp_file = NamedTempFile::new().unwrap();
            {
                let mut std_file = StdFile::create(temp_file.path()).unwrap();
                std_file.write(&WRITTEN).unwrap();
            }

            let fs = RealFileSystem::new();
            let mut file = fs.open_for_read(temp_file.path()).unwrap();
            // Should be readable.
            let mut buf = Vec::<u8>::new();
            file.read_to_end(&mut buf).unwrap();
            assert_eq!(buf, WRITTEN);
            // Should be read-only.
            let error = file.write_u8(42).unwrap_err();
            // The Uncategorized kind is inaccessible.
            assert_eq!(format!("{}", error), "Bad file descriptor (os error 9)");
        }
    }

    #[test]
    // for coverage
    fn test_debug() {
        format!("{:?}", RealFileSystem::new());
    }
}
