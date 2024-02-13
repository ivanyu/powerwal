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

use crate::fs::file::SizeableFile;
use std::io;

pub(crate) trait Preallocator {
    fn preallocate_if_needed<TF: SizeableFile>(
        &self,
        file: &mut TF,
        to_write: u64,
    ) -> io::Result<()>;
}

#[derive(Clone, Debug)]
pub(crate) struct NormalPreallocator {
    pub(crate) preallocate_size: u64,
}

impl Preallocator for NormalPreallocator {
    fn preallocate_if_needed<TF: SizeableFile>(
        &self,
        file: &mut TF,
        to_write: u64,
    ) -> io::Result<()> {
        let size = file.get_len()?;
        let pos = file.stream_position()?;
        match next_file_size_with_preallocation(size, pos, to_write, self.preallocate_size) {
            Some(next_size) => file.set_len(next_size),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mockall::mock! {
    #[cfg(test)]
    #[derive(Debug)]
    pub(crate) TestPreallocator {}

    #[cfg(test)]
    impl Preallocator for TestPreallocator {
        #[mockall::concretize]
        fn preallocate_if_needed<TF: SizeableFile>(&self, file: &mut TF, to_write: u64) -> io::Result<()>;
    }

    impl Clone for TestPreallocator {
        fn clone(&self) -> Self;
    }
}

fn next_file_size_with_preallocation(
    size: u64,
    pos: u64,
    to_write: u64,
    preallocate_size: u64,
) -> Option<u64> {
    if can_fit_into_file_without_allocation(size, pos, to_write) {
        None
    } else {
        let mut new_size = size + preallocate_size;
        while !can_fit_into_file_without_allocation(new_size, pos, to_write) {
            new_size = new_size + preallocate_size;
        }
        Some(new_size)
    }
}

fn can_fit_into_file_without_allocation(size: u64, pos: u64, to_write: u64) -> bool {
    pos + to_write <= size
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Write};

    use rstest::rstest;

    use crate::fs::file::SizeableFile;
    use crate::fs::mock_file::MockTestFile;
    use crate::fs::real_file::RealFile;
    use crate::preallocator::{
        can_fit_into_file_without_allocation, next_file_size_with_preallocation,
        NormalPreallocator, Preallocator,
    };

    #[rstest]
    #[case(10, 1024, 1024)]
    #[case(1030, 1024, 2048)]
    fn preallocate_if_needed(
        #[case] to_write: u64,
        #[case] preallocate_size: u64,
        #[case] expected_size: u64,
    ) {
        let preallocator = NormalPreallocator { preallocate_size };
        let mut file: RealFile = RealFile::new(tempfile::tempfile().unwrap());
        assert_eq!(file.get_len().unwrap(), 0);
        preallocator
            .preallocate_if_needed(&mut file, to_write)
            .unwrap();
        assert_eq!(file.get_len().unwrap(), expected_size);
    }

    #[test]
    fn series() {
        let preallocate_size = 1024;
        let preallocator = NormalPreallocator { preallocate_size };

        let mut file = RealFile::new(tempfile::tempfile().unwrap());
        assert_eq!(file.get_len().unwrap(), 0);

        let to_write = 10;
        let mut vec = Vec::new();
        vec.resize(to_write, 0);

        preallocator
            .preallocate_if_needed(&mut file, to_write as u64)
            .unwrap();
        assert_eq!(file.get_len().unwrap(), preallocate_size);

        for _ in 0..3 {
            preallocator
                .preallocate_if_needed(&mut file, to_write as u64)
                .unwrap();
            assert_eq!(file.get_len().unwrap(), preallocate_size);
            file.write(&vec).unwrap();
            assert_eq!(file.get_len().unwrap(), preallocate_size);
        }

        preallocator
            .preallocate_if_needed(&mut file, preallocate_size)
            .unwrap();
        assert_eq!(file.get_len().unwrap(), preallocate_size * 2);

        vec.resize(preallocate_size as usize, 0);
        file.write(&vec).unwrap();
        assert_eq!(file.get_len().unwrap(), preallocate_size * 2);
    }

    #[test]
    fn io_error() {
        let preallocate_size = 1024;
        let preallocator = NormalPreallocator { preallocate_size };
        let mut file: MockTestFile = MockTestFile::new();
        file.expect_get_len()
            .return_once(|| Err(std::io::Error::new(ErrorKind::Other, "test_error")));
        let error = preallocator
            .preallocate_if_needed(&mut file, 123)
            .unwrap_err();
        println!("{:?}", error);
    }

    #[rstest]
    #[case(0, 0, 1, 128, Some(128))]
    #[case(1, 0, 1, 128, None)]
    #[case(128, 128, 1, 128, Some(256))]
    #[case(0, 0, 129, 128, Some(256))]
    fn test_next_file_size_with_preallocation(
        #[case] size: u64,
        #[case] pos: u64,
        #[case] to_write: u64,
        #[case] preallocate_size: u64,
        #[case] expected: Option<u64>,
    ) {
        assert_eq!(
            next_file_size_with_preallocation(size, pos, to_write, preallocate_size),
            expected
        )
    }

    #[rstest]
    #[case(0, 0, 1, false)]
    #[case(1, 0, 1, true)]
    #[case(10, 10, 1, false)]
    fn test_can_fit_into_file_without_allocation(
        #[case] size: u64,
        #[case] pos: u64,
        #[case] to_write: u64,
        #[case] expected: bool,
    ) {
        assert_eq!(
            can_fit_into_file_without_allocation(size, pos, to_write),
            expected
        )
    }
}
