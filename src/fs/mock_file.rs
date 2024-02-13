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

#[cfg(test)]
use std::io::{Read, Result, Seek, SeekFrom, Write};

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
use crate::fs::file::File;

#[cfg(test)]
use crate::fs::file::SizeableFile;

#[cfg(test)]
mock! {
    #[cfg(test)]
    #[derive(Debug)]
    pub(crate) TestFile {}

    impl Read for TestFile {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize,>;
    }

    impl Write for TestFile {
        fn write(&mut self, buf: &[u8]) -> Result<usize>;
        fn flush(&mut self) -> Result<()>;
    }

    impl Seek for TestFile {
        fn seek(&mut self, pos: SeekFrom) -> Result<u64>;
    }

    impl File for TestFile {
        fn sync_all(&self) -> Result<()>;
    }

    impl SizeableFile for TestFile {
        fn get_len(&self) -> Result<u64>;
        fn set_len(&self, size: u64) -> Result<()>;
    }
}
