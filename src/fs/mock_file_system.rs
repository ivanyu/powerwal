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
use std::path::Path;

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
use crate::fs::file_system::FileSystem;
#[cfg(test)]
use crate::fs::mock_file::MockTestFile;

#[cfg(test)]
mock! {
    #[cfg(test)]
    pub(crate) TestFileSystem {}

    impl FileSystem<MockTestFile> for TestFileSystem {
        #[mockall::concretize]
        fn read_dir<P: AsRef<Path>>(&self, path: P) -> std::io::Result<std::fs::ReadDir>;

        #[mockall::concretize]
        fn create_for_read_write<P: AsRef<Path>>(&self, path: P) -> std::io::Result<MockTestFile>;

        #[mockall::concretize]
        fn open_for_read_write<P: AsRef<Path>>(&self, path: P) -> std::io::Result<MockTestFile>;

        #[mockall::concretize]
        fn open_for_read<P: AsRef<Path>>(&self, path: P) -> std::io::Result<MockTestFile>;
    }
}
