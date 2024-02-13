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

use std::io;
use std::io::{Read, Seek, Write};

use byteorder::WriteBytesExt;

pub(crate) trait SizeableFile: Seek {
    fn get_len(&self) -> io::Result<u64>;

    fn set_len(&self, size: u64) -> io::Result<()>;
}

pub(crate) trait File: SizeableFile + Read + Write + Seek + WriteBytesExt {
    fn sync_all(&self) -> io::Result<()>;
}
