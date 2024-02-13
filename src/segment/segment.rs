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

use crate::entry::{DeserializationError, Entry};
use std::io::SeekFrom;
use std::path::Path;

use crate::fs::file::File;
use crate::fs::file_system::FileSystem;
use crate::preallocator::Preallocator;
use crate::segment::file_names::log_file_name;
use crate::segment::files::{
    create_file_for_read_write, open_file_for_read, open_file_for_read_write, SegmentFileError,
};
use crate::segment::writer::{SegmentWriteError, SegmentWriter};

const PREALLOCATE_SIZE: u64 = 64 * 1024 * 1024; // TODO make configurable

#[derive(Debug)]
pub struct Segment<TFile: File, TPreallocator: Preallocator> {
    base_offset: u64,
    size: u64, // TODO is it needed?
    read_file: TFile,
    writer: Option<SegmentWriter<TFile, TPreallocator>>,
}

impl<TFile: File, TPreallocator: Preallocator + Clone> Segment<TFile, TPreallocator> {
    pub fn open(
        fs: &impl FileSystem<TFile>,
        dir: &Path,
        base_offset: u64,
        active: bool,
        preallocator: TPreallocator,
    ) -> Result<Segment<TFile, TPreallocator>, SegmentFileError> {
        let file_path = dir.join(log_file_name(base_offset));
        if active {
            Segment::open_active(fs, &file_path, base_offset, preallocator)
        } else {
            Segment::open_passive(fs, &file_path, base_offset)
        }
    }

    fn open_active(
        fs: &impl FileSystem<TFile>,
        file_path: &Path,
        base_offset: u64,
        preallocator: TPreallocator,
    ) -> Result<Segment<TFile, TPreallocator>, SegmentFileError> {
        let mut write_file = match open_file_for_read_write(fs, file_path) {
            Ok(f) => f,

            Err(SegmentFileError::NotFound) => {
                create_file_for_read_write(fs, file_path, preallocator.clone())?
            }

            Err(e) => return Err(e),
        };

        while write_file.stream_position()? < write_file.get_len()? {
            // TODO reduce syscalls
            let write_file_pos_before_read = write_file.stream_position()?;
            match Entry::deserialize(0, &mut write_file) {
                Ok(_) => { /* do nothing */ }

                Err(DeserializationError::Validation) => {
                    write_file.seek(SeekFrom::Start(write_file_pos_before_read))?;
                    write_file.set_len(write_file_pos_before_read)?;
                    break;
                }

                Err(DeserializationError::IO { source: e }) => {
                    return Err(SegmentFileError::from(e))
                }
            }
        }

        let position = write_file.stream_position()?;

        let mut read_file = open_file_for_read(fs, file_path)?;
        read_file.seek(SeekFrom::Start(position))?;

        Ok(Segment {
            base_offset,
            size: position,
            read_file,
            writer: Some(SegmentWriter {
                file: write_file,
                preallocator,
            }),
        })
    }

    fn open_passive(
        fs: &impl FileSystem<TFile>,
        file_path: &Path,
        base_offset: u64,
    ) -> Result<Segment<TFile, TPreallocator>, SegmentFileError> {
        let mut read_file = open_file_for_read(fs, file_path)?;
        let position = read_file
            .stream_position()
            .map_err(SegmentFileError::from)?;
        Ok(Segment {
            base_offset,
            size: position,
            read_file,
            writer: None,
        })
    }

    #[inline]
    fn is_active(&self) -> bool {
        self.writer.is_some()
    }

    fn write(&mut self, entry: &Entry) -> Result<usize, SegmentWriteError> {
        let writer = self.writer.as_mut().expect("segment is not active");
        writer.write(&entry)
    }
}

#[cfg(test)]
mod tests {
    mod test_segment {
        use crate::entry::Entry;
        use assert_matches::assert_matches;
        use rstest::rstest;
        use std::io::Seek;

        use crate::fs::real_file_system::RealFileSystem;
        use crate::preallocator::NormalPreallocator;
        use crate::segment::constants::{MAGIC_SIZE, VERSION_SIZE};
        use crate::segment::files::{create_file_for_read_write, SegmentFileError};
        use crate::segment::segment::Segment;
        use crate::segment::writer::SegmentWriter;

        #[rstest]
        #[case(true)]
        #[case(false)]
        fn open_existing(#[case] active: bool) {
            let base_offset = 999;
            let fs = RealFileSystem::new();

            let temp_dir = tempfile::tempdir().unwrap();
            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };

            let mut total_entries_size = 0_usize;
            {
                let file_path = temp_dir.path().join("00000000000000000999.log");
                let file =
                    create_file_for_read_write(&fs, &file_path, preallocator.clone()).unwrap();
                let mut writer = SegmentWriter {
                    file,
                    preallocator: preallocator.clone(),
                };

                let number_or_entries = 10;
                let entry_size = 4096_u64;
                for i in 0_u64..number_or_entries {
                    let buf = (0_u8..255)
                        .cycle()
                        .skip(i as usize)
                        .take(entry_size as usize)
                        .collect::<Vec<u8>>();
                    let entry = Entry::new(base_offset + i, buf);
                    total_entries_size += entry.serialized_size();
                    writer.write(&entry).unwrap();
                }
            }

            let mut segment = Segment::open(
                &fs,
                temp_dir.path(),
                base_offset,
                active,
                preallocator.clone(),
            )
            .unwrap();
            let after_header_position = (MAGIC_SIZE + VERSION_SIZE) as u64;
            let expected_size = after_header_position + total_entries_size as u64;
            assert_eq!(segment.base_offset, base_offset);
            assert_eq!(segment.size, expected_size);
            assert_eq!(
                segment.read_file.stream_position().unwrap(),
                after_header_position
            );
            if let Some(ref mut writer) = segment.writer {
                assert_eq!(writer.file.stream_position().unwrap(), expected_size);
            }
            assert_eq!(segment.is_active(), active);
            assert_eq!(segment.writer.is_some(), active);
        }

        #[test]
        #[should_panic(expected = "segment is not active")]
        fn passive_segments_cannot_write() {
            let base_offset = 999;
            let fs = RealFileSystem::new();

            let temp_dir = tempfile::tempdir().unwrap();
            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };

            {
                let file_path = temp_dir.path().join("00000000000000000999.log");
                create_file_for_read_write(&fs, &file_path, preallocator.clone()).unwrap();
            }

            let mut segment = Segment::open(
                &fs,
                temp_dir.path(),
                base_offset,
                false,
                preallocator.clone(),
            )
            .unwrap();

            let entry = Entry::new(base_offset, vec![0_u8, 1, 2, 3]);
            segment.write(&entry).unwrap();
        }

        #[test]
        fn open_passive_non_existent() {
            let fs = RealFileSystem::new();
            let temp_dir = tempfile::tempdir().unwrap();

            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };
            let error = Segment::open(&fs, temp_dir.path(), 999, false, preallocator).unwrap_err();
            assert_matches!(error, SegmentFileError::NotFound);
        }

        #[test]
        fn open_active_non_existent() {
            let base_offset = 999;
            let fs = RealFileSystem::new();

            let temp_dir = tempfile::tempdir().unwrap();
            let preallocator = NormalPreallocator {
                preallocate_size: 1024,
            };

            let mut segment = Segment::open(
                &fs,
                temp_dir.path(),
                base_offset,
                true,
                preallocator.clone(),
            )
            .unwrap();
            let expected_size = (MAGIC_SIZE + VERSION_SIZE) as u64;
            assert_eq!(segment.base_offset, base_offset);
            assert_eq!(segment.size, expected_size);
            assert!(segment.writer.is_some());
            assert_eq!(segment.read_file.stream_position().unwrap(), expected_size);
            assert_eq!(
                segment
                    .writer
                    .as_mut()
                    .unwrap()
                    .file
                    .stream_position()
                    .unwrap(),
                expected_size
            );
            assert!(segment.is_active());
        }
    }
}
