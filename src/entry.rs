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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crc32fast::Hasher;
use std::io::{Cursor, Read, Write};
use std::mem::size_of;
use thiserror::Error;

#[derive(Debug, PartialEq)]
pub(crate) struct Entry {
    pub(crate) offset: u64,
    pub(crate) payload: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum DeserializationError {
    #[error("entry deserialization error: IO error")]
    IO {
        #[from]
        source: std::io::Error,
    },

    #[error("entry deserialization error: checksum, magic, or size is invalid")]
    Validation,
}

impl Entry {
    const MAGIC_SIZE: usize = size_of::<u8>() * 4;
    const MAGIC: [u8; 4] = [69, 78, 84, 82]; // ENTR

    pub(crate) fn new(offset: u64, payload: Vec<u8>) -> Entry {
        // TODO guard against too big payloads
        Entry {
            offset,
            payload: payload,
        }
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        // TODO zigzag encoding

        let mut cur = Cursor::new(Vec::with_capacity(self.serialized_size()));

        // It's safe to unwrap writes in this method,
        // because everything is in memory and no interruption is possible.

        // CRC32 and size -- will write the actual values later.
        let crc_pos = cur.position();
        cur.write_u32::<BigEndian>(0).unwrap();
        let size_pos = cur.position();
        cur.write_u32::<BigEndian>(0).unwrap();

        let payload_pos = cur.position();
        // Payload
        cur.write_all(&self.payload).unwrap();

        // Magic
        cur.write_all(&Entry::MAGIC).unwrap();

        // Size - the actual value.
        cur.set_position(size_pos);
        // Include everything apart from the CRC32 and the size itself.
        let size: u32 = cur.get_ref()[(payload_pos as usize)..].len() as u32;
        cur.write_u32::<BigEndian>(size).unwrap();

        // CRC32 - the actual value.
        // Include everything apart from the CRC32 itself.
        let crc32 = crc32fast::hash(&cur.get_ref()[(size_pos as usize)..]);
        cur.set_position(crc_pos);
        cur.write_u32::<BigEndian>(crc32).unwrap();

        cur.into_inner()
    }

    pub(crate) fn serialized_size(&self) -> usize {
        // CRC and payload size
        size_of::<u32>() * 2
            // payload
            + self.payload.len()
            // magic
            + Entry::MAGIC_SIZE
    }

    pub(crate) fn deserialize(
        offset: u64,
        input: &mut impl Read,
    ) -> Result<Entry, DeserializationError> {
        let mut crc32_hasher = Hasher::new();

        // We do only two reads here.

        let (crc32, size) = {
            let mut crc32_and_size_vec = vec![0_u8; size_of::<u32>() * 2];
            input
                .read_exact(&mut crc32_and_size_vec)
                .map_err(DeserializationError::from)?;
            let size_slice = &crc32_and_size_vec[size_of::<u32>()..size_of::<u32>() * 2];
            crc32_hasher.update(size_slice);
            let mut crc32_and_size_cur = Cursor::new(crc32_and_size_vec);
            (
                Entry::read_u32(&mut crc32_and_size_cur)?,
                Entry::read_u32(&mut crc32_and_size_cur)?,
            )
        };

        // Even with 0-byte payload, the size with magic can't be less than the magic size.
        if size < Self::MAGIC_SIZE as u32 {
            return Err(DeserializationError::Validation);
        }

        let mut payload_and_magic = vec![0_u8; size as usize];
        input
            .read_exact(&mut payload_and_magic)
            .map_err(DeserializationError::from)?;

        if payload_and_magic[payload_and_magic.len() - Entry::MAGIC_SIZE..] != Entry::MAGIC {
            return Err(DeserializationError::Validation);
        }

        crc32_hasher.update(&payload_and_magic);
        if crc32_hasher.finalize() != crc32 {
            return Err(DeserializationError::Validation);
        }

        Ok(Entry {
            offset,
            payload: payload_and_magic[..payload_and_magic.len() - Entry::MAGIC_SIZE].to_vec(),
        })
    }

    fn read_u32(data: &mut impl Read) -> Result<u32, DeserializationError> {
        data.read_u32::<BigEndian>()
            .map_err(DeserializationError::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::{DeserializationError, Entry};
    use assert_matches::assert_matches;
    use byteorder::{BigEndian, WriteBytesExt};
    use rstest::rstest;
    use std::error::Error;
    use std::io::{Cursor, ErrorKind, Read, Seek, SeekFrom};

    #[rstest]
    fn ser_de(
        #[values(
        vec![],
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        vec![1; 1024 * 1024]
        )]
        payload: Vec<u8>,
        #[values(0, 1, u64::MAX)] offset: u64,
    ) {
        let entry = Entry::new(offset, payload);
        let serialized = entry.serialize();
        // Check that magic is written.
        assert_eq!(serialized[serialized.len() - 4..], vec![69, 78, 84, 82]);

        let mut cursor = Cursor::new(serialized.as_slice());
        let entry2 = Entry::deserialize(offset, &mut cursor).unwrap();
        assert_eq!(entry, entry2);
    }

    #[test]
    fn broken_crc() {
        let payload: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let entry = Entry::new(0, payload);

        let mut serialized = entry.serialize();
        serialized[0] += 1;

        let mut cursor = Cursor::new(serialized.as_slice());
        let result = Entry::deserialize(0, &mut cursor);
        assert_matches!(result, Err(DeserializationError::Validation));
    }

    #[test]
    fn broken_magic() {
        let payload: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let entry = Entry::new(0, payload);

        let mut serialized = entry.serialize();
        let idx = serialized.len() - 2;
        serialized[idx] += 1;

        let mut cursor = Cursor::new(serialized.as_slice());
        let result = Entry::deserialize(0, &mut cursor);
        assert_matches!(result, Err(DeserializationError::Validation));
    }

    #[test]
    fn smaller_size() {
        let payload: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let entry = Entry::new(0, payload);

        let mut serialized = entry.serialize();
        serialized[7] -= 1;

        let mut cursor = Cursor::new(serialized.as_slice());
        let result = Entry::deserialize(0, &mut cursor);
        assert_matches!(result, Err(DeserializationError::Validation));
    }

    #[test]
    fn bigger_size_nothing_after() {
        let payload: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let entry = Entry::new(0, payload);

        let mut serialized = entry.serialize();
        serialized[7] += 1;

        let mut cursor = Cursor::new(serialized.as_slice());
        let result = Entry::deserialize(0, &mut cursor);
        assert_matches!(result, Err(DeserializationError::IO { source: _ }));
    }

    #[test]
    fn bigger_size_something_after() {
        let payload: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let entry = Entry::new(0, payload);

        let mut serialized = entry.serialize();
        serialized[7] += 1;
        serialized.push(1);
        serialized.push(2);
        serialized.push(3);

        let mut cursor = Cursor::new(serialized.as_slice());
        let result = Entry::deserialize(0, &mut cursor);
        assert_matches!(result, Err(DeserializationError::Validation));
    }

    #[test]
    fn test_read_from_many_zeros() {
        // This is a realistic scenario of reading from a padded file.
        let buf = vec![0_u8; 1024];
        let mut cursor = Cursor::new(buf);
        let result = Entry::deserialize(0, &mut cursor);
        assert_matches!(result, Err(DeserializationError::Validation));
    }

    #[test]
    fn test_size_less_than_magic() {
        // This is a realistic scenario of reading from a padded file.
        let buf = vec![0_u8; 1024];
        let mut cursor = Cursor::new(buf);
        cursor.write_u32::<BigEndian>(0).unwrap(); // crc32, we don't care about the value.
        cursor
            .write_u32::<BigEndian>((Entry::MAGIC_SIZE - 1) as u32)
            .unwrap();
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let result = Entry::deserialize(0, &mut cursor);
        assert_matches!(result, Err(DeserializationError::Validation));
    }

    // TODO replace with mock??
    struct FaultyRead {
        inner: Cursor<Vec<u8>>,
        fail_at_pos: u64,
        error_kind: std::io::ErrorKind,
    }

    impl Read for FaultyRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let inner_result = self.inner.read(buf);
            if self.inner.position() >= self.fail_at_pos {
                Err(std::io::Error::from(self.error_kind))
            } else {
                inner_result
            }
        }
    }

    #[rstest]
    fn faulty_input(
        #[values(0, 1, 3, 10, 22)] fail_at_pos: u64,
        #[values(ErrorKind::UnexpectedEof, ErrorKind::Other)] error_kind: ErrorKind,
    ) {
        let entry = Entry::new(0, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let serialized = entry.serialize();
        let mut faulty_read = FaultyRead {
            inner: Cursor::new(serialized),
            fail_at_pos,
            error_kind,
        };
        let result = Entry::deserialize(0, &mut faulty_read);
        assert_matches!(result, Err(DeserializationError::IO { .. }));
        let deser_error = result.unwrap_err();
        let io_error = deser_error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(io_error.kind(), error_kind);
    }

    #[test]
    fn test_serialized_size() {
        let buf = vec![1_u8; 1024 * 1024];
        let entry = Entry::new(0, buf);
        let serialized = entry.serialize();
        assert_eq!(serialized.len(), entry.serialized_size());
        assert_eq!(serialized.len(), 4 + 4 + 1024 * 1024 + Entry::MAGIC_SIZE);
    }
}
