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

use std::fs;
use std::path::Path;
use crate::utils::get_base_offset_from_segment_log_file_name;

fn list_log_segments(dir: &Path) -> Vec<u64> {
    let mut result: Vec<u64> = fs::read_dir(dir).unwrap()
        .map(|e| get_base_offset_from_segment_log_file_name(e.unwrap().file_name()))
        .flatten()
        .collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use crate::log::list_log_segments;

    #[test]
    fn test_list_log_segments() {
        let tmp_dir = tempfile::tempdir().unwrap();
        File::create(tmp_dir.path().join("aaa.bbb")).unwrap();
        File::create(tmp_dir.path().join("00000000000000000000.log")).unwrap();
        File::create(tmp_dir.path().join("00000000000000010000.log")).unwrap();
        File::create(tmp_dir.path().join("00000000000000050708.log")).unwrap();
        File::create(tmp_dir.path().join("00000000000010067880.log")).unwrap();
        File::create(tmp_dir.path().join("00000000000099999999.xxx")).unwrap();
        assert_eq!(list_log_segments(tmp_dir.path()), vec![0, 10000, 50708, 10067880]);
    }
}
