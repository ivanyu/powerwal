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

use lazy_static::lazy_static;
use regex::Regex;
use std::ffi::OsString;
use std::str::FromStr;

lazy_static! {
    static ref LOG_FILE_NAME_RE: Regex = Regex::new(r"^(\d{20})\.log$").unwrap();
}

pub(crate) fn log_file_name(base_offset: u64) -> String {
    return format!("{:0>20}.log", base_offset);
}

pub(crate) fn get_base_offset_from_segment_log_file_name(file_name: OsString) -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use crate::utils::{get_base_offset_from_segment_log_file_name, log_file_name};
    use rstest::rstest;
    use std::ffi::OsString;

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
    #[case("99999999999999999999.log", None)] // too big
    fn test_get_base_offset_from_segment_log_file_name(
        #[case] input: OsString,
        #[case] expected: Option<u64>,
    ) {
        assert_eq!(get_base_offset_from_segment_log_file_name(input), expected);
    }
}
