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

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub dir: PathBuf,
    pub max_segment_size: u64,
    pub preallocate_size: u64,
}

impl LogConfig {
    const MAX_SEGMENT_SIZE_DEFAULT: u64 = 128 * 1024 * 1024;
    const PREALLOCATE_SIZE_DEFAULT: u64 = 32 * 1024 * 1024;

    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
            max_segment_size: LogConfig::MAX_SEGMENT_SIZE_DEFAULT,
            preallocate_size: LogConfig::PREALLOCATE_SIZE_DEFAULT,
        }
    }

    pub fn max_segment_size(mut self, value: u64) -> Self {
        self.max_segment_size = value;
        self
    }

    pub fn preallocate_size(mut self, value: u64) -> Self {
        self.preallocate_size = value;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::config::LogConfig;
    use std::path::Path;

    #[test]
    fn creation() {
        let config = LogConfig::new(Path::new("./"))
            .preallocate_size(123)
            .max_segment_size(456);
        assert_eq!(config.preallocate_size, 123);
        assert_eq!(config.max_segment_size, 456);
    }
}
