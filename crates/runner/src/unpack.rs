//! Safe extraction of uploaded project archives.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

pub struct Limits {
    pub max_files: usize,
    pub max_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Unpacked {
    pub file_count: usize,
    pub total_bytes: u64,
}

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;

/// Extracts `archive` into `dest`, which must be empty.
///
/// Rejects entries that would land outside `dest` (`../`, absolute paths),
/// skips symlinks, writes files without execute bits, and stops as soon as
/// the file count or total unpacked size goes over the limits, so zip bombs
/// can't fill the disk.
pub fn unpack(archive: &Path, dest: &Path, limits: &Limits) -> Result<Unpacked, String> {
    let file = File::open(archive).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("Not a valid zip file: {e}"))?;
    if zip.len() > limits.max_files.saturating_mul(2) {
        return Err(format!(
            "Too many entries (limit {} files)",
            limits.max_files
        ));
    }
    let mut out = Unpacked {
        file_count: 0,
        total_bytes: 0,
    };
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| format!("Corrupt zip entry: {e}"))?;
        let Some(rel) = entry.enclosed_name() else {
            return Err(format!("Unsafe path in archive: {}", entry.name()));
        };
        if entry.unix_mode().is_some_and(|m| m & S_IFMT == S_IFLNK) {
            continue;
        }
        let path = dest.join(&rel);
        if entry.is_dir() {
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            continue;
        }
        out.file_count += 1;
        if out.file_count > limits.max_files {
            return Err(format!("Too many files (limit {})", limits.max_files));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file =
            File::create_new(&path).map_err(|e| format!("Cannot write {}: {e}", rel.display()))?;
        let remaining = limits.max_bytes - out.total_bytes;
        let written = io::copy(&mut (&mut entry).take(remaining + 1), &mut file)
            .map_err(|e| format!("Cannot extract {}: {e}", rel.display()))?;
        out.total_bytes += written;
        if out.total_bytes > limits.max_bytes {
            return Err(format!(
                "Unpacked size is over the limit of {} MB",
                limits.max_bytes / 1024 / 1024
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_zip(dir: &Path, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
        let path = dir.join("upload.zip");
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        for (name, data) in entries {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
        path
    }

    fn limits() -> Limits {
        Limits {
            max_files: 10,
            max_bytes: 1024,
        }
    }

    #[test]
    fn extracts_normal_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let zip = make_zip(tmp.path(), &[("a/b.txt", b"hello"), ("c.txt", b"hi")]);
        let dest = tmp.path().join("src");
        fs::create_dir(&dest).unwrap();
        let res = unpack(&zip, &dest, &limits()).unwrap();
        assert_eq!(
            res,
            Unpacked {
                file_count: 2,
                total_bytes: 7
            }
        );
        assert_eq!(fs::read_to_string(dest.join("a/b.txt")).unwrap(), "hello");
    }

    #[test]
    fn rejects_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let zip = make_zip(tmp.path(), &[("../evil.txt", b"x")]);
        let dest = tmp.path().join("src");
        fs::create_dir(&dest).unwrap();
        assert!(unpack(&zip, &dest, &limits())
            .unwrap_err()
            .contains("Unsafe path"));
        assert!(!tmp.path().join("evil.txt").exists());
    }

    #[test]
    fn stops_at_size_and_file_limits() {
        let tmp = tempfile::tempdir().unwrap();
        let big = vec![b'a'; 2048];
        let zip = make_zip(tmp.path(), &[("big.bin", &big)]);
        let dest = tmp.path().join("src");
        fs::create_dir(&dest).unwrap();
        assert!(unpack(&zip, &dest, &limits())
            .unwrap_err()
            .contains("over the limit"));

        let names: Vec<String> = (0..11).map(|i| format!("f{i}")).collect();
        let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let zip = make_zip(tmp.path(), &entries);
        let dest = tmp.path().join("src2");
        fs::create_dir(&dest).unwrap();
        assert!(unpack(&zip, &dest, &limits())
            .unwrap_err()
            .contains("Too many files"));
    }
}
