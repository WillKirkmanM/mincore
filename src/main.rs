use clap::{Parser, ValueEnum};
use std::{fs::File, io::Write, num::NonZeroU64, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    version,
    about = "Report which pages of a file are resident in memory",
    after_help = "Residency is a snapshot and may change immediately. Partially selected pages are counted as whole pages. Range offsets are page-aligned; range ends are exclusive and may extend beyond the selected bytes or file size."
)]
struct Cli {
    #[arg(help = "Regular file to inspect")]
    file: PathBuf,
    #[arg(long, default_value_t = 0, help = "Starting byte offset in the file")]
    offset: u64,
    #[arg(
        long,
        help = "Positive number of bytes to inspect (default: all remaining bytes)"
    )]
    length: Option<NonZeroU64>,
    #[arg(long, value_enum, default_value_t = Format::Text, help = "Output format")]
    format: Format,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, PartialEq)]
struct Range {
    offset: u64,
    length: u64,
    resident: bool,
}

fn selected_bytes(size: u64, offset: u64, length: Option<NonZeroU64>) -> Result<u64, String> {
    let remaining = size.checked_sub(offset).ok_or("offset exceeds file size")?;
    let length = length.map_or(remaining, NonZeroU64::get);
    if length > remaining {
        return Err("selected range exceeds file size".into());
    }
    Ok(length)
}

fn ranges(pages: &[u8], offset: u64, page_size: u64) -> Vec<Range> {
    let mut result: Vec<Range> = Vec::new();
    for (index, page) in pages.iter().enumerate() {
        let resident = page & 1 != 0;
        if let Some(last) = result.last_mut()
            && last.resident == resident
        {
            last.length += page_size;
            continue;
        }
        result.push(Range {
            offset: offset + index as u64 * page_size,
            length: page_size,
            resident,
        });
    }
    result
}

fn run(cli: Cli) -> Result<(), String> {
    let page_size = platform::page_size()?;
    let file = File::open(&cli.file).map_err(|error| format!("cannot open file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect file: {error}"))?;
    if !metadata.is_file() {
        return Err("path must refer to a regular file".into());
    }
    let length = selected_bytes(metadata.len(), cli.offset, cli.length)?;
    let aligned_offset = cli.offset / page_size * page_size;
    let pages = if length == 0 {
        Vec::new()
    } else {
        let mapping_length = length
            .checked_add(cli.offset - aligned_offset)
            .ok_or("mapping length is too large")?;
        platform::residency(&file, aligned_offset, mapping_length, page_size)?
    };
    let resident = pages.iter().filter(|page| **page & 1 != 0).count();
    let percentage = if pages.is_empty() {
        0.0
    } else {
        resident as f64 * 100.0 / pages.len() as f64
    };
    let ranges = ranges(&pages, aligned_offset, page_size);
    let mut output = String::new();
    use std::fmt::Write;
    match cli.format {
        Format::Text => {
            writeln!(output, "Page size: {page_size} bytes\nSelected bytes: {length} (offset {})\nResident pages: {resident}/{} ({percentage:.2}%)", cli.offset, pages.len()).unwrap();
            for range in ranges {
                writeln!(
                    output,
                    "{}..{}: {}",
                    range.offset,
                    range.offset + range.length,
                    if range.resident {
                        "resident"
                    } else {
                        "non-resident"
                    }
                )
                .unwrap();
            }
            output.push_str("Residency is a snapshot. Partially selected pages count as whole pages.\nRange ends are exclusive and page-aligned; they may extend beyond the selection or file.\n");
        }
        Format::Json => {
            write!(output, "{{\"page_size\":{page_size},\"selected_offset\":{},\"selected_bytes\":{length},\"resident_pages\":{resident},\"total_pages\":{},\"resident_percentage\":{percentage:.2},\"ranges\":[", cli.offset, pages.len()).unwrap();
            for (index, range) in ranges.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write!(
                    output,
                    "{{\"offset\":{},\"length\":{},\"resident\":{}}}",
                    range.offset, range.length, range.resident
                )
                .unwrap();
            }
            output.push_str("],\"note\":\"Residency is a snapshot. Partially selected pages count as whole pages. Range ends are exclusive and page-aligned; they may extend beyond the selection or file.\"}\n");
        }
    }
    std::io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(|error| format!("cannot write output: {error}"))
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        ffi::{c_int, c_void},
        fs::File,
        io,
        os::fd::AsRawFd,
    };

    unsafe extern "C" {
        fn getpagesize() -> c_int;
        fn mmap64(
            address: *mut c_void,
            length: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;
        fn mincore(address: *mut c_void, length: usize, vector: *mut u8) -> c_int;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
    }

    struct Mapping {
        address: *mut c_void,
        length: usize,
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            unsafe {
                munmap(self.address, self.length);
            }
        }
    }

    pub fn page_size() -> Result<u64, String> {
        let size = unsafe { getpagesize() };
        if size <= 0 {
            return Err("cannot determine system page size".into());
        }
        Ok(size as u64)
    }

    pub fn residency(
        file: &File,
        offset: u64,
        length: u64,
        page_size: u64,
    ) -> Result<Vec<u8>, String> {
        let count = usize::try_from(length.div_ceil(page_size))
            .map_err(|_| "too many pages for this platform")?;
        let length =
            usize::try_from(length).map_err(|_| "mapping length is too large for this platform")?;
        let offset =
            i64::try_from(offset).map_err(|_| "mapping offset is too large for this platform")?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(count)
            .map_err(|error| format!("cannot allocate residency vector: {error}"))?;
        pages.resize(count, 0);
        const PROT_NONE: c_int = 0;
        const MAP_PRIVATE: c_int = 2;
        let address = unsafe {
            mmap64(
                std::ptr::null_mut(),
                length,
                PROT_NONE,
                MAP_PRIVATE,
                file.as_raw_fd(),
                offset,
            )
        };
        if address as isize == -1 {
            return Err(format!("mmap failed: {}", io::Error::last_os_error()));
        }
        let mapping = Mapping { address, length };
        if unsafe { mincore(mapping.address, mapping.length, pages.as_mut_ptr()) } != 0 {
            return Err(format!("mincore failed: {}", io::Error::last_os_error()));
        }
        if unsafe { munmap(mapping.address, mapping.length) } != 0 {
            return Err(format!("munmap failed: {}", io::Error::last_os_error()));
        }
        std::mem::forget(mapping);
        Ok(pages)
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::fs::File;

    pub fn page_size() -> Result<u64, String> {
        Err("mincore is supported only on Linux".into())
    }

    pub fn residency(_: &File, _: u64, _: u64, _: u64) -> Result<Vec<u8>, String> {
        Err("mincore is supported only on Linux".into())
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_selection_without_overflow() {
        assert_eq!(selected_bytes(0, 0, None), Ok(0));
        assert_eq!(selected_bytes(10, 3, None), Ok(7));
        assert_eq!(selected_bytes(10, 10, None), Ok(0));
        assert!(selected_bytes(10, 11, None).is_err());
        assert!(selected_bytes(10, 9, NonZeroU64::new(2)).is_err());
        assert!(selected_bytes(u64::MAX, 1, NonZeroU64::new(u64::MAX)).is_err());
    }

    #[test]
    fn groups_pages_using_only_the_residency_bit() {
        assert_eq!(
            ranges(&[1, 3, 0, 2, 1], 4096, 4096),
            vec![
                Range {
                    offset: 4096,
                    length: 8192,
                    resident: true
                },
                Range {
                    offset: 12288,
                    length: 8192,
                    resident: false
                },
                Range {
                    offset: 20480,
                    length: 4096,
                    resident: true
                },
            ]
        );
        assert!(ranges(&[], 0, 4096).is_empty());
    }

    #[test]
    fn rejects_zero_and_malformed_lengths() {
        for length in ["0", "-1", "abc", "18446744073709551616"] {
            assert!(Cli::try_parse_from(["mincore", "--length", length, "file"]).is_err());
        }
        assert!(
            Cli::try_parse_from(["mincore", "--length", "4", "--format", "json", "file"]).is_ok()
        );
    }
}
