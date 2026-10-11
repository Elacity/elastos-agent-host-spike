//! One host memory observation for Runtime model admission and execution.
use std::io::{self, Read as _};
use std::path::Path;

const MAX_OBSERVATION_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMemory {
    /// Effective physical/cgroup capacity, rather than currently free memory.
    pub total: u64,
    pub available: u64,
    pub pressure_normal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelMemoryFit {
    Fits,
    Insufficient,
    Unavailable,
}

/// A signed minimum is an admission requirement; it does not promise that a
/// later reply's weights, KV cache and working memory fit the current free RAM.
pub fn model_memory_fit(minimum_memory_mb: u32, memory: Option<HostMemory>) -> ModelMemoryFit {
    if minimum_memory_mb == 0 {
        return ModelMemoryFit::Unavailable;
    }
    match memory {
        Some(memory) if memory.available <= memory.total => {
            if u64::from(minimum_memory_mb) * 1024 * 1024 <= memory.total {
                ModelMemoryFit::Fits
            } else {
                ModelMemoryFit::Insufficient
            }
        }
        _ => ModelMemoryFit::Unavailable,
    }
}

pub fn observe_host_memory(platform: &str) -> io::Result<HostMemory> {
    observe_host_memory_with_reader(platform, read_observation)
}

fn read_observation(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_OBSERVATION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OBSERVATION_BYTES {
        return Err(io::Error::other(
            "host memory observation exceeds its limit",
        ));
    }
    String::from_utf8(bytes).map_err(|_| io::Error::other("invalid host memory observation"))
}

/// Explicit platform and reader keep Linux observations testable on any host.
/// macOS uses its native host statistics; unsupported platforms refuse.
pub fn observe_host_memory_with_reader(
    platform: &str,
    read: impl Fn(&Path) -> io::Result<String>,
) -> io::Result<HostMemory> {
    match platform {
        "linux" => {
            let host = parse_meminfo(&read(Path::new("/proc/meminfo"))?)?;
            // Preserve the current v1/missing-file behavior. The v2 observer
            // applies every observed finite ancestor to capacity and headroom.
            Ok(match read(Path::new("/proc/self/cgroup")) {
                Ok(groups) => cgroup_memory(&groups, Path::new("/sys/fs/cgroup"), host, |path| {
                    read(path).ok()
                }),
                Err(_) => host,
            })
        }
        "macos" => {
            #[cfg(target_os = "macos")]
            {
                macos_host_memory()
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(io::Error::other(
                    "macOS memory observation is unavailable on this host",
                ))
            }
        }
        _ => Err(io::Error::other("host memory observation is unsupported")),
    }
}

fn parse_meminfo(text: &str) -> io::Result<HostMemory> {
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|kib| kib.checked_mul(1024))
            .ok_or_else(|| io::Error::other("invalid host memory observation"))
    };
    let total = field("MemTotal:")?;
    let available = field("MemAvailable:")?;
    if total == 0 || available > total {
        return Err(io::Error::other("invalid host memory observation"));
    }
    Ok(HostMemory {
        total,
        available,
        pressure_normal: false,
    })
}

fn cgroup_memory(
    groups: &str,
    root: &Path,
    mut memory: HostMemory,
    read: impl Fn(&Path) -> Option<String>,
) -> HostMemory {
    let Some(group) = groups.lines().find_map(|line| line.strip_prefix("0::")) else {
        return memory;
    };
    let mut path = root.to_path_buf();
    for part in Path::new(group).components() {
        if let std::path::Component::Normal(name) = part {
            path.push(name);
        }
    }
    while path.starts_with(root) {
        let number = |file: &str| read(&path.join(file))?.trim().parse::<u64>().ok();
        if let (Some(limit), Some(current)) = (number("memory.max"), number("memory.current")) {
            let cache = read(&path.join("memory.stat")).map_or(0, |stat| file_cache(&stat));
            memory.total = memory.total.min(limit);
            memory.available = memory
                .available
                .min(limit.saturating_sub(current.saturating_sub(cache)));
        }
        if path == root || !path.pop() {
            break;
        }
    }
    memory
}

/// File LRU pages are reclaimable; dirty/writeback pages and tmpfs stay used.
fn file_cache(stat: &str) -> u64 {
    let field = |name: &str| {
        stat.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    field("active_file")
        .saturating_add(field("inactive_file"))
        .saturating_sub(field("file_dirty").saturating_add(field("file_writeback")))
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn macos_host_memory() -> io::Result<HostMemory> {
    let fail = || io::Error::other("host memory observation unavailable");
    let mut total = 0_u64;
    let mut len = std::mem::size_of_val(&total);
    let mut stats = std::mem::MaybeUninit::<libc::vm_statistics64>::zeroed();
    let mut count = libc::HOST_VM_INFO64_COUNT;
    // SAFETY: host_statistics64 writes at most `count` words into `stats`;
    // the host port is released below.
    let host = unsafe { libc::mach_host_self() };
    let result = unsafe {
        libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            stats.as_mut_ptr().cast(),
            &mut count,
        )
    };
    unsafe extern "C" {
        fn mach_port_deallocate(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
        ) -> libc::kern_return_t;
    }
    // SAFETY: `host` is a send right owned by this call.
    unsafe {
        mach_port_deallocate(libc::mach_task_self(), host);
    }
    // SAFETY: hw.memsize is a u64 and `len` is its size.
    let sysctl = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            (&mut total as *mut u64).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if result != 0 || sysctl != 0 || page <= 0 || total == 0 {
        return Err(fail());
    }
    // SAFETY: host_statistics64 succeeded.
    let stats = unsafe { stats.assume_init() };
    let available = macos_available(
        u64::from(stats.free_count),
        u64::from(stats.speculative_count),
        u64::from(stats.purgeable_count),
        u64::from(stats.external_page_count),
        page as u64,
    )
    .ok_or_else(fail)?;
    // kern.memorystatus_vm_pressure_level: 1 normal, 2 warning, 4 critical.
    // Unreadable counts as not normal.
    let mut level: libc::c_int = 0;
    let mut level_len = std::mem::size_of_val(&level);
    // SAFETY: the sysctl is an int and `level_len` is its size.
    let pressure = unsafe {
        libc::sysctlbyname(
            c"kern.memorystatus_vm_pressure_level".as_ptr(),
            (&mut level as *mut libc::c_int).cast(),
            &mut level_len,
            std::ptr::null_mut(),
            0,
        )
    };
    Ok(HostMemory {
        total,
        available: available.min(total),
        pressure_normal: pressure == 0 && level == 1,
    })
}

/// Pages macOS can hand out without compressing or swapping: free pages
/// (whose count includes speculative read-ahead), purgeable pages, and
/// file-backed pages (speculative pages are file-backed, so counted once).
/// Inactive anonymous memory is excluded: reclaiming it needs the compressor.
#[cfg(any(target_os = "macos", test))]
fn macos_available(
    free: u64,
    speculative: u64,
    purgeable: u64,
    file_backed: u64,
    page: u64,
) -> Option<u64> {
    free.saturating_sub(speculative)
        .checked_add(purgeable)?
        .checked_add(file_backed)?
        .checked_mul(page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    fn read_fixture(files: &BTreeMap<String, String>, path: &Path) -> io::Result<String> {
        files
            .get(path.to_str().unwrap())
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
    fn files() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "/proc/meminfo".into(),
                format!(
                    "MemTotal: {} kB\nMemFree: 1 kB\nMemAvailable: {} kB\n",
                    8 * GIB / 1024,
                    6 * GIB / 1024
                ),
            ),
            (
                "/proc/self/cgroup".into(),
                "0::/system.slice/home.service\n".into(),
            ),
        ])
    }
    #[test]
    fn meminfo_reports_mem_available_not_mem_free() {
        let host =
            parse_meminfo("MemTotal: 8000000 kB\nMemFree: 100000 kB\nMemAvailable: 3000000 kB\n")
                .unwrap();
        assert_eq!(
            host,
            HostMemory {
                total: 8_000_000 * 1024,
                available: 3_000_000 * 1024,
                pressure_normal: false
            }
        );
        for text in [
            "MemTotal: 8000000 kB\n",
            "MemTotal: 0 kB\nMemAvailable: 0 kB\n",
            "MemTotal: 1 kB\nMemAvailable: 2 kB\n",
        ] {
            assert!(parse_meminfo(text).is_err());
        }
    }
    #[test]
    fn cgroup_v2_ancestor_limit_lowers_available() {
        let mut files = files();
        assert_eq!(
            observe_host_memory_with_reader("linux", |p| read_fixture(&files, p))
                .unwrap()
                .available,
            6 * GIB
        );
        files.insert(
            "/sys/fs/cgroup/system.slice/home.service/memory.max".into(),
            "max\n".into(),
        );
        files.insert(
            "/sys/fs/cgroup/system.slice/home.service/memory.current".into(),
            "100\n".into(),
        );
        files.insert(
            "/sys/fs/cgroup/system.slice/memory.max".into(),
            (2 * GIB).to_string(),
        );
        files.insert(
            "/sys/fs/cgroup/system.slice/memory.current".into(),
            (3 * GIB / 2).to_string(),
        );
        let host = observe_host_memory_with_reader("linux", |p| read_fixture(&files, p)).unwrap();
        assert_eq!(host.total, 2 * GIB);
        assert_eq!(host.available, GIB / 2);
        files.insert(
            "/proc/meminfo".into(),
            format!(
                "MemTotal: {} kB\nMemAvailable: {} kB\n",
                8 * GIB / 1024,
                MIB / 1024
            ),
        );
        assert_eq!(
            observe_host_memory_with_reader("linux", |p| read_fixture(&files, p))
                .unwrap()
                .available,
            MIB
        );
        files.insert(
            "/proc/meminfo".into(),
            format!(
                "MemTotal: {} kB\nMemAvailable: {} kB\n",
                8 * GIB / 1024,
                6 * GIB / 1024
            ),
        );
        assert_eq!(model_memory_fit(2048, Some(host)), ModelMemoryFit::Fits);
        assert_eq!(
            model_memory_fit(2049, Some(host)),
            ModelMemoryFit::Insufficient
        );
        files.insert("/proc/self/cgroup".into(), "4:memory:/home\n".into());
        assert_eq!(
            observe_host_memory_with_reader("linux", |p| read_fixture(&files, p))
                .unwrap()
                .available,
            6 * GIB
        );
    }
    #[test]
    fn cgroup_v2_page_cache_is_not_counted_as_used() {
        let mut files = files();
        files.insert(
            "/sys/fs/cgroup/system.slice/memory.max".into(),
            (7680 * MIB).to_string(),
        );
        files.insert(
            "/sys/fs/cgroup/system.slice/memory.current".into(),
            (3395 * MIB).to_string(),
        );
        let observe = |files: &BTreeMap<String, String>| {
            observe_host_memory_with_reader("linux", |p| read_fixture(files, p))
                .unwrap()
                .available
        };
        assert_eq!(observe(&files), 4285 * MIB);
        // The file counter includes tmpfs; only the two file LRUs are credited.
        let stat = format!(
            "active_file {}\ninactive_file {}\nfile {}\nshmem {}\n",
            1953 * MIB,
            1321 * MIB,
            3338 * MIB,
            64 * MIB
        );
        files.insert(
            "/sys/fs/cgroup/system.slice/memory.stat".into(),
            stat.clone(),
        );
        assert_eq!(observe(&files), 6 * GIB);
        files.insert(
            "/proc/meminfo".into(),
            format!(
                "MemTotal: {} kB\nMemAvailable: {} kB\n",
                8 * GIB / 1024,
                8 * GIB / 1024
            ),
        );
        assert_eq!(observe(&files), (7680 - 121) * MIB);
        files.insert(
            "/sys/fs/cgroup/system.slice/memory.stat".into(),
            format!(
                "{stat}file_dirty {}\nfile_writeback {}\n",
                200 * MIB,
                56 * MIB
            ),
        );
        assert_eq!(observe(&files), (7680 - 377) * MIB);
        files.insert(
            "/sys/fs/cgroup/system.slice/memory.stat".into(),
            format!("{stat}file_dirty {}\n", 4000 * MIB),
        );
        assert_eq!(observe(&files), 4285 * MIB);
    }
    #[test]
    fn macos_estimate_excludes_inactive_anonymous_pages() {
        assert_eq!(macos_available(100, 20, 5, 300, 16384), Some(385 * 16384));
        assert_eq!(macos_available(10, 20, 0, 0, 16384), Some(0));
    }
    #[test]
    fn live_host_memory_is_readable() {
        // Fixed OS input covers the observation without depending on the test host.
        let files = files();
        let host = observe_host_memory_with_reader("linux", |p| read_fixture(&files, p)).unwrap();
        assert!(host.total > 0 && host.available <= host.total);
        assert!(observe_host_memory_with_reader("unsupported", |_| panic!(
            "unsupported platform reads no files"
        ))
        .is_err());
        assert!(
            observe_host_memory_with_reader("linux", |_| Err(io::Error::from(
                io::ErrorKind::PermissionDenied
            )))
            .is_err()
        );
    }
    #[test]
    fn signed_minimum_checks_capacity_without_promising_free_memory() {
        let host = HostMemory {
            total: 4 * GIB,
            available: 0,
            pressure_normal: false,
        };
        assert_eq!(model_memory_fit(0, Some(host)), ModelMemoryFit::Unavailable);
        assert_eq!(model_memory_fit(4096, Some(host)), ModelMemoryFit::Fits);
        assert_eq!(
            model_memory_fit(4097, Some(host)),
            ModelMemoryFit::Insufficient
        );
        assert_eq!(model_memory_fit(512, None), ModelMemoryFit::Unavailable);
        assert_eq!(
            model_memory_fit(
                512,
                Some(HostMemory {
                    total: 0,
                    available: 0,
                    pressure_normal: false
                })
            ),
            ModelMemoryFit::Insufficient
        );
    }
}
