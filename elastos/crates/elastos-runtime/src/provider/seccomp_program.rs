//! B3 provider filter programs, rendered without a kernel dependency.
use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;
use super::seccomp_list::{linux_seccomp_list, AuditArch};

type Instruction = [u32; 4]; // classic BPF: code, true jump, false jump, operand
const DENY: u32 = 0x0005_000d; // SECCOMP_RET_ERRNO | EACCES
const ALLOW: u32 = 0x7fff_0000;
const NUMBERS: &str = concat!(
    "arch_prctl:158:- close:3:57 epoll_create1:291:20 epoll_ctl:233:21 epoll_pwait:281:22 epoll_wait:232:- ",
    "eventfd2:290:19 execve:59:221 execveat:322:281 exit:60:93 exit_group:231:94 faccessat:269:48 ",
    "fchmod:91:52 fcntl:72:25 fdatasync:75:83 flock:73:32 fstat:5:80 fsync:74:82 ",
    "ftruncate:77:46 futex:202:98 getdents64:217:61 geteuid:107:175 getrandom:318:278 linkat:265:37 ",
    "lseek:8:62 mkdir:83:- mkdirat:258:34 mmap:9:222 mprotect:10:226 munmap:11:215 ",
    "newfstatat:262:79 openat:257:56 openat2:437:437 poll:7:- ppoll:271:73 pread64:17:67 ",
    "prlimit64:302:261 pwrite64:18:68 read:0:63 readlinkat:267:78 readv:19:65 rename:82:- ",
    "renameat:-:38 renameat2:316:276 rmdir:84:- rseq:334:293 rt_sigaction:13:134 socketpair:53:199 statx:332:291 ",
    "sysinfo:99:179 uname:63:160 unlink:87:- unlinkat:263:35 write:1:64 writev:20:66 ",
    "clone:56:220 clone3:435:435 ",
    // Linux probe rows. The measured x86-only dup2, getpgrp, and readlink
    // have no AArch64 syscall or libc::SYS_* constant; '-' excludes each there.
    "accept4:288:242 bind:49:200 connect:42:203 dup2:33:- getpgrp:111:- getpid:39:172 getsockopt:55:209 kill:62:129 listen:50:201 pipe2:293:59 readlink:89:- recvfrom:45:207 rt_sigprocmask:14:135 sendto:44:206 setpgid:109:154 socket:41:198 waitid:247:95 ",
    // Chain network stack. `sendmmsg` is glibc DNS; `setsockopt` is argument-checked.
    // `open`, `stat`, and `lstat` are the x86_64 musl 1.2.5 forms of `openat`,
    // `statx`, and `newfstatat`. aarch64 musl has none of those three.
    // `recvmsg` is musl 1.2.5 `res_msend` (UDP and its TCP fallback, flags 0).
    "sendmmsg:307:269 setsockopt:54:208 open:2:- stat:4:- lstat:6:- recvmsg:47:212",
);

// An absent cell excludes that call by policy on this architecture. An absent
// row is not admitted: the caller drops it, and the filter's default is deny.
pub(super) fn number(name: &str, arch: AuditArch) -> Option<u32> {
    let row = NUMBERS
        .split_whitespace()
        .find(|row| row.split(':').next() == Some(name))?;
    let cell = row
        .split(':')
        .nth(match arch {
            AuditArch::X86_64 => 1,
            AuditArch::Aarch64 => 2,
        })
        .unwrap();
    (cell != "-").then(|| cell.parse().expect("invalid syscall number"))
}

fn stmt(code: u32, k: u32) -> Instruction {
    [code, 0, 0, k]
}
fn jump(code: u32, k: u32, jt: u32, jf: u32) -> Instruction {
    [code, jt, jf, k]
}

// The model's measured argument rules, packed as code:jt:jf:k. Seven syscall
// operands are filled from NUMBERS below. The suffix is the measured program:
// clone tests CLONE_THREAD and then the exact measured vfork flags, fcntl admits F_GETFD,
// F_DUPFD_CLOEXEC, F_GETFL and F_SETFL, and socket admits AF_UNIX only.
const MODEL_RULES: &str = concat!(
    "0015000100000000 0006000000050026 0015000600000000 0020000000000010 0045000100010000 000600007fff0000 ",
    "0015000100004111 000600007fff0000 000600000005000d 0015000400000000 0020000000000010 0015000100000001 ",
    "000600007fff0000 000600000005000d 0015000700000000 0020000000000018 0015030000000001 0015020000000406 ",
    "0015010000000003 0015000100000004 000600007fff0000 000600000005000d 0015000a00000000 0020000000000010 ",
    "0015000700000000 0020000000000014 0015000500000000 0020000000000020 0015000300000000 0020000000000024 ",
    "0015000100000000 000600007fff0000 000600000005000d 0015000800000000 0020000000000018 00540000fffffe7f ",
    "0015030000000000 0015020000000001 0015010000000009 001500010000000a 000600007fff0000 000600000005000d ",
    "0015000400000000 0020000000000010 0015000100000001 000600007fff0000 000600000005000d 000600000005000d",
);

#[allow(dead_code)] // The installer is a later B3 slice.
#[rustfmt::skip]
pub(super) fn program(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    arch: AuditArch,
) -> Vec<Instruction> {
    let audit: u32 = match arch { AuditArch::X86_64 => 0xc000_003e, AuditArch::Aarch64 => 0xc000_00b7 };
    let mut code = vec![
        stmt(0x20, 4), jump(0x15, audit, 1, 0), stmt(6, DENY),
        stmt(0x20, 0), jump(0x35, 0x4000_0000, 0, 1), stmt(6, DENY),
    ];
    for name in linux_seccomp_list(provider, admitted, arch) {
        let nr = number(name, arch).expect("listed syscall needs an architecture number");
        code.extend([jump(0x15, nr, 0, 1), stmt(6, ALLOW)]);
    }
    // Localhost, object, and chain already allow `openat`. x86_64 musl issues
    // `open` for the same calls. Did, wallet, and model do not get this row.
    if matches!(
        provider,
        RuntimeProviderId::Localhost | RuntimeProviderId::Object | RuntimeProviderId::Chain
    ) {
        code.extend(musl_open_rule(arch));
    }
    if matches!(provider, RuntimeProviderId::Model) {
        code.extend(measured_argument_rules(arch));
    } else if matches!(provider, RuntimeProviderId::Chain) {
        code.extend(chain_argument_rules(arch));
    } else {
        // Object only. Localhost deletes an empty directory with rmdir, which
        // does not call fcntl. Chain keeps its own fcntl commands.
        if matches!(provider, RuntimeProviderId::Object) {
            code.extend(object_directory_fcntl(arch));
        }
        code.push(stmt(6, DENY));
    }
    code
}

/// `fcntl` commands glibc `fdopendir` uses for Rust `remove_dir_all`.
///
/// On x86_64 and aarch64, glibc 2.35 and 2.39 `fdopendir` calls `F_GETFL`,
/// then `__alloc_dir` with `close_fd = false` calls `F_SETFD` of `FD_CLOEXEC`.
/// Rust 1.95 `remove_dir_all` opens with `openat(O_DIRECTORY|O_NOFOLLOW)` and
/// passes that descriptor to `fdopendir`. `opendir` (list, and `rmdir` of an
/// empty directory) sets `close_fd` and does not call `fcntl`, which is why
/// trash of a directory already succeeds. The filter's deny is `EACCES` and
/// does not name the call. Landlock `REMOVE_DIR` is already on the storage
/// mask; this is not a path rule.
fn object_directory_fcntl(arch: AuditArch) -> Vec<Instruction> {
    let nr = number("fcntl", arch).expect("object fcntl rule needs a number");
    // F_GETFL = 3, F_SETFD = 2, FD_CLOEXEC = 1. Same numbers on both arches.
    vec![
        jump(0x15, nr, 0, 7),
        stmt(0x20, 24),
        jump(0x15, 3, 3, 0),
        jump(0x15, 2, 0, 3),
        stmt(0x20, 32),
        jump(0x15, 1, 0, 1),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]
}

/// The model's measured argument rules, with syscall numbers filled in.
/// Chain uses the clone3, clone, fcntl, futex, and prlimit64 blocks. Those
/// blocks jump only inside themselves, so chain can place them in its order.
fn measured_argument_rules(arch: AuditArch) -> Vec<Instruction> {
    let mut rules: Vec<Instruction> = MODEL_RULES
        .split_whitespace()
        .map(|packed| {
            let bits = u64::from_str_radix(packed, 16).expect("model rule encoding");
            [
                (bits >> 48) as u32,
                ((bits >> 40) & 255) as u32,
                ((bits >> 32) & 255) as u32,
                bits as u32,
            ]
        })
        .collect();
    for (at, name) in [
        (0, "clone3"),
        (2, "clone"),
        (9, "socketpair"),
        (14, "fcntl"),
        (22, "prlimit64"),
        (33, "futex"),
        (42, "socket"),
    ] {
        rules[at][3] = number(name, arch).expect("measured rule needs an architecture number");
    }
    rules
}

/// Chain argument tail. Allow-list entries win on the first match, so these
/// names stay out of `measured_syscalls`. Pinned to reqwest 0.12.28, tokio
/// 1.52.1, mio 1.2.0, hyper-util 0.1.20, and socket2 0.6.3
/// (`chain_filter_names_the_pinned_network_stack`).
fn chain_argument_rules(arch: AuditArch) -> Vec<Instruction> {
    let measured = measured_argument_rules(arch);
    let nr = |name: &str| number(name, arch).expect("chain rule needs an architecture number");
    let mut code = Vec::new();
    // clone3 and clone, then fcntl, futex, and prlimit64. Same instructions as
    // the model blocks. Chain's order is fcntl, futex, prlimit64.
    code.extend_from_slice(&measured[0..9]);
    code.extend_from_slice(&measured[14..22]);
    code.extend_from_slice(&measured[33..42]);
    code.extend_from_slice(&measured[22..33]);
    // socket: AF_INET and AF_INET6. AF_UNIX and AF_NETLINK stay denied.
    code.extend([
        jump(0x15, nr("socket"), 0, 5),
        stmt(0x20, 16),
        jump(0x15, 2, 1, 0),
        jump(0x15, 10, 0, 1),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]);
    // setsockopt: IP_RECVERR, IPV6_RECVERR, and IPV6_V6ONLY. Musl 1.2.5
    // `res_msend` sets IPV6_V6ONLY to 0 on an AF_INET6 UDP socket before bind.
    // TCP_NODELAY and SO_KEEPALIVE stay denied.
    code.extend([
        jump(0x15, nr("setsockopt"), 0, 11),
        stmt(0x20, 24),
        jump(0x15, 0, 0, 3),
        stmt(0x20, 32),
        jump(0x15, 11, 0, 6),
        stmt(6, ALLOW),
        jump(0x15, 41, 0, 4),
        stmt(0x20, 32),
        jump(0x15, 25, 1, 0),
        jump(0x15, 26, 0, 1),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]);
    // getsockopt: SO_ERROR. take_error fails closed without it.
    code.extend([
        jump(0x15, nr("getsockopt"), 0, 6),
        stmt(0x20, 24),
        jump(0x15, 1, 0, 3),
        stmt(0x20, 32),
        jump(0x15, 4, 0, 1),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]);
    // Musl 1.2.5 `res_msend` binds an ephemeral UDP socket (addrlen 16 or 28),
    // sends with MSG_NOSIGNAL to that same length, and receives with flags 0.
    // listen, accept, and AF_UNIX stay denied. These three are chain only.
    code.extend(chain_dns_rules(&nr));
    code.push(stmt(6, DENY));
    code
}

/// `bind`, `sendto`, and `recvmsg` for chain DNS. Each block denies every
/// other shape of that syscall.
fn chain_dns_rules(nr: &dyn Fn(&str) -> u32) -> Vec<Instruction> {
    const MSG_NOSIGNAL: u32 = 0x4000;
    let mut code = Vec::new();
    // bind(fd, addr, addrlen): addrlen is 16 (IPv4) or 28 (IPv6).
    code.extend([
        jump(0x15, nr("bind"), 0, 5),
        stmt(0x20, 32),
        jump(0x15, 16, 1, 0),
        jump(0x15, 28, 0, 1),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]);
    // sendto(fd, buf, len, flags, addr, addrlen): flags MSG_NOSIGNAL, addrlen 16 or 28.
    code.extend([
        jump(0x15, nr("sendto"), 0, 7),
        stmt(0x20, 40),
        jump(0x15, MSG_NOSIGNAL, 0, 4),
        stmt(0x20, 56),
        jump(0x15, 16, 1, 0),
        jump(0x15, 28, 0, 1),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]);
    // recvmsg(fd, msg, flags): musl passes flags 0.
    code.extend([
        jump(0x15, nr("recvmsg"), 0, 4),
        stmt(0x20, 32),
        jump(0x15, 0, 0, 1),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]);
    code
}

/// x86_64 musl `open` is the older form of `openat` for `AT_FDCWD`.
/// Rust 1.95.0's musl target is musl 1.2.5: `src/internal/syscall.h`
/// `__sys_open` uses `SYS_open` when that number exists, and ORs `O_LARGEFILE`
/// (0 on this check; the bit is allowed). aarch64 has no `open` and uses
/// `openat`, which these helpers already allow.
///
/// `O_PATH` (0x200000) and `__O_TMPFILE` (0x400000) are denied. Landlock does
/// not check `O_PATH`, and a tmpfile has no path for Landlock to check.
/// `O_CREAT` stays allowed: Landlock checks `MAKE_REG` on `open` the same way
/// it checks `openat`. This row lets the helper open a file the way musl
/// opens one on x86_64. It does not add a path Landlock does not already see.
fn musl_open_rule(arch: AuditArch) -> Vec<Instruction> {
    let Some(nr) = number("open", arch) else {
        return Vec::new();
    };
    const O_PATH: u32 = 0x0020_0000;
    const O_TMPFILE_BIT: u32 = 0x0040_0000;
    vec![
        jump(0x15, nr, 0, 5),
        stmt(0x20, 24),
        jump(0x45, O_PATH, 2, 0),
        jump(0x45, O_TMPFILE_BIT, 1, 0),
        stmt(6, ALLOW),
        stmt(6, DENY),
    ]
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;
    use super::super::rights::admit_committed;

    fn golden(text: &str) -> Vec<Instruction> {
        text.lines().filter(|line| !line.starts_with('#') && !line.is_empty()).map(|line| {
            let fields: Vec<u32> = line.split('#').next().unwrap().split_whitespace().map(|word| {
                match word.strip_prefix("0x") {
                    Some(hex) => u32::from_str_radix(hex, 16).unwrap(),
                    None => word.parse().unwrap(),
                }
            }).collect();
            fields.try_into().unwrap_or_else(|_| panic!("invalid golden: {line}"))
        }).collect()
    }

    #[test]
    fn all_provider_programs_equal_committed_instruction_numbers() {
        macro_rules! check {
            ($file:literal, $arch:ident, $provider:ident) => {
                assert_eq!(program(RuntimeProviderId::$provider,
                    &admit_committed(RuntimeProviderId::$provider), AuditArch::$arch),
                    golden(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
                        "/../../../capsules/wallet-provider/tests/", $file))), $file);
            };
        }
        check!("did-seccomp-x86_64.golden", X86_64, Did);
        check!("wallet-seccomp-x86_64.golden", X86_64, Wallet);
        check!("model-seccomp-x86_64.golden", X86_64, Model);
        check!("did-seccomp-aarch64.golden", Aarch64, Did);
        check!("wallet-seccomp-aarch64.golden", Aarch64, Wallet);
        check!("model-seccomp-aarch64.golden", Aarch64, Model);
    }

    /// Whole-file pins for the reviewed M1a programs. These digests are
    /// independent of both builders and include every argument decision.
    #[test]
    fn model_whole_goldens_match_reviewed_pins() {
        use sha2::{Digest as _, Sha256};
        for (golden, expected) in [
            (include_bytes!("../../../../../capsules/wallet-provider/tests/model-seccomp-x86_64.golden").as_slice(), "4fae5d0743d35c1650c6453d6f5bc9541ce67fb4237a99563dd9cafef8bcaf6a"),
            (include_bytes!("../../../../../capsules/wallet-provider/tests/model-seccomp-aarch64.golden").as_slice(), "4debc431452131f50261d7fd2a9561503fcb6f9b934222770a35862c5271530c"),
        ] {
            assert_eq!(format!("{:x}", Sha256::digest(golden)), expected);
        }
    }

    #[test]
    fn an_unlisted_name_is_absent_and_does_not_panic() {
        assert_eq!(number("missing_call", AuditArch::Aarch64), None);
        assert_eq!(number("ioctl", AuditArch::X86_64), None);
        assert_eq!(number("ioctl", AuditArch::Aarch64), None);
    }

    /// Measured decisions on both architectures. A classic BPF interpreter
    /// runs the rendered program. The pin's unconditional baseline is separate.
    #[test]
    fn measured_filter_decides_the_argument_cases() {
        // label, syscall, args, allow
        let cases: [(&str, &str, [u64; 6], bool); 19] = [
            ("thread clone", "clone", [0x3d_0f00, 0, 0, 0, 0, 0], true),
            ("measured vfork", "clone", [0x4111, 0, 0, 0, 0, 0], true),
            ("plain fork", "clone", [0x11, 0, 0, 0, 0, 0], false),
            ("clone newuser", "clone", [0x1000_0011, 0, 0, 0, 0, 0], false),
            ("clone newuser vfork", "clone", [0x1000_4011, 0, 0, 0, 0, 0], false),
            ("futex", "futex", [0, 0, 0, 0, 0, 0], true),
            ("futex requeue", "futex", [0, 3, 0, 0, 0, 0], false),
            ("socketpair", "socketpair", [1, 1, 0, 0, 0, 0], true),
            ("socketpair inet", "socketpair", [2, 1, 0, 0, 0, 0], false),
            ("fcntl getfl", "fcntl", [3, 3, 0, 0, 0, 0], true),
            ("fcntl setfl", "fcntl", [3, 4, 0, 0, 0, 0], true),
            ("fcntl setfd", "fcntl", [3, 2, 0, 0, 0, 0], false),
            ("prlimit64", "prlimit64", [0, 0, 0, 0, 0, 0], true),
            ("prlimit64 other pid", "prlimit64", [1, 0, 0, 0, 0, 0], false),
            ("prlimit64 new limit", "prlimit64", [0, 0, 1, 0, 0, 0], false),
            ("socket unix", "socket", [1, 1, 0, 0, 0, 0], true),
            ("socket inet", "socket", [2, 1, 0, 0, 0, 0], false),
            ("socket inet6", "socket", [10, 1, 0, 0, 0, 0], false),
            ("kill other pid", "kill", [1, 9, 0, 0, 0, 0], false),
        ];
        for arch in [AuditArch::X86_64, AuditArch::Aarch64] {
            let audit = match arch { AuditArch::X86_64 => 0xc000_003e, AuditArch::Aarch64 => 0xc000_00b7 };
            let prog = program(RuntimeProviderId::Model, &admit_committed(RuntimeProviderId::Model), arch);
            for (label, name, args, allow) in cases {
                let nr = number(name, arch).expect(name);
                let got = interpret(&prog, nr, args, audit);
                let want = if allow { super::ALLOW } else { super::DENY };
                assert_eq!(got, want, "{arch:?} {label} returned {got:#x}");
            }
        }
    }

    fn interpret(prog: &[[u32; 4]], nr: u32, args: [u64; 6], arch: u32) -> u32 {
        let mut data = [0u8; 64];
        data[..4].copy_from_slice(&(nr as i32).to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (index, arg) in args.iter().enumerate() {
            let at = 16 + index * 8;
            data[at..at + 8].copy_from_slice(&arg.to_le_bytes());
        }
        let mut acc = 0u32;
        let mut pc = 0usize;
        for _ in 0..prog.len().saturating_mul(8) {
            let [code, jt, jf, k] = prog[pc];
            match code {
                0x20 => {
                    let off = k as usize;
                    acc = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
                    pc += 1;
                }
                0x54 => { acc &= k; pc += 1; }
                0x06 => return k,
                0x15 | 0x35 | 0x45 => {
                    let yes = match code {
                        0x15 => acc == k,
                        0x35 => acc >= k,
                        _ => acc & k != 0,
                    };
                    pc += 1 + if yes { jt as usize } else { jf as usize };
                }
                other => panic!("opcode {other:#x}"),
            }
        }
        panic!("filter did not return");
    }

    /// Localhost `write_file` opens, writes, and may `mkdirat`. It does not rename
    /// (`capsules/localhost-provider/src/main.rs` write path). Object's atomic write
    /// and chain's lifecycle file use `rename`, which is `renameat` on aarch64.
    /// `faccessat2` and `ioctl` are not those calls. Both stay denied.
    #[test]
    fn helper_operations_pass_the_filter_for_the_calls_they_make() {
        let arch = AuditArch::Aarch64;
        let audit = 0xc000_00b7_u32;
        let allow = ["openat", "write", "close", "mkdirat", "statx", "newfstatat", "readlinkat"];
        for provider in [RuntimeProviderId::Localhost, RuntimeProviderId::Object, RuntimeProviderId::Chain] {
            let admitted = super::super::rights::admit_runtime_grant(provider);
            let names = super::linux_seccomp_list(provider, &admitted, arch);
            assert!(!names.contains(&"ioctl"), "{provider:?}");
            assert!(!names.contains(&"faccessat2"), "{provider:?}");
            let prog = program(provider, &admitted, arch);
            for name in allow {
                let nr = number(name, arch).expect(name);
                assert_eq!(interpret(&prog, nr, [0; 6], audit), super::ALLOW, "{provider:?} {name}");
            }
            let renameat = number("renameat", arch).expect("renameat");
            let rename_allowed = matches!(provider, RuntimeProviderId::Object | RuntimeProviderId::Chain);
            assert_eq!(
                interpret(&prog, renameat, [0; 6], audit) == super::ALLOW,
                rename_allowed,
                "{provider:?} renameat"
            );
            // aarch64 ioctl is 29. faccessat2 is 439 on both arches. Neither name is listed.
            assert_eq!(interpret(&prog, 29, [0; 6], audit), super::DENY, "{provider:?} ioctl");
            assert_eq!(interpret(&prog, 439, [0; 6], audit), super::DENY, "{provider:?} faccessat2");
        }
        let x86 = AuditArch::X86_64;
        let x86_audit = 0xc000_003e_u32;
        for provider in [RuntimeProviderId::Localhost, RuntimeProviderId::Object, RuntimeProviderId::Chain] {
            let admitted = super::super::rights::admit_runtime_grant(provider);
            let prog = program(provider, &admitted, x86);
            // x86_64 ioctl is 16.
            assert_eq!(interpret(&prog, 16, [0; 6], x86_audit), super::DENY, "{provider:?} ioctl");
            assert_eq!(interpret(&prog, 439, [0; 6], x86_audit), super::DENY, "{provider:?} faccessat2");
        }
    }

    /// The pin's model golden, minus the post-pin rename pair, is the unconditional
    /// baseline. Measured probe names are dropped the same way. The argument tail
    /// is the interpreter row above, not this pin.
    #[test]
    fn model_golden_at_pin_d0dd5693_drops_rename_pairs() {
        const POST_PIN: &[&str] = &[
            "rename", "renameat", "accept4", "bind", "connect", "dup2", "getpgrp", "getpid",
            "getsockopt", "listen", "pipe2", "readlink", "recvfrom", "rt_sigprocmask",
            "sendto", "setpgid", "waitid",
        ];
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
        for arch in ["x86_64", "aarch64"] {
            let head = std::fs::read_to_string(format!("{root}/capsules/wallet-provider/tests/model-seccomp-{arch}.golden")).unwrap();
            let spec = format!("d0dd5693:capsules/wallet-provider/tests/model-seccomp-{arch}.golden");
            let out = super::super::rights::git_show(&spec);
            assert!(out.status.success(), "pin {spec} missing: {}", String::from_utf8_lossy(&out.stderr));
            let pin = String::from_utf8(out.stdout).unwrap();
            assert_eq!(baseline_words(&head, POST_PIN), baseline_words(&pin, POST_PIN), "pin d0dd5693 model {arch} golden baseline");
        }
    }

    fn baseline_words(text: &str, drop_names: &[&str]) -> Vec<[u32; 4]> {
        let lines: Vec<&str> = text.lines().collect();
        let mut out = Vec::new();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            if line.contains("SYS_clone3") { break; }
            let body = line.split('#').next().unwrap().trim();
            if body.is_empty() || line.trim_start().starts_with('#') { index += 1; continue; }
            let name = line.split("# SYS_").nth(1).map(str::trim);
            if name.is_some_and(|name| drop_names.contains(&name)) { index += 2; continue; }
            let fields: Vec<u32> = body.split_whitespace().map(|word| match word.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16).unwrap(),
                None => word.parse().unwrap(),
            }).collect();
            out.push(fields.try_into().unwrap());
            index += 1;
        }
        out
    }

    /// Did and wallet goldens arrived after the original lab pin.
    #[test]
    fn did_and_wallet_goldens_postdate_pin_d0dd5693() {
        for (provider, added) in [("did", "c2dc6ca08"), ("wallet", "51c503fe7")] {
            for arch in ["x86_64", "aarch64"] {
                let spec = format!("d0dd5693:capsules/wallet-provider/tests/{provider}-seccomp-{arch}.golden");
                assert!(!super::super::rights::git_show(&spec).status.success(), "{provider} golden is absent at pin d0dd5693; added at {added}");
            }
            assert!(super::super::rights::git_show(&format!("{added}:capsules/wallet-provider/tests/{provider}-seccomp-x86_64.golden")).status.success(), "{provider} golden is the post-pin addition at {added}");
        }
    }

    /// Chain's own argument rules. An unconditional allow of `socket` would
    /// accept AF_UNIX here, and a missing `clone3` rule would return EACCES.
    #[test]
    fn chain_filter_decides_the_argument_cases() {
        let admitted = super::super::rights::admit_runtime_grant(RuntimeProviderId::Chain);
        let cases: &[(&str, &str, [u64; 6], u32)] = &[
            ("thread clone", "clone", [0x3d_0f00, 0, 0, 0, 0, 0], super::ALLOW),
            ("measured vfork", "clone", [0x4111, 0, 0, 0, 0, 0], super::ALLOW),
            ("plain fork", "clone", [0x11, 0, 0, 0, 0, 0], super::DENY),
            ("clone3", "clone3", [0, 0, 0, 0, 0, 0], 0x0005_0026),
            ("fcntl getfd", "fcntl", [3, 1, 0, 0, 0, 0], super::ALLOW),
            ("fcntl dupfd_cloexec", "fcntl", [3, 0x406, 0, 0, 0, 0], super::ALLOW),
            ("fcntl getfl", "fcntl", [3, 3, 0, 0, 0, 0], super::ALLOW),
            ("fcntl setfl", "fcntl", [3, 4, 0, 0, 0, 0], super::ALLOW),
            ("fcntl setfd", "fcntl", [3, 2, 0, 0, 0, 0], super::DENY),
            ("futex wait", "futex", [0, 0, 0, 0, 0, 0], super::ALLOW),
            ("futex wake", "futex", [0, 1, 0, 0, 0, 0], super::ALLOW),
            ("futex lock", "futex", [0, 9, 0, 0, 0, 0], super::ALLOW),
            ("futex unlock", "futex", [0, 10, 0, 0, 0, 0], super::ALLOW),
            ("futex private wait", "futex", [0, 128, 0, 0, 0, 0], super::ALLOW),
            ("futex requeue", "futex", [0, 3, 0, 0, 0, 0], super::DENY),
            ("prlimit64", "prlimit64", [0, 0, 0, 0, 0, 0], super::ALLOW),
            ("prlimit64 other pid", "prlimit64", [1, 0, 0, 0, 0, 0], super::DENY),
            ("prlimit64 new limit", "prlimit64", [0, 0, 1, 0, 0, 0], super::DENY),
            ("socket inet", "socket", [2, 1, 0, 0, 0, 0], super::ALLOW),
            ("socket inet6", "socket", [10, 1, 0, 0, 0, 0], super::ALLOW),
            ("socket unix", "socket", [1, 1, 0, 0, 0, 0], super::DENY),
            ("socket netlink", "socket", [16, 3, 0, 0, 0, 0], super::DENY),
            ("setsockopt ip recverr", "setsockopt", [6, 0, 11, 0, 0, 0], super::ALLOW),
            ("setsockopt ipv6 recverr", "setsockopt", [6, 41, 25, 0, 0, 0], super::ALLOW),
            ("setsockopt keepalive", "setsockopt", [6, 1, 9, 0, 0, 0], super::DENY),
            ("setsockopt nodelay", "setsockopt", [6, 6, 1, 0, 0, 0], super::DENY),
            ("setsockopt ipv6 v6only", "setsockopt", [6, 41, 26, 0, 0, 0], super::ALLOW),
            ("getsockopt so_error", "getsockopt", [6, 1, 4, 0, 0, 0], super::ALLOW),
            ("getsockopt other", "getsockopt", [6, 1, 7, 0, 0, 0], super::DENY),
            ("connect", "connect", [6, 0, 0, 0, 0, 0], super::ALLOW),
            ("sendmmsg", "sendmmsg", [6, 0, 0, 0, 0, 0], super::ALLOW),
            ("sendto", "sendto", [6, 0, 0, 0, 0, 0], super::DENY),
            ("sendto musl dns", "sendto", [6, 0, 0, 0x4000, 0, 16], super::ALLOW),
            ("sendto musl dns v6", "sendto", [6, 0, 0, 0x4000, 0, 28], super::ALLOW),
            ("sendto other length", "sendto", [6, 0, 0, 0x4000, 0, 110], super::DENY),
            ("bind ipv4", "bind", [6, 0, 16, 0, 0, 0], super::ALLOW),
            ("bind ipv6", "bind", [6, 0, 28, 0, 0, 0], super::ALLOW),
            ("bind other length", "bind", [6, 0, 110, 0, 0, 0], super::DENY),
            ("recvmsg flags 0", "recvmsg", [6, 0, 0, 0, 0, 0], super::ALLOW),
            ("recvmsg other flags", "recvmsg", [6, 0, 1, 0, 0, 0], super::DENY),
            ("listen", "listen", [6, 1, 0, 0, 0, 0], super::DENY),
            ("accept4", "accept4", [6, 0, 0, 0, 0, 0], super::DENY),
            ("pipe2", "pipe2", [0, 0, 0, 0, 0, 0], super::DENY),
        ];
        for arch in [AuditArch::X86_64, AuditArch::Aarch64] {
            let audit = match arch { AuditArch::X86_64 => 0xc000_003e, AuditArch::Aarch64 => 0xc000_00b7 };
            let prog = program(RuntimeProviderId::Chain, &admitted, arch);
            assert!(prog.len() <= 256, "{arch:?} chain filter is {} instructions", prog.len());
            for (label, name, args, want) in cases {
                let Some(nr) = number(name, arch) else { continue };
                let got = interpret(&prog, nr, *args, audit);
                assert_eq!(got, *want, "{arch:?} {label} returned {got:#x}");
            }
        }
    }

    /// The chain filter is coupled to these crate versions. A lockfile bump
    /// fails here instead of becoming EACCES inside a running helper.
    #[test]
    fn chain_filter_names_the_pinned_network_stack() {
        const PINNED: &[(&str, &str)] = &[
            ("reqwest", "0.12.28"),
            ("tokio", "1.52.1"),
            ("mio", "1.2.0"),
            ("hyper-util", "0.1.20"),
            ("socket2", "0.6.3"),
        ];
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../capsules/chain-provider/Cargo.lock"
        );
        let lock = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
        for (name, version) in PINNED {
            let mut found = Vec::new();
            let mut lines = lock.lines();
            while let Some(line) = lines.next() {
                if line == "[[package]]" {
                    let crate_name = lines.next().unwrap_or("");
                    let crate_version = lines.next().unwrap_or("");
                    if crate_name == format!("name = \"{name}\"") {
                        found.push(
                            crate_version
                                .strip_prefix("version = \"")
                                .and_then(|rest| rest.strip_suffix('"'))
                                .unwrap_or(crate_version)
                                .to_string(),
                        );
                    }
                }
            }
            assert_eq!(found, vec![(*version).to_string()], "{name} left the pinned chain stack");
        }
    }

    /// Names the fcntl commands `remove_dir_all` needs. Seccomp's deny is
    /// EACCES and the kernel does not put the syscall number in that errno,
    /// so this interpreter is the name. `--nocapture` prints each decision.
    #[test]
    fn object_directory_delete_names_the_fdopendir_fcntl_commands() {
        let admitted = super::super::rights::admit_runtime_grant(RuntimeProviderId::Object);
        let local = super::super::rights::admit_runtime_grant(RuntimeProviderId::Localhost);
        let cases: &[(&str, [u64; 6], bool)] = &[
            ("fcntl F_GETFL", [7, 3, 0, 0, 0, 0], true),
            ("fcntl F_SETFD FD_CLOEXEC", [7, 2, 1, 0, 0, 0], true),
            ("fcntl F_SETFD other", [7, 2, 0, 0, 0, 0], false),
            ("fcntl F_GETFD", [7, 1, 0, 0, 0, 0], false),
            ("fcntl F_SETFL", [7, 4, 0, 0, 0, 0], false),
            ("fcntl F_DUPFD_CLOEXEC", [7, 0x406, 0, 0, 0, 0], false),
        ];
        for arch in [AuditArch::X86_64, AuditArch::Aarch64] {
            let audit = match arch {
                AuditArch::X86_64 => 0xc000_003e,
                AuditArch::Aarch64 => 0xc000_00b7,
            };
            let object = program(RuntimeProviderId::Object, &admitted, arch);
            let localhost = program(RuntimeProviderId::Localhost, &local, arch);
            assert!(
                object.len() <= 256,
                "{arch:?} object filter is {} instructions",
                object.len()
            );
            for (label, args, allow) in cases {
                let nr = number("fcntl", arch).expect("fcntl");
                let got = interpret(&object, nr, *args, audit);
                let want = if *allow { super::ALLOW } else { super::DENY };
                let decision = if got == super::ALLOW { "allow" } else { "deny" };
                eprintln!("{arch:?} object {label}: {decision}");
                assert_eq!(got, want, "{arch:?} object {label} returned {got:#x}");
                assert_eq!(
                    interpret(&localhost, nr, *args, audit),
                    super::DENY,
                    "{arch:?} localhost {label} must stay denied"
                );
            }
            let unlinkat = number("unlinkat", arch).expect("unlinkat");
            assert_eq!(
                interpret(&object, unlinkat, [0; 6], audit),
                super::ALLOW,
                "{arch:?} unlinkat AT_REMOVEDIR stays allowed"
            );
            if let Some(rmdir) = number("rmdir", arch) {
                assert_eq!(
                    interpret(&object, rmdir, [0; 6], audit),
                    super::ALLOW,
                    "{arch:?} rmdir stays allowed"
                );
            }
        }
        for name in ["chmod", "fchmodat"] {
            assert!(
                !super::NUMBERS
                    .split_whitespace()
                    .any(|row| row.split(':').next() == Some(name)),
                "{name} is not a helper syscall number"
            );
        }
    }

    /// x86_64 musl `open` for the three helpers. `O_PATH` and `__O_TMPFILE`
    /// stay denied. `O_CREAT` stays allowed because Landlock checks it.
    /// aarch64 has no `open`. Did does not get the row. `stat` and `lstat`
    /// are the older metadata calls and are not on Did.
    #[test]
    fn musl_open_stat_and_lstat_are_only_the_three_helpers() {
        const O_CLOEXEC: u64 = 0x80000;
        const O_CREAT: u64 = 0x40;
        const O_PATH: u64 = 0x200000;
        const O_TMPFILE: u64 = 0x400000;
        let audit = 0xc000_003e;
        let chain = super::super::rights::admit_runtime_grant(RuntimeProviderId::Chain);
        let did = super::super::rights::admit_runtime_grant(RuntimeProviderId::Did);
        assert_eq!(number("open", AuditArch::Aarch64), None);
        assert_eq!(number("stat", AuditArch::Aarch64), None);
        assert_eq!(number("lstat", AuditArch::Aarch64), None);
        let open_nr = number("open", AuditArch::X86_64).unwrap();
        let shapes: &[(&str, [u64; 6], u32)] = &[
            ("read", [0, O_CLOEXEC, 0, 0, 0, 0], super::ALLOW),
            ("create", [0, O_CREAT | O_CLOEXEC, 0o644, 0, 0, 0], super::ALLOW),
            ("path", [0, O_PATH, 0, 0, 0, 0], super::DENY),
            ("tmpfile", [0, O_TMPFILE | 0x10000, 0o644, 0, 0, 0], super::DENY),
        ];
        for provider in [
            RuntimeProviderId::Localhost,
            RuntimeProviderId::Object,
            RuntimeProviderId::Chain,
        ] {
            let admitted = super::super::rights::admit_runtime_grant(provider);
            let prog = program(provider, &admitted, AuditArch::X86_64);
            for (label, args, want) in shapes {
                assert_eq!(
                    interpret(&prog, open_nr, *args, audit),
                    *want,
                    "{provider:?} open {label}"
                );
            }
            for name in ["stat", "lstat"] {
                let nr = number(name, AuditArch::X86_64).unwrap();
                assert_eq!(
                    interpret(&prog, nr, [0; 6], audit),
                    super::ALLOW,
                    "{provider:?} {name}"
                );
            }
        }
        let chain_prog = program(RuntimeProviderId::Chain, &chain, AuditArch::X86_64);
        let did_prog = program(RuntimeProviderId::Did, &did, AuditArch::X86_64);
        assert_eq!(
            interpret(&did_prog, open_nr, [0, O_CLOEXEC, 0, 0, 0, 0], audit),
            super::DENY
        );
        for name in ["stat", "lstat"] {
            let nr = number(name, AuditArch::X86_64).unwrap();
            assert_eq!(interpret(&did_prog, nr, [0; 6], audit), super::DENY, "did {name}");
        }
        let bind_nr = number("bind", AuditArch::X86_64).unwrap();
        let recv_nr = number("recvmsg", AuditArch::X86_64).unwrap();
        assert_eq!(interpret(&chain_prog, bind_nr, [0; 6], audit), super::DENY);
        assert_eq!(interpret(&did_prog, bind_nr, [6, 0, 16, 0, 0, 0], audit), super::DENY);
        assert_eq!(interpret(&did_prog, recv_nr, [0; 6], audit), super::DENY);
        assert_eq!(interpret(&chain_prog, recv_nr, [6, 0, 1, 0, 0, 0], audit), super::DENY);
    }
}
