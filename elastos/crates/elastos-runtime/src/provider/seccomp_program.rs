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
    "chmod:90:- fchmod:91:52 fchmodat:268:53 fcntl:72:25 fdatasync:75:83 flock:73:32 fstat:5:80 fsync:74:82 ",
    "ftruncate:77:46 futex:202:98 getdents64:217:61 geteuid:107:175 getrandom:318:278 linkat:265:37 ",
    "lseek:8:62 mkdir:83:- mkdirat:258:34 mmap:9:222 mprotect:10:226 munmap:11:215 ",
    "newfstatat:262:79 openat:257:56 openat2:437:437 poll:7:- ppoll:271:73 pread64:17:67 ",
    "prlimit64:302:261 pwrite64:18:68 read:0:63 readlinkat:267:78 readv:19:65 rename:82:- ",
    "renameat:-:38 renameat2:316:276 rmdir:84:- rseq:334:293 rt_sigaction:13:134 socketpair:53:199 statx:332:291 ",
    "sysinfo:99:179 uname:63:160 unlink:87:- unlinkat:263:35 write:1:64 writev:20:66 ",
    "clone:56:220 clone3:435:435 ",
    // Linux probe rows. The measured x86-only dup2, getpgrp, and readlink
    // have no AArch64 syscall or libc::SYS_* constant; '-' excludes each there.
    "accept4:288:242 bind:49:200 connect:42:203 dup2:33:- getpgrp:111:- getpid:39:172 getsockopt:55:209 kill:62:129 listen:50:201 pipe2:293:59 readlink:89:- recvfrom:45:207 rt_sigprocmask:14:135 sendto:44:206 setpgid:109:154 socket:41:198 waitid:247:95",
);

// An absent cell excludes that call by policy on this architecture. An absent row is an error.
pub(super) fn number(name: &str, arch: AuditArch) -> Option<u32> {
    let row = NUMBERS
        .split_whitespace()
        .find(|row| row.split(':').next() == Some(name))
        .unwrap_or_else(|| panic!("{name} has no syscall number row"));
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
    if matches!(provider, RuntimeProviderId::Model) {
        let mut rules: Vec<Instruction> = MODEL_RULES.split_whitespace().map(|packed| {
            let bits = u64::from_str_radix(packed, 16).expect("model rule encoding");
            [(bits >> 48) as u32, ((bits >> 40) & 255) as u32,
             ((bits >> 32) & 255) as u32, bits as u32]
        }).collect();
        for (at, name) in [(0, "clone3"), (2, "clone"), (9, "socketpair"),
                           (14, "fcntl"), (22, "prlimit64"), (33, "futex"),
                           (42, "socket")] {
            rules[at][3] = number(name, arch).expect("model rule needs an architecture number");
        }
        code.extend(rules);
    } else {
        code.push(stmt(6, DENY));
    }
    code
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
    #[should_panic(expected = "has no syscall number row")]
    fn unknown_syscall_name_fails_loudly() {
        number("missing_call", AuditArch::Aarch64);
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
}
