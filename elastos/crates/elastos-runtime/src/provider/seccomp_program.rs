//! B3 provider filter programs, rendered without a kernel dependency.
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
    "renameat:-:38 renameat2:316:276 rseq:334:293 rt_sigaction:13:134 socketpair:53:199 statx:332:291 ",
    "sysinfo:99:179 uname:63:160 unlink:87:- unlinkat:263:35 write:1:64 writev:20:66 ",
    "clone:56:220 clone3:435:435",
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

// The model's measured argument rules, packed as code:jt:jf:k. Six syscall
// operands are filled from NUMBERS below. This suffix keeps clone, socketpair,
// fcntl, prlimit64 and futex conditional instead of allowing them by number.
const MODEL_RULES: &str = concat!(
    "0015000100000000 0006000000050026 0015000400000000 0020000000000010 0045000100010000 ",
    "000600007fff0000 000600000005000d 0015000400000000 0020000000000010 0015000100000001 ",
    "000600007fff0000 000600000005000d 0015000500000000 0020000000000018 0015010000000001 ",
    "0015000100000406 000600007fff0000 000600000005000d 0015000a00000000 0020000000000010 ",
    "0015000700000000 0020000000000014 0015000500000000 0020000000000020 0015000300000000 ",
    "0020000000000024 0015000100000000 000600007fff0000 000600000005000d 0015000800000000 ",
    "0020000000000018 00540000fffffe7f 0015030000000000 0015020000000001 0015010000000009 ",
    "001500010000000a 000600007fff0000 000600000005000d 000600000005000d",
);

#[allow(dead_code)] // The installer is a later B3 slice.
#[rustfmt::skip]
pub(super) fn program(provider: RuntimeProviderId, arch: AuditArch) -> Vec<Instruction> {
    let audit: u32 = match arch { AuditArch::X86_64 => 0xc000_003e, AuditArch::Aarch64 => 0xc000_00b7 };
    let mut code = vec![
        stmt(0x20, 4), jump(0x15, audit, 1, 0), stmt(6, DENY),
        stmt(0x20, 0), jump(0x35, 0x4000_0000, 0, 1), stmt(6, DENY),
    ];
    for name in linux_seccomp_list(provider, arch) {
        let nr = number(name, arch).expect("listed syscall needs an architecture number");
        code.extend([jump(0x15, nr, 0, 1), stmt(6, ALLOW)]);
    }
    if matches!(provider, RuntimeProviderId::Model) {
        let mut rules: Vec<Instruction> = MODEL_RULES.split_whitespace().map(|packed| {
            let bits = u64::from_str_radix(packed, 16).expect("model rule encoding");
            [(bits >> 48) as u32, ((bits >> 40) & 255) as u32,
             ((bits >> 32) & 255) as u32, bits as u32]
        }).collect();
        for (at, name) in [(0, "clone3"), (2, "clone"), (7, "socketpair"),
                           (12, "fcntl"), (18, "prlimit64"), (29, "futex")] {
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
                assert_eq!(program(RuntimeProviderId::$provider, AuditArch::$arch),
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

    #[test]
    #[should_panic(expected = "has no syscall number row")]
    fn unknown_syscall_name_fails_loudly() {
        number("missing_call", AuditArch::Aarch64);
    }
}
