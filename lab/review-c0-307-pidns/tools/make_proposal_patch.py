#!/usr/bin/env python3
"""Build proposal.patch against a writable copy of #307 at 637345ac.

This script is how the committed patch was produced. It is not applied
to PR #307. Run from the review folder with FCL_SRC set.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REVIEW = Path(__file__).resolve().parent.parent
SRC = Path(
    os.environ.get("FCL_SRC", "/tmp/fcl-637345ac/lab/fail-closed-linux")
)


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected 1 occurrence, found {count}:\n{old[:80]}")
    path.write_text(text.replace(old, new, 1))


def patch_lib(src: Path) -> None:
    replace_once(
        src / "src/lib.rs",
        """pub struct NeededRight {
    pub name: &'static str,
    pub minimum_abi: u32,
    pub mask: i32,
}
""",
        """pub struct NeededRight {
    pub name: &'static str,
    pub minimum_abi: u32,
    pub mask: i32,
    /// Landlock filesystem bit to try-create. Used by the rights probe.
    pub access: u64,
}
""",
    )
    replace_once(
        src / "src/lib.rs",
        """    NeededRight {
        name: "truncate",
        minimum_abi: TRUNCATE_ABI,
        mask: MISSING_TRUNCATE,
    },
    NeededRight {
        name: "ioctl_dev",
        minimum_abi: IOCTL_DEV_ABI,
        mask: MISSING_IOCTL_DEV,
    },
""",
        """    NeededRight {
        name: "truncate",
        minimum_abi: TRUNCATE_ABI,
        mask: MISSING_TRUNCATE,
        access: landlock::ACCESS_FS_TRUNCATE,
    },
    NeededRight {
        name: "ioctl_dev",
        minimum_abi: IOCTL_DEV_ABI,
        mask: MISSING_IOCTL_DEV,
        access: landlock::ACCESS_FS_IOCTL_DEV,
    },
""",
    )
    replace_once(
        src / "src/lib.rs",
        """    Fork,
    PidFork,
    Report,
}
""",
        """    Fork,
    PidFork,
    Report,
    RightProbe,
}
""",
    )
    replace_once(
        src / "src/lib.rs",
        """        Step::AbiProbe,
        Step::AbiFloor,
        Step::CreateRuleset,
""",
        """        Step::AbiProbe,
        Step::AbiFloor,
        Step::RightProbe,
        Step::CreateRuleset,
""",
    )
    replace_once(
        src / "src/lib.rs",
        """            Step::AbiProbe
            | Step::AbiFloor
            | Step::CreateRuleset
""",
        """            Step::AbiProbe
            | Step::AbiFloor
            | Step::RightProbe
            | Step::CreateRuleset
""",
    )
    replace_once(
        src / "src/lib.rs",
        """            Step::AbiFloor => "abi_floor",
            Step::CreateRuleset => "create_ruleset",
""",
        """            Step::AbiFloor => "abi_floor",
            Step::RightProbe => "right_probe",
            Step::CreateRuleset => "create_ruleset",
""",
    )
    replace_once(
        src / "src/lib.rs",
        """            Step::AbiFloor => missing_rights_reason(fault.found, fault.errno),
            Step::AbiProbe => format!(
""",
        """            Step::AbiFloor => missing_rights_reason(fault.found, fault.errno),
            Step::RightProbe if fault.found != 0 => format!(
                "{}: landlock_create_ruleset returned EINVAL (reported ABI {})",
                missing_rights_reason(fault.found, fault.errno),
                fault.found
            ),
            Step::AbiProbe => format!(
""",
    )
    replace_once(
        src / "src/lib.rs",
        "    pub const GUARD: [Step; 18] = [",
        "    pub const GUARD: [Step; 19] = [",
    )
    replace_once(
        src / "src/lib.rs",
        """    pub const fn missing_rights(found: u32, mask: i32) -> Fault {
        Fault {
            step: Step::AbiFloor,
            errno: mask,
            found,
        }
    }
""",
        """    pub const fn missing_rights(found: u32, mask: i32) -> Fault {
        Fault {
            step: Step::AbiFloor,
            errno: mask,
            found,
        }
    }

    pub const fn right_probe(found: u32, mask: i32) -> Fault {
        Fault {
            step: Step::RightProbe,
            errno: mask,
            found,
        }
    }
""",
    )
    replace_once(
        src / "src/lib.rs",
        """    fn landlock_restrict_self(&mut self, ruleset: RawFd) -> Result<(), Errno>;
""",
        """    fn landlock_restrict_self(&mut self, ruleset: RawFd) -> Result<(), Errno>;
    /// Try-create a ruleset that handles only `access`. Ok(false) means
    /// the kernel returned EINVAL: it does not have that right.
    fn landlock_can_handle_fs(&mut self, access: u64) -> Result<bool, Errno> {
        match self.landlock_create_ruleset(access, 0, 0) {
            Ok(_) => Ok(true),
            Err(errno) if errno == libc::EINVAL => Ok(false),
            Err(errno) => Err(errno),
        }
    }
""",
    )
    replace_once(
        src / "src/lib.rs",
        """    if let Some(mask) = missing_required_mask(abi) {
        return Err(Fault::missing_rights(abi, mask));
    }
    let ruleset = kernel
""",
        """    if let Some(mask) = missing_required_mask(abi) {
        return Err(Fault::missing_rights(abi, mask));
    }
    let mut probed = 0;
    for right in FILE_PROFILE_NEEDED_RIGHTS {
        match kernel.landlock_can_handle_fs(right.access) {
            Ok(true) => {}
            Ok(false) => probed |= right.mask,
            Err(errno) => return Err(Fault::os(Step::RightProbe, errno)),
        }
    }
    if probed != 0 {
        return Err(Fault::right_probe(abi, probed));
    }
    let ruleset = kernel
""",
    )


def patch_sim(src: Path) -> None:
    replace_once(
        src / "src/sim.rs",
        """    pub handled_fs: u64,
    pub handled_net: u64,
    pub scoped: u64,
}
""",
        """    pub handled_fs: u64,
    pub handled_net: u64,
    pub scoped: u64,
    /// When set, `landlock_can_handle_fs` uses this mask instead of the
    /// reported ABI. A liar reports ABI 5 and accepts only ABI 1 bits.
    pub accepted_fs: Option<u64>,
}
""",
    )
    replace_once(
        src / "src/sim.rs",
        """            handled_fs: 0,
            handled_net: 0,
            scoped: 0,
        }
""",
        """            handled_fs: 0,
            handled_net: 0,
            scoped: 0,
            accepted_fs: None,
        }
""",
    )
    replace_once(
        src / "src/sim.rs",
        """    fn landlock_restrict_self(&mut self, _ruleset: RawFd) -> Result<(), Errno> {
        self.run(Step::RestrictSelf)
    }
""",
        """    fn landlock_restrict_self(&mut self, _ruleset: RawFd) -> Result<(), Errno> {
        self.run(Step::RestrictSelf)
    }

    fn landlock_can_handle_fs(&mut self, access: u64) -> Result<bool, Errno> {
        self.steps.push(Step::RightProbe);
        if let Some((Step::RightProbe, errno)) = self.fail {
            return Err(errno);
        }
        let accepted = self
            .accepted_fs
            .unwrap_or_else(|| crate::handled_fs_for_abi(self.landlock_abi));
        Ok(accepted & access == access)
    }
""",
    )


def patch_real(src: Path) -> None:
    replace_once(
        src / "src/real.rs",
        """    fn landlock_restrict_self(&mut self, ruleset: RawFd) -> Result<(), Errno> {
        // SAFETY: integer arguments only.
        check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) }).map(drop)
    }
""",
        """    fn landlock_restrict_self(&mut self, ruleset: RawFd) -> Result<(), Errno> {
        // SAFETY: integer arguments only.
        check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) }).map(drop)
    }

    fn landlock_can_handle_fs(&mut self, access: u64) -> Result<bool, Errno> {
        match self.landlock_create_ruleset(access, 0, 0) {
            Ok(fd) => {
                // SAFETY: fd came from create_ruleset above.
                unsafe { libc::close(fd) };
                Ok(true)
            }
            Err(errno) if errno == libc::EINVAL => Ok(false),
            Err(errno) => Err(errno),
        }
    }
""",
    )


def patch_tests(src: Path) -> None:
    tests = src / "tests/simulated.rs"
    text = tests.read_text()
    addition = """

#[test]
fn sim_lying_abi_5_with_abi_1_rights_refuses() {
    for provider in PROVIDERS {
        let mut kernel = SimKernel::with_landlock_abi(5);
        kernel.accepted_fs = Some(handled_fs_for_abi(1));
        let refusal = refused(&mut kernel, &spec(provider));
        assert_eq!(refusal.layer, Layer::Landlock, "{refusal}");
        assert_eq!(refusal.step, Step::RightProbe, "{refusal}");
        let text = refusal.to_string();
        assert!(
            text.contains("landlock_create_ruleset returned EINVAL"),
            "{refusal}"
        );
        assert!(text.contains("reported ABI 5"), "{refusal}");
        assert!(text.contains("truncate"), "{refusal}");
        assert!(text.contains("ioctl_dev"), "{refusal}");
        assert!(
            kernel.execs.is_empty(),
            "{provider} started on a lying ABI: {:?}",
            kernel.execs
        );
        assert!(
            !kernel.steps.contains(&Step::Execve),
            "{:?}",
            kernel.steps
        );
    }
}
"""
    if "sim_lying_abi_5_with_abi_1_rights_refuses" in text:
        return
    tests.write_text(text + addition)


def main() -> None:
    if not (SRC / "src/lib.rs").is_file():
        raise SystemExit(f"FCL_SRC missing: {SRC}")
    work = Path(tempfile.mkdtemp(prefix="rv-proposal-"))
    crate = work / "crate"
    shutil.copytree(SRC, crate, ignore=shutil.ignore_patterns("target", "__pycache__"))
    for path in crate.rglob("*"):
        if path.is_file() or path.is_dir():
            path.chmod(path.stat().st_mode | (0o200 if path.is_file() else 0o700))
    patch_lib(crate)
    patch_sim(crate)
    patch_real(crate)
    patch_tests(crate)
    files = ["src/lib.rs", "src/real.rs", "src/sim.rs", "tests/simulated.rs"]
    chunks = []
    for rel in files:
        diff = subprocess.run(
            ["diff", "-u", str(SRC / rel), str(crate / rel)],
            text=True,
            capture_output=True,
        )
        if not diff.stdout:
            continue
        rewritten = []
        for line in diff.stdout.splitlines():
            if line.startswith("--- "):
                rewritten.append(f"--- a/{rel}")
            elif line.startswith("+++ "):
                rewritten.append(f"+++ b/{rel}")
            else:
                rewritten.append(line)
        chunks.append("\n".join(rewritten))
    out = REVIEW / "proposal.patch"
    out.write_text("\n".join(chunks) + "\n")
    shutil.rmtree(work, ignore_errors=True)
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
