//! A simulated kernel for tests. It fails one chosen step with a chosen OS
//! error, records every step it was asked to run, and records every exec.
//! `spawn_confined` runs the guard in the calling process, so nothing here
//! touches the real process state.

use crate::{confine_and_exec, Errno, Fault, Kernel, Plan, Step};
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

pub const SIM_PID: u32 = 4242;
const SIM_RULESET_FD: RawFd = 100;

#[derive(Debug)]
pub struct SimKernel {
    pub landlock_abi: u32,
    pub last_capability: u32,
    pub fail: Option<(Step, Errno)>,
    pub steps: Vec<Step>,
    pub execs: Vec<CString>,
    pub handled_fs: u64,
    pub handled_net: u64,
    pub scoped: u64,
}

impl Default for SimKernel {
    fn default() -> SimKernel {
        SimKernel {
            landlock_abi: 6,
            last_capability: 40,
            fail: None,
            steps: Vec::new(),
            execs: Vec::new(),
            handled_fs: 0,
            handled_net: 0,
            scoped: 0,
        }
    }
}

impl SimKernel {
    pub fn new() -> SimKernel {
        SimKernel::default()
    }

    pub fn failing(step: Step, errno: Errno) -> SimKernel {
        SimKernel {
            fail: Some((step, errno)),
            ..SimKernel::default()
        }
    }

    pub fn with_landlock_abi(abi: u32) -> SimKernel {
        SimKernel {
            landlock_abi: abi,
            ..SimKernel::default()
        }
    }

    fn run(&mut self, step: Step) -> Result<(), Errno> {
        self.steps.push(step);
        match self.fail {
            Some((failing, errno)) if failing == step => Err(errno),
            _ => Ok(()),
        }
    }
}

impl Kernel for SimKernel {
    fn unshare_user_namespace(&mut self) -> Result<(), Errno> {
        self.run(Step::Unshare)
    }

    fn unshare_pid_namespace(&mut self) -> Result<(), Errno> {
        self.run(Step::UnsharePid)
    }

    fn write_uid_map(&mut self, _map: &[u8]) -> Result<(), Errno> {
        self.run(Step::UidMap)
    }

    fn deny_setgroups(&mut self) -> Result<(), Errno> {
        self.run(Step::Setgroups)
    }

    fn write_gid_map(&mut self, _map: &[u8]) -> Result<(), Errno> {
        self.run(Step::GidMap)
    }

    fn last_capability(&mut self) -> Result<u32, Errno> {
        self.run(Step::LastCapability)?;
        Ok(self.last_capability)
    }

    fn drop_bounding_capability(&mut self, _cap: u32) -> Result<(), Errno> {
        self.run(Step::BoundingSet)
    }

    fn clear_ambient_capabilities(&mut self) -> Result<(), Errno> {
        self.run(Step::AmbientSet)
    }

    fn clear_capability_sets(&mut self) -> Result<(), Errno> {
        self.run(Step::CapabilitySets)
    }

    fn set_no_new_privs(&mut self) -> Result<(), Errno> {
        self.run(Step::SetNoNewPrivs)
    }

    fn install_seccomp_filter(&mut self, _filter: &[libc::sock_filter]) -> Result<(), Errno> {
        self.run(Step::InstallFilter)
    }

    fn landlock_abi(&mut self) -> Result<u32, Errno> {
        self.run(Step::AbiProbe)?;
        Ok(self.landlock_abi)
    }

    fn landlock_create_ruleset(
        &mut self,
        handled_fs: u64,
        handled_net: u64,
        scoped: u64,
    ) -> Result<RawFd, Errno> {
        self.handled_fs = handled_fs;
        self.handled_net = handled_net;
        self.scoped = scoped;
        self.run(Step::CreateRuleset)?;
        Ok(SIM_RULESET_FD)
    }

    fn landlock_add_path_rule(
        &mut self,
        _ruleset: RawFd,
        _path: &CStr,
        _access: u64,
    ) -> Result<(), Errno> {
        let step = if self.steps.contains(&Step::StorageRootRule) {
            Step::ExecutableRule
        } else {
            Step::StorageRootRule
        };
        self.run(step)
    }

    fn landlock_restrict_self(&mut self, _ruleset: RawFd) -> Result<(), Errno> {
        self.run(Step::RestrictSelf)
    }

    fn exec(&mut self, plan: &Plan) -> Result<(), Errno> {
        self.run(Step::Execve)?;
        self.execs.push(plan.executable().to_owned());
        Ok(())
    }

    fn spawn_confined(&mut self, plan: &Plan) -> Result<u32, Fault> {
        confine_and_exec(self, plan).map(|()| SIM_PID)
    }
}
