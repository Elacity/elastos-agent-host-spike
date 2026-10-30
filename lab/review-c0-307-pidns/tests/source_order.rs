//! Reads the reviewed #307 sources. These tests pin the PID-namespace
//! order that the review argues from. They do not edit that tree.

use std::path::PathBuf;

fn fcl_src() -> PathBuf {
    PathBuf::from(
        std::env::var("FCL_SRC")
            .unwrap_or_else(|_| "/tmp/fcl-637345ac/lab/fail-closed-linux".into()),
    )
}

fn read(rel: &str) -> String {
    let path = fcl_src().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("NOT RUN: {path:?}: {err}"))
}

#[test]
fn unshare_pid_is_inside_confine_before_capability_drop() {
    let lib = read("src/lib.rs");
    let confine = slice_fn(&lib, "pub fn confine<");
    let unshare = confine
        .find("unshare_pid_namespace()")
        .expect("confine must unshare the PID namespace");
    let caps = confine
        .find("last_capability()")
        .expect("confine must drop capabilities");
    assert!(
        unshare < caps,
        "unshare(CLONE_NEWPID) must run before cap drop inside confine"
    );
    assert!(
        !confine.contains("detach_into_pid_namespace"),
        "confine must not fork the reapers; that is confine_and_exec"
    );
}

#[test]
fn reaper_forks_run_after_confine_returns() {
    let lib = read("src/lib.rs");
    let body = slice_fn(&lib, "pub fn confine_and_exec<");
    let confine = body.find("confine(kernel, plan)?").expect("calls confine");
    let detach = body
        .find("detach_into_pid_namespace()")
        .expect("then detaches");
    let exec = body.find("exec(plan)").expect("then exec");
    assert!(confine < detach, "detach must follow a successful confine");
    assert!(detach < exec, "exec must follow detach");
}

#[test]
fn helper_and_init_close_the_fault_pipe_then_never_return() {
    let real = read("src/real.rs");
    let detach = slice_fn(&real, "fn detach_into_pid_namespace");
    assert!(detach.contains("close_fault_write(self)"));
    assert!(detach.contains("reap_forever(init)"));
    assert!(detach.contains("reap_forever(provider)"));
    let helper_close = detach.find("close_fault_write(self)").unwrap();
    let helper_reap = detach.find("reap_forever(init)").unwrap();
    assert!(
        helper_close < helper_reap,
        "the helper closes the fault pipe before it waits"
    );
}

#[test]
fn launch_returns_the_first_child_pid() {
    let real = read("src/real.rs");
    let spawn = slice_fn(&real, "fn spawn_confined");
    assert!(
        spawn.contains("return Ok(pid as u32)"),
        "empty fault pipe returns the first fork pid, the helper"
    );
    assert!(
        spawn.contains("if got == 0 && read_error.is_none()"),
        "an empty pipe is treated as a start"
    );
}

#[test]
fn signal_forwarder_omits_sigkill_and_uses_libc_signal() {
    let real = read("src/real.rs");
    let install = slice_fn(&real, "fn install_signal_forwarders");
    assert!(install.contains("libc::SIGTERM"));
    assert!(
        !install.contains("SIGKILL"),
        "SIGKILL cannot be caught; the helper cannot forward it"
    );
    assert!(
        install.contains("libc::signal("),
        "handlers are installed with signal(2), after REAP_CHILD is stored"
    );
}

#[test]
fn seccomp_denies_ptrace_and_allows_kill() {
    let seccomp = read("src/seccomp.rs");
    assert!(seccomp.contains("SYS_ptrace"));
    assert!(seccomp.contains("SYS_process_vm_readv"));
    assert!(
        !seccomp.contains("SYS_kill"),
        "kill is not on the deny-list; a reaper in the host PID ns can call it"
    );
}

fn slice_fn<'a>(src: &'a str, start: &str) -> &'a str {
    let at = src.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let rest = &src[at..];
    let mut depth = 0i32;
    let mut end = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(end > 0, "unbalanced function starting at {start}");
    &rest[..end]
}
