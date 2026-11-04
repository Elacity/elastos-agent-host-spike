//! Linux model-provider socket boundary. The provider and its descendants may
//! create Unix sockets for the private local engine path, but cannot create
//! Internet sockets. Runtime closes all other inherited descriptors on exec.

use std::io;
use tokio::process::Command;

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000 | libc::EPERM as u32;
const CLOSE_RANGE_CLOEXEC: u32 = 4;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(super) fn install_on_command(command: &mut Command) -> io::Result<()> {
    let mut code = vec![
        stmt(LD_W_ABS, 4), // seccomp_data.arch
        jump(JEQ_K, AUDIT_ARCH, 1, 0),
        stmt(RET_K, RET_KILL_PROCESS),
        stmt(LD_W_ABS, 0), // seccomp_data.nr
        jump(JGE_K, 0x4000_0000, 0, 1),
        stmt(RET_K, RET_KILL_PROCESS),
    ];
    for syscall in [libc::SYS_socket, libc::SYS_socketpair] {
        code.extend([
            jump(JEQ_K, syscall as u32, 0, 4),
            stmt(LD_W_ABS, 16), // seccomp_data.args[0], low 32 bits
            jump(JEQ_K, libc::AF_UNIX as u32, 1, 0),
            stmt(RET_K, RET_ERRNO),
            stmt(RET_K, RET_ALLOW),
        ]);
    }
    // These syscalls could create sockets or receive an external descriptor
    // without the socket() gate. Ordinary local HTTP uses read/write instead.
    for syscall in [
        libc::SYS_io_uring_setup,
        libc::SYS_pidfd_getfd,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
    ] {
        code.extend([jump(JEQ_K, syscall as u32, 0, 1), stmt(RET_K, RET_ERRNO)]);
    }
    code.push(stmt(RET_K, RET_ALLOW));
    let length =
        u16::try_from(code.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // All allocation occurs in Runtime before fork. The pre-exec closure only
    // makes raw syscalls and returns an errno if confinement cannot attach.
    unsafe {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let program = libc::sock_fprog {
                len: length,
                filter: code.as_mut_ptr(),
            };
            if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn install_on_command(_: &mut Command) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux model socket confinement is unavailable on this architecture",
    ))
}

#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(target_os = "macos")
))]
mod tests {
    use super::*;

    /// Printed by the filtered probe when its row passes. A child that exits
    /// zero without it exercised nothing and FAILS.
    const PROBE_TOKEN: &str = "elastos-seccomp-row-probe-passed";
    const ROW_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_ROW";
    const TOKEN_ROW: &str = "socket+AF_INET";
    const TOKEN_LINE: &str = "elastos-seccomp-row-probe-passed\n";
    /// Debug only: send each probe's stderr to its token file.
    const PROBE_LOG_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_LOG";
    /// The pid of a plain helper the harness starts beside the filtered probe.
    /// The victim rows call cross-process syscalls on that sibling, so no row
    /// can read its own process or its child instead.
    const VICTIM_PID_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_VICTIM_PID";
    /// The harness pid, keyed into the helper's token path so the harness and
    /// each row read one file.
    const VICTIM_PARENT_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_VICTIM_PARENT";
    /// The helper's published buffer address.
    const VICTIM_ADDRESS_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_VICTIM_ADDRESS";
    /// Set only in the helper process it starts, so a row that inherits the row
    /// variable still names the live sibling.
    const VICTIM_SELF_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_VICTIM_SELF";
    /// Set only for the unfiltered probe in a victim row's sibling control: the
    /// probe runs from the filtered probe's position (a sibling of the helper)
    /// but takes no filter, so its success proves the position can reach the
    /// helper and only the deny entry refuses the filtered row.
    const UNFILTERED_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_UNFILTERED";
    const CONTROL_STDERR: &str = "elastos-seccomp-control-stderr";
    const CONTROL_EXIT: i32 = 7;
    /// On a control child's own command only: it prints `n` bytes, exits [`CONTROL_EXIT`].
    const CONTROL_VAR: &str = "ELASTOS_LINUX_MODEL_SECCOMP_CONTROL";
    /// The test that serves as the helper sibling.
    const VICTIM_TEST: &str =
        "provider::linux_model_seccomp::tests::helper_sibling_serves_the_victim_rows";
    /// The harness test also dispatches a row when `ROW_VAR` is set, before it
    /// touches the test process, so a probe enters its own row there. The probe
    /// runs from the test executable's directory and passes `--`, so libtest
    /// reads no row variable as a name filter and this path selects the test:
    /// a probe that runs no test would pass its row unused.
    const PROBE_TEST_NAME: &str =
        "provider::linux_model_seccomp::tests::every_denied_syscall_and_domain_has_a_row";
    /// The descendant test serves a row that ends in a signal, because a killed
    /// process cannot print the pass token.
    const DESCENDANT_TEST: &str =
        "provider::linux_model_seccomp::tests::child_and_descendant_have_no_inet_sockets";

    /// Expected result of a row: EPERM, a permitted call, or SIGSYS.
    const EPERM: u8 = 0;
    const PERMITTED: u8 = 1;
    const KILLED: u8 = 2;

    thread_local! {
        /// The bytes the last `process_vm` body moved out of its own buffer.
        static BODY_BYTES: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// The helper's published pattern size.
    const PATTERN_LEN: usize = 64;

    /// The row that reads the pattern.
    const READV_ROW: &str = "process_vm_readv sibling";

    /// The row that stores this process's own bytes into the helper's buffer.
    const WRITEV_ROW: &str = "process_vm_writev sibling";

    /// `true` for either `process_vm` row: each returns a byte count.
    fn is_process_vm(name: &str) -> bool {
        name == READV_ROW || name == WRITEV_ROW
    }

    /// `true` for a row that moves bytes into the helper.
    fn is_write(nr: libc::c_long) -> bool {
        nr == libc::SYS_process_vm_writev
    }

    /// A row body is a plain `fn` taking the row's three syscall arguments, so
    /// the table stays a table and no row captures state.
    type Body = fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_long;

    struct Row {
        name: &'static str,
        body: Body,
        domain: libc::c_int,
        kind: libc::c_int,
        protocol: libc::c_int,
        outcome: u8,
    }

    fn errno() -> libc::c_int {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn sys(nr: libc::c_long, a: [libc::c_ulong; 6]) -> libc::c_long {
        unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }
    }

    fn close_all(fds: &[libc::c_int]) {
        for fd in fds {
            unsafe { libc::close(*fd) };
        }
    }

    /// `socket` with the row's own family, type and protocol. Each denied shape
    /// opens on this host without the filter, so only the socket gate can turn
    /// it into EPERM.
    fn socket_body(domain: libc::c_int, kind: libc::c_int, protocol: libc::c_int) -> libc::c_long {
        sys(
            libc::SYS_socket,
            [domain as _, kind as _, protocol as _, 0, 0, 0],
        )
    }

    /// `socketpair` of the row's family, type and protocol. A permitted pair (the
    /// Unix control) is closed again, so the row leaks no descriptor.
    fn socketpair_body(
        domain: libc::c_int,
        kind: libc::c_int,
        protocol: libc::c_int,
    ) -> libc::c_long {
        let mut fds = [-1 as libc::c_int; 2];
        let rc = sys(
            libc::SYS_socketpair,
            [
                domain as _,
                kind as _,
                protocol as _,
                fds.as_mut_ptr() as _,
                0,
                0,
            ],
        );
        if rc >= 0 {
            close_all(&fds);
        }
        rc
    }

    /// A Unix socketpair made in this probe, so a message row reaches the
    /// kernel without a network address.
    fn pair() -> Option<[libc::c_int; 2]> {
        let mut fd = [-1 as libc::c_int; 2];
        let rc = sys(
            libc::SYS_socketpair,
            [
                libc::AF_UNIX as _,
                (libc::SOCK_STREAM | libc::SOCK_NONBLOCK) as _,
                0,
                fd.as_mut_ptr() as _,
                0,
                0,
            ],
        );
        (rc >= 0).then_some(fd)
    }

    /// Header bytes of one message.
    const MMSG_LEN: usize = 64;
    /// The ancillary buffer, in `u64` words so it is word-aligned as
    /// `CMSG_SPACE` asks. `CMSG_SPACE` for one `c_int` is 24 bytes here, so
    /// three words hold one `SCM_RIGHTS` header and its descriptor.
    const CONTROL: usize = 6;
    /// The `MSG_DONTWAIT` flag a queuing send passes to the kernel, so a peer
    /// that cannot take the message answers EAGAIN instead of waiting.
    const MSG_DONTWAIT: u64 = libc::MSG_DONTWAIT as u64;

    /// A whole message in one owner: header bytes, the iovec pointing into
    /// them, and an ancillary buffer with room for one `SCM_RIGHTS`
    /// descriptor. Every pointer is taken from this value inside `send`/`recv`,
    /// so nothing outlives the call.
    struct Messages {
        header: [u8; MMSG_LEN],
        iovec: libc::iovec,
        control: [u64; CONTROL],
        /// The header the syscall uses and, for a batched call, the
        /// one-element array that wraps it.
        hdr: libc::msghdr,
        batch: [libc::mmsghdr; 1],
    }

    impl Messages {
        /// A message of `payload` header bytes, handing over `fd` as a real
        /// `SCM_RIGHTS` control message when it is not negative. A receive
        /// (`fd < 0`) asks for one byte, so it stops after the sent byte.
        fn fill(&mut self, payload: usize, fd: libc::c_int) {
            self.iovec = libc::iovec {
                iov_base: self.header.as_mut_ptr() as _,
                iov_len: payload,
            };
            // Only an earlier receive leaves a header in the leading words;
            // clearing them keeps the next receive's `msg_controllen` honest.
            self.control[..2].fill(0);
            let size = std::mem::size_of::<libc::c_int>();
            // SAFETY: `CMSG_SPACE` is a pure size computation.
            let space = unsafe { libc::CMSG_SPACE(size as _) } as usize;
            if fd >= 0 {
                // A send passes exactly one `CMSG_SPACE`, and its header sits
                // in those leading words: the kernel reads the header and its
                // descriptor there.
                // SAFETY: `control` is word aligned and holds the header and
                // its descriptor.
                unsafe {
                    let cmsg = self.control.as_mut_ptr() as *mut libc::cmsghdr;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(size as _) as _;
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    std::ptr::write(libc::CMSG_DATA(cmsg) as *mut libc::c_int, fd);
                }
            }
            let controllen = if fd >= 0 { space } else { space + space };
            self.iovec.iov_len = payload;
            self.hdr = libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut self.iovec,
                msg_iovlen: 1,
                msg_control: self.control.as_mut_ptr() as _,
                msg_controllen: controllen as _,
                msg_flags: 0,
            };
        }

        /// `true` when the received control space holds exactly one
        /// `SCM_RIGHTS` message carrying one descriptor.
        fn received_rights(&self) -> bool {
            // SAFETY: `hdr.msg_control` points at `control` for this value.
            unsafe {
                // Only the receive's own `msg_controllen` says whether the
                // kernel wrote a header here: a previous call may have left
                // bytes in this buffer.
                let cmsg = libc::CMSG_FIRSTHDR(&self.hdr);
                self.hdr.msg_controllen >= std::mem::size_of::<libc::cmsghdr>()
                    && !cmsg.is_null()
                    && (*cmsg).cmsg_level == libc::SOL_SOCKET
                    && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                    && (*cmsg).cmsg_len
                        == libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as usize
            }
        }

        /// `sendmsg`, or `sendmmsg` on a one-element `mmsghdr` array.
        /// `flags` is `MSG_DONTWAIT` for a queuing send, so a peer that cannot
        /// take the message answers EAGAIN instead of waiting.
        fn send(&mut self, sock: libc::c_int, batched: bool, flags: u64) -> libc::c_long {
            self.hdr.msg_iov = &mut self.iovec;
            if batched {
                self.batch[0] = libc::mmsghdr {
                    msg_hdr: self.hdr,
                    msg_len: 0,
                };
                let rc = sys(
                    libc::SYS_sendmmsg,
                    [sock as _, self.batch.as_mut_ptr() as _, 1, flags, 0, 0],
                );
                self.hdr = self.batch[0].msg_hdr;
                rc
            } else {
                sys(
                    libc::SYS_sendmsg,
                    [sock as _, &mut self.hdr as *mut _ as _, flags, 0, 0, 0],
                )
            }
        }

        /// `recvmsg`, or `recvmmsg` on a one-element `mmsghdr` array, which is
        /// where the kernel buffers the received message. The caller's socket
        /// is non-blocking and `flags` carries `MSG_DONTWAIT`, so a receive
        /// never waits for a peer.
        fn recv(&mut self, sock: libc::c_int, batched: bool, flags: u64) -> libc::c_long {
            // `fill` set the receive iovec; the header holds the whole queued
            // message and a descriptor's header.
            self.iovec.iov_len = MMSG_LEN;
            self.iovec.iov_base = self.header.as_mut_ptr() as _;
            self.hdr.msg_iov = &mut self.iovec;
            if batched {
                self.batch[0] = libc::mmsghdr {
                    msg_hdr: self.hdr,
                    msg_len: 0,
                };
                let rc = sys(
                    libc::SYS_recvmmsg,
                    [sock as _, self.batch.as_mut_ptr() as _, 1, flags, 0, 0],
                );
                self.hdr = self.batch[0].msg_hdr;
                self.hdr.msg_control = self.control.as_mut_ptr() as _;
                rc
            } else {
                sys(
                    libc::SYS_recvmsg,
                    [sock as _, &mut self.hdr as *mut _ as _, flags, 0, 0, 0],
                )
            }
        }
    }

    /// One empty message with `MMSG_LEN` bytes of header space.
    fn message() -> Messages {
        Messages {
            header: [0u8; MMSG_LEN],
            iovec: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            control: [0u64; CONTROL],
            hdr: unsafe { std::mem::zeroed() },
            batch: [unsafe { std::mem::zeroed() }],
        }
    }

    /// A send row sends one descriptor-bearing header byte from a pair the probe opens, so only the filter can refuse it.
    fn sendmsg_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        send_message(false)
    }

    /// Sends on `sock`, handing over `fd` when it is `Some`.
    fn sending(sock: libc::c_int, batched: bool, fd: Option<libc::c_int>) -> libc::c_long {
        let mut messages = message();
        messages.fill(1, fd.unwrap_or(-1));
        messages.send(sock, batched, MSG_DONTWAIT)
    }

    /// One `sendmsg`, or `sendmmsg` when `batched`, of one descriptor-bearing
    /// header byte on a socketpair opened inside the probe, so only the filter
    /// can refuse the call; `MSG_DONTWAIT` means the peer answers EAGAIN rather
    /// than waiting.
    fn send_message(batched: bool) -> libc::c_long {
        let Some(fd) = pair() else {
            return -1;
        };
        let sender = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let rc = sending(fd[0], batched, Some(sender));
        close_all(&[sender]);
        close_all(&fd);
        rc
    }

    /// The unfiltered control for a receive row: one `recvmsg`, or `recvmmsg` on
    /// a one-element `mmsghdr` array, whose peer sends one descriptor-bearing
    /// message. It proves the same call answers with the descriptor its peer
    /// sent, so only the filter can refuse the row.
    fn recv_control(fd: libc::c_int, batched: bool) -> libc::c_long {
        let mut messages = message();
        messages.fill(1, -1);
        let rc = messages.recv(fd, batched, 0);
        assert!(
            rc == 1 && messages.received_rights(),
            "control lost SCM_RIGHTS: rc {rc}, errno {}",
            errno()
        );
        rc
    }

    fn sendmmsg_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        send_message(true)
    }

    /// A receive row queues one byte from its own pair's far end and calls
    /// `recvmsg`, or `recvmmsg` when `batched` is set. `sendmsg` is on the deny
    /// list too, so the byte goes through `sendto`. The body returns the call's
    /// own `rc`, and its errno is the one the call left: `check` then reads the
    /// receive's answer, not a constant. A filtered call is the EPERM the
    /// filter returns; an unfiltered call reads the queued byte, so only the
    /// filter can refuse this row.
    fn recv_body(batched: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        let fd = pair().expect("row socketpair");
        let _ = sys(
            libc::SYS_sendto,
            [fd[1] as _, [b'x'].as_ptr() as _, 1, 0, 0, 0],
        );
        let mut messages = message();
        messages.fill(1, -1);
        let rc = messages.recv(fd[0], batched != 0, libc::MSG_CMSG_CLOEXEC as u64);
        // `close_all` would leave its own errno for `check` to read, so the
        // receive's errno is put back after the descriptors are closed.
        let err = errno();
        close_all(&fd);
        // SAFETY: `__errno_location` is this thread's errno cell.
        unsafe { *libc::__errno_location() = err };
        rc
    }

    fn io_uring_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        // An all-zero `io_uring_params` (zero entries) is a valid request, so
        // an unfiltered host answers with a ring descriptor and only the deny
        // entry can refuse it. That descriptor is closed here.
        let mut params = [0u8; 120];
        let rc = sys(
            libc::SYS_io_uring_setup,
            [1, params.as_mut_ptr() as _, 0, 0, 0, 0],
        );
        if rc > 2 {
            close_all(&[rc as libc::c_int]);
        }
        rc
    }

    /// `getpid` must stay permitted: the filter denies by number, not by class.
    fn getpid_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        sys(libc::SYS_getpid, [0; 6])
    }

    /// The x32 boundary: `nr >= 0x40000000` must be killed, not mapped onto the
    /// low x86_64 syscall that shares its low 32 bits.
    fn x32_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        sys(0x4000_0000, [0; 6])
    }

    /// The helper sibling the victim rows act on. A row with no pid fails by
    /// name, so a row run without a live sibling cannot pass.
    fn victim_pid() -> libc::pid_t {
        std::env::var(VICTIM_PID_VAR)
            .ok()
            .and_then(|pid| pid.parse().ok())
            .unwrap_or_else(|| panic!("row has no live helper pid in {VICTIM_PID_VAR}"))
    }

    /// The helper's own buffer address.
    fn victim_address() -> usize {
        std::env::var(VICTIM_ADDRESS_VAR)
            .ok()
            .and_then(|address| address.parse().ok())
            .unwrap_or_else(|| panic!("row has no helper buffer in {VICTIM_ADDRESS_VAR}"))
    }

    /// The cross-process calls the deny list refuses: each names the helper
    /// sibling, never this process or its own child.
    fn pidfd_getfd_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        let pid = victim_pid();
        let pidfd = sys(libc::SYS_pidfd_open, [pid as _, 0, 0, 0, 0, 0]);
        if pidfd < 0 {
            panic!("pidfd_open on helper {pid} failed: errno {}", errno());
        }
        // `pidfd_open` is permitted by the filter, so this row proves the
        // `pidfd_getfd` deny entry alone.
        let borrowed = sys(libc::SYS_pidfd_getfd, [pidfd as _, 0, 0, 0, 0, 0]);
        let failed = errno();
        // The borrowed descriptor stays open in the unfiltered sibling
        // control, so that call really borrows from the helper. A negative
        // pidfd fails both positions and would make the control prove nothing.
        if std::env::var_os(UNFILTERED_VAR).is_none() || borrowed < 0 {
            close_all(&[pidfd as libc::c_int]);
        }
        // The control checks the borrowed descriptor is a real fd. A filtered
        // probe never gets here with one: the filter answers EPERM. `close_all`
        // leaves its own errno, so the call's errno is restored for the check.
        if borrowed >= 0 && std::env::var_os(UNFILTERED_VAR).is_none() {
            close_all(&[borrowed as libc::c_int]);
        }
        unsafe { *libc::__errno_location() = failed };
        borrowed
    }

    /// An `iovec` over a whole buffer.
    fn iovec(base: *mut u8, len: usize) -> libc::iovec {
        libc::iovec {
            iov_base: base as _,
            iov_len: len,
        }
    }

    /// Byte `i` of the pattern holds `i + 1`.
    fn pattern_bytes() -> Vec<u8> {
        (1..=PATTERN_LEN as u8).collect()
    }

    /// The write row's bytes: 201..=255 then 0..=8, unlike any read pattern.
    fn write_bytes() -> Vec<u8> {
        (201..=255).chain(0..=8).collect()
    }

    fn check_write(got: &[u8], expected: &[u8], wrong: &str) {
        assert_eq!(
            got.len(),
            PATTERN_LEN,
            "process_vm_writev control sent {} bytes, expected {PATTERN_LEN}",
            got.len()
        );
        if let Some(index) = got
            .iter()
            .zip(expected)
            .position(|(read, want)| read != want)
        {
            panic!(
                "process_vm_writev control {wrong} at byte {}: expected {}, read {}",
                index + 1,
                expected[index],
                got[index]
            );
        }
    }

    /// Checks a whole read of the pattern.
    fn check_pattern(got: &[u8]) {
        assert_eq!(
            got.len(),
            PATTERN_LEN,
            "process_vm_readv control moved {} bytes, expected {PATTERN_LEN}",
            got.len()
        );
        let expected = pattern_bytes();
        if let Some(index) = got
            .iter()
            .zip(&expected)
            .position(|(read, want)| read != want)
        {
            panic!(
                "process_vm_readv control read bytes 1..={PATTERN_LEN} of the wrong memory: byte {} expected {}, read {}",
                index + 1,
                expected[index],
                got[index]
            );
        }
    }

    /// Reads the helper's buffer here.
    fn process_vm_readv_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        process_vm_body(libc::SYS_process_vm_readv)
    }

    /// The helper's buffer, written here: only the filter can refuse it.
    fn process_vm_writev_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        process_vm_body(libc::SYS_process_vm_writev)
    }

    fn process_vm_pattern_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        process_vm_transfer(libc::SYS_process_vm_writev, &pattern_bytes())
    }

    /// One whole `PATTERN_LEN` transfer: a read fills this process's bytes, a
    /// write sends them to the helper.
    fn process_vm_body(nr: libc::c_long) -> libc::c_long {
        let sent = if is_write(nr) {
            write_bytes()
        } else {
            pattern_bytes()
        };
        process_vm_transfer(nr, &sent)
    }

    /// One whole transfer of `sent` with the helper's buffer on the remote
    /// side, and this process's buffer published for its control.
    fn process_vm_transfer(nr: libc::c_long, sent: &[u8]) -> libc::c_long {
        let pid = victim_pid();
        let mut local = [0u8; PATTERN_LEN];
        if is_write(nr) {
            local.copy_from_slice(sent);
        }
        let mut remote = iovec(victim_address() as *mut u8, PATTERN_LEN);
        let mut here = iovec(local.as_mut_ptr(), PATTERN_LEN);
        let rc = sys(
            nr,
            [
                pid as _,
                &mut here as *mut _ as _,
                1,
                &mut remote as *mut _ as _,
                1,
                0,
            ],
        );
        let moved = if rc == PATTERN_LEN as libc::c_long {
            PATTERN_LEN
        } else {
            0
        };
        BODY_BYTES.with(|bytes| *bytes.borrow_mut() = local[..moved].to_vec());
        if rc >= 0 {
            // A short transfer is the control's own failure.
            assert_eq!(
                rc,
                PATTERN_LEN as libc::c_long,
                "process_vm control nr {nr} moved {rc} bytes, errno {}",
                errno()
            );
        }
        rc
    }

    /// This process's bytes as the last body left them.
    fn body_bytes() -> Vec<u8> {
        BODY_BYTES.with(|bytes| bytes.borrow().clone())
    }

    /// Each denied family through `socket`, the Unix controls through both
    /// creators, the four message syscalls the deny list refuses, `getpid` and
    /// the x32 boundary. Each entry is its own probe run, so a removed deny
    /// entry turns exactly that row red. A receive row runs its own call on its
    /// own socketpair, so only the filter can refuse it.
    #[rustfmt::skip]
    fn rows() -> Vec<Row> {
        let row = |name, body, domain, kind, protocol, outcome| Row {
            name,
            body,
            domain,
            kind,
            protocol,
            outcome,
        };
        let (tcp, raw) = (libc::SOCK_STREAM, libc::SOCK_RAW);
        vec![
            row("socket+AF_INET", socket_body, libc::AF_INET, tcp, libc::IPPROTO_TCP, EPERM),
            row("sendmsg+SCM_RIGHTS", sendmsg_body, 0, 0, 0, EPERM),
            row("recvmsg+cmsg", recv_body, 0, 0, 0, EPERM),
            row("socket+AF_INET6", socket_body, libc::AF_INET6, tcp, libc::IPPROTO_TCP, EPERM),
            row("socket+AF_NETLINK", socket_body, libc::AF_NETLINK, raw, 0, EPERM),
            row("socket+AF_UNIX", socket_body, libc::AF_UNIX, tcp, 0, PERMITTED),
            row("socketpair+AF_UNIX", socketpair_body, libc::AF_UNIX, tcp, 0, PERMITTED),
            row("sendmmsg+SCM_RIGHTS", sendmmsg_body, 0, 0, 0, EPERM),
            row("recvmmsg+cmsg", recv_body, 1, 0, 0, EPERM),
            row("io_uring_setup", io_uring_body, 0, 0, 0, EPERM),
            row("pidfd_getfd sibling", pidfd_getfd_body, 0, 0, 0, EPERM),
            row(READV_ROW, process_vm_readv_body, 0, 0, 0, EPERM),
            row(WRITEV_ROW, process_vm_writev_body, 0, 0, 0, EPERM),
            row("getpid", getpid_body, 0, 0, 0, PERMITTED),
            row("nr==0x40000000", x32_body, 0, 0, 0, KILLED),
        ]
    }

    fn check(name: &str, outcome: u8, rc: libc::c_long) {
        match outcome {
            EPERM => {
                assert_eq!(rc, -1, "row {name}: expected -1, got {rc}");
                assert_eq!(
                    errno(),
                    libc::EPERM,
                    "row {name}: expected EPERM, got errno {}",
                    errno()
                );
            }
            PERMITTED => assert!(
                rc >= 0,
                "row {name}: expected a permitted call, got {rc} (errno {})",
                errno()
            ),
            _ => panic!("row {name}: returned {rc}, expected SIGSYS"),
        }
    }

    /// Runs one named row in the filtered probe.
    fn probe(wanted: &str) {
        // The unfiltered sibling control takes no filter on purpose.
        let unfiltered = std::env::var_os(UNFILTERED_VAR).is_some();
        if !unfiltered {
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) },
                2,
                "the model filter was not attached"
            );
            // The probe runs under install_on_command, which sets no_new_privs
            // before attaching the filter.
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
                1
            );
        }
        let row = rows()
            .into_iter()
            .find(|row| row.name == wanted)
            .unwrap_or_else(|| panic!("row {wanted} was not requested by the harness"));
        let rc = (row.body)(row.domain, row.kind, row.protocol);
        if unfiltered {
            // The control expects the whole call to work here: a refusal of
            // the position (Yama, for example) fails loudly, never skips; the
            // errno is read before any other call.
            let failed = errno();
            let moved = if is_process_vm(wanted) {
                rc == PATTERN_LEN as libc::c_long
            } else {
                rc >= 0
            };
            assert!(
                moved && rc >= row.outcome as libc::c_long,
                "unfiltered sibling control for row {wanted}: rc {rc}, errno {failed}"
            );
            // A real descriptor; the `process_vm` rows return a byte count.
            if rc > 2 && !is_process_vm(wanted) {
                close_all(&[rc as libc::c_int]);
            }
            // This buffer was filled before the call, so a no-op differs.
            let buffer = body_bytes();
            if wanted == READV_ROW {
                check_pattern(&buffer);
            } else if wanted == WRITEV_ROW {
                check_write(&buffer, &write_bytes(), "sent");
            }
            // Set on a test's own control child only.
            planted_control();
        } else {
            check(row.name, row.outcome, rc);
        }
        println!("{PROBE_TOKEN} {}", row.name);
    }

    #[tokio::test]
    async fn child_and_descendant_have_no_inet_sockets() {
        let name = DESCENDANT_TEST;
        let executable = std::env::current_exe().unwrap();
        // A signal row runs here: the harness proves the filter.
        if let Ok(row) = std::env::var(ROW_VAR) {
            probe(&row);
            return;
        }
        if let Ok(stage) = std::env::var("ELASTOS_LINUX_MODEL_SECCOMP_PROBE") {
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
                1
            );
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }, 2);
            for domain in [libc::AF_INET, libc::AF_INET6] {
                let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
                assert_eq!(fd, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            }
            let unix = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            assert!(unix >= 0);
            unsafe { libc::close(unix) };
            if stage == "child" {
                let output = std::process::Command::new(&executable)
                    .arg("--exact")
                    .arg(name)
                    .arg("--nocapture")
                    .env("ELASTOS_LINUX_MODEL_SECCOMP_PROBE", "descendant")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("descendant-probe-ok"),
                    "{}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            println!("{stage}-probe-ok");
            return;
        }
        let mut command = Command::new(executable);
        command
            .arg("--exact")
            .arg(name)
            .arg("--nocapture")
            .env("ELASTOS_LINUX_MODEL_SECCOMP_PROBE", "child")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        install_on_command(&mut command).unwrap();
        let output = command.output().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("child-probe-ok"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// Reaps one probe child without blocking the runtime thread and kills it
    /// at `limit`, so a probe stuck in a permitted syscall fails by name. The
    /// child stays owned by the caller, so its stdout pipe survives the wait.
    async fn run_probe(
        child: &mut tokio::process::Child,
        limit: std::time::Duration,
    ) -> Option<std::process::ExitStatus> {
        // The limit runs on the wall clock, so a paused runtime clock cannot
        // stop a probe that never returns from reaching it.
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("probe wait failed") {
                return Some(status);
            }
            if start.elapsed() > limit {
                let _ = child.start_kill();
                return child.wait().await.ok();
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// A row's token file, opened before the fork; `tag` keeps two runs apart.
    fn probe_token(tag: &str, name: &str) -> std::path::PathBuf {
        let safe: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        std::env::temp_dir().join(format!("field-probe-{}-{tag}-{safe}", std::process::id()))
    }

    /// The token file one child writes.
    fn token_file(tag: &str, name: &str) -> std::fs::File {
        std::fs::File::create(probe_token(tag, name)).expect("token")
    }

    /// One tag per control: no two controls share a token file.
    fn next_tag() -> u64 {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Where the helper publishes its readiness line, keyed by the harness pid
    /// and the helper pid, so the harness and the helper name one file. The
    /// harness passes its own `process::id()`; the helper reads it from
    /// `VICTIM_PARENT_VAR`. A missing variable is a failure, never a silent
    /// `getppid()` fallback, because the helper's parent is not the harness.
    fn victim_token(parent: libc::pid_t, pid: libc::pid_t) -> std::path::PathBuf {
        tagged_victim_token(&parent.to_string(), pid)
    }

    fn tagged_victim_token(tag: &str, pid: libc::pid_t) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("elastos-row-victim-{tag}-{pid}"))
    }

    /// The harness pid a helper process was given in `VICTIM_PARENT_VAR`.
    fn victim_parent() -> libc::pid_t {
        std::env::var(VICTIM_PARENT_VAR)
            .ok()
            .and_then(|parent| parent.parse().ok())
            .unwrap_or_else(|| panic!("helper has no harness pid in {VICTIM_PARENT_VAR}"))
    }

    /// Reads the helper's readiness line, then unlinks the file: the open
    /// descriptor is the file the check and the read share, so no path is
    /// re-resolved after the check. The helper writes the line once, through a
    /// rename, so a poll reads a whole line or no file. Only a file that is not
    /// there yet is a retry: every other cause fails here, by name, with the
    /// text it read, because the next poll would otherwise report a missing
    /// publication after a publication was already consumed. A line that names
    /// another pid, lacks the address, or carries an address of zero fails.
    fn read_readiness(token: &std::path::Path, pid: libc::pid_t) -> Option<usize> {
        let file = match std::fs::File::open(token) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("readiness token {token:?} did not open: {error}"),
        };
        // The opened file is the one this read and the unlink name, so no path
        // is re-resolved after the check.
        let _ = std::fs::remove_file(token);
        let mut file = file;
        let mut text = String::new();
        if let Err(error) = std::io::Read::read_to_string(&mut file, &mut text) {
            panic!("readiness token {token:?} did not read: {error}");
        }
        let mut fields = text.split_whitespace();
        let named = match fields.next() {
            Some(field) => field.parse().ok(),
            None => panic!("readiness line {text:?} is empty"),
        };
        assert_eq!(
            named,
            Some(pid),
            "readiness line {text:?} is not helper {pid}"
        );
        let address = match fields.next() {
            Some(field) => match field.parse::<usize>() {
                Ok(address) => address,
                Err(error) => panic!("readiness line {text:?} has no address: {error}"),
            },
            None => panic!("readiness line {text:?} has no address field"),
        };
        assert!(
            address != 0,
            "readiness line {text:?} publishes address zero"
        );
        Some(address)
    }

    /// `true` for a row that acts on the helper sibling.
    fn is_victim(name: &str) -> bool {
        name.ends_with(" sibling")
    }

    /// A plain helper the harness starts beside the filtered probe: the test
    /// executable re-entered as `VICTIM_TEST`, which publishes its pid in its
    /// token file. It holds no filter, so the control can act on it, and the
    /// harness kills and reaps it on every path.
    struct Victim {
        pid: libc::pid_t,
        address: usize,
        /// `process::Child` owns the wait and the kill.
        child: std::process::Child,
    }

    impl Victim {
        /// Starts the helper and waits for its first publication. The helper
        /// exits by itself after 120 s, so a lost harness cannot leave it
        /// running.
        fn start() -> Victim {
            let child =
                std::process::Command::new(std::env::current_exe().expect("test executable path"))
                    .arg("--exact")
                    .arg(VICTIM_TEST)
                    .arg("--nocapture")
                    .env(VICTIM_SELF_VAR, "")
                    .env(VICTIM_PARENT_VAR, std::process::id().to_string())
                    // The helper holds fd 0, the only cheap descriptor the
                    // filter permits the probe to open a pidfd for, so the row
                    // borrows a real descriptor and never fails on EBADF.
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .expect("helper sibling did not start");
            let pid = child.id() as libc::pid_t;
            let mut victim = Victim {
                pid,
                address: 0,
                child,
            };
            let token = victim_token(std::process::id() as libc::pid_t, pid);
            let start = std::time::Instant::now();
            // Only a publication that is not there yet is retried; every other
            // cause fails inside `read_readiness` with its own text.
            loop {
                if let Some(address) = read_readiness(&token, pid) {
                    victim.address = address;
                    break;
                }
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(30),
                    "helper sibling published no readiness line: token {:?} parent {} child {:?}",
                    token,
                    std::process::id(),
                    victim.child.try_wait()
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            victim
        }
    }

    impl Drop for Victim {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// The unfiltered control for a victim row: the same call against the same
    /// helper, made by this unfiltered process, must succeed, so only the
    /// filter can refuse the probe's call.
    fn victim_control(victim: &Victim, row: &Row) {
        if is_process_vm(row.name) {
            process_vm_control(victim, row);
            return;
        }
        let previous_pid = std::env::var(VICTIM_PID_VAR).ok();
        std::env::set_var(VICTIM_PID_VAR, victim.pid.to_string());
        let rc = (row.body)(0, 0, 0);
        let failed = errno();
        match previous_pid {
            Some(value) => std::env::set_var(VICTIM_PID_VAR, value),
            None => std::env::remove_var(VICTIM_PID_VAR),
        }
        assert!(
            rc >= 0,
            "row {} is not valid unfiltered: rc {rc}, errno {failed}",
            row.name
        );
        if rc > 2 {
            close_all(&[rc as libc::c_int]);
            unsafe { *libc::__errno_location() = failed };
        }
    }

    /// The `process_vm_readv` control: the body returns the whole pattern, so
    /// no descriptor is involved.
    fn process_vm_control(victim: &Victim, row: &Row) {
        with_victim(victim, || {
            let rc = (row.body)(0, 0, 0);
            let failed = errno();
            assert_eq!(
                rc, PATTERN_LEN as libc::c_long,
                "row {} is not valid unfiltered: rc {rc}, errno {failed}",
                row.name
            );
            check_pattern(&body_bytes());
        });
    }

    /// The `process_vm_writev` control: pattern, then the row's own bytes.
    fn check_write_control(row: &Row) {
        let victim = Victim::start();
        pattern_control(&victim);
        write_control_writes(&victim, row, &write_bytes());
    }

    /// The write body on `victim`, then its own published bytes.
    fn write_control_writes(victim: &Victim, row: &Row, sent: &[u8]) {
        with_victim(victim, || {
            let rc = (row.body)(0, 0, 0);
            let failed = errno();
            assert_eq!(
                rc, PATTERN_LEN as libc::c_long,
                "row {} is not valid unfiltered: rc {rc}, errno {failed}",
                row.name
            );
            // The helper's buffer is read back below, not only this side's.
            check_write(&body_bytes(), sent, "sent");
        });
        let got = victim_report(victim);
        check_write(&got, sent, "wrote");
    }

    /// Sets the helper variables around one call, then restores them.
    fn with_victim<T>(victim: &Victim, call: impl FnOnce() -> T) -> T {
        let previous_pid = std::env::var(VICTIM_PID_VAR).ok();
        let previous_address = std::env::var(VICTIM_ADDRESS_VAR).ok();
        // Post what the harness posts; the body reads the environment.
        std::env::set_var(VICTIM_PID_VAR, victim.pid.to_string());
        std::env::set_var(VICTIM_ADDRESS_VAR, victim.address.to_string());
        let out = call();
        for (name, previous) in [
            (VICTIM_PID_VAR, previous_pid),
            (VICTIM_ADDRESS_VAR, previous_address),
        ] {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        out
    }

    /// The helper's published bytes, read until they are not the pattern, from
    /// where a helper this process started publishes its buffer. Victim stays
    /// as #1394 merged it (Rong 0935), so a killed run leaves this file.
    fn victim_report(victim: &Victim) -> Vec<u8> {
        let path =
            victim_token(std::process::id() as libc::pid_t, victim.pid).with_extension("report");
        let _ = std::fs::remove_file(&path);
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(5) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let bytes: Vec<u8> = text
                    .split_whitespace()
                    .map(|byte| byte.parse().expect("helper report byte"))
                    .collect();
                if bytes.first() != pattern_bytes().first() {
                    return bytes;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("helper published no written report in {path:?}");
    }

    /// Puts the pattern back after a write control.
    fn restores_pattern(victim: &Victim) {
        with_victim(victim, || {
            let rc = process_vm_pattern_body(0, 0, 0);
            let failed = errno();
            assert_eq!(
                rc, PATTERN_LEN as libc::c_long,
                "pattern restore rc {rc}, errno {failed}"
            );
        });
    }

    /// Reads the helper's bytes at the published address and checks them.
    fn pattern_control(victim: &Victim) {
        let mut got = [0u8; PATTERN_LEN];
        let l = libc::iovec {
            iov_base: got.as_mut_ptr().cast(),
            iov_len: got.len(),
        };
        let r = libc::iovec {
            iov_base: victim.address as *mut _,
            iov_len: got.len(),
        };
        let io = [&l as *const _, &r as *const _];
        let read = sys(
            libc::SYS_process_vm_readv,
            [victim.pid as _, io[0] as _, 1, io[1] as _, 1, 0],
        );
        let failed = errno();
        if read != PATTERN_LEN as libc::c_long {
            panic!(
                "helper pattern at {} unreadable: read {read}, errno {failed}",
                victim.address
            );
        }
        check_pattern(&got);
    }

    /// The helper served by `VICTIM_TEST`. Without the flag it is a plain test.
    /// With it the helper publishes its pid once through a rename, then sleeps
    /// until the harness ends it; that line is the readiness line.
    #[test]
    fn helper_sibling_serves_the_victim_rows() {
        if std::env::var(VICTIM_SELF_VAR).is_err() {
            return;
        }
        let pid = std::process::id() as libc::pid_t;
        let mut pattern = std::hint::black_box(vec![0u8; 64]);
        for (i, byte) in pattern.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        // pidfd_getfd needs ptrace-attach access. The probe is a sibling, not
        // an ancestor, so Yama scope 1 (the Jetson) refuses it. Allow any
        // tracer: test fixture only. A host without Yama answers EINVAL.
        let permitted =
            unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0) };
        assert!(
            permitted == 0 || errno() == libc::EINVAL,
            "helper PR_SET_PTRACER failed: errno {}",
            errno()
        );
        let token = victim_token(victim_parent(), pid);
        let staging = token.with_extension("tmp");
        std::fs::write(
            &staging,
            format!("{pid} {}\n", pattern.as_mut_ptr() as usize),
        )
        .expect("helper publication");
        std::fs::rename(&staging, &token).expect("helper publication rename");
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(120) {
            let report = token.with_extension("report");
            let staging = token.with_extension("report.tmp");
            let bytes: Vec<String> = pattern.iter().map(|byte| byte.to_string()).collect();
            std::fs::write(&staging, bytes.join(" ")).expect("helper report");
            std::fs::rename(&staging, &report).expect("helper report rename");
            // Rename leaves nothing, but a helper killed between the two
            // steps would otherwise leave the staging file behind.
            let _ = std::fs::remove_file(&staging);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Spawns one filtered probe child for a row command.
    fn spawn_row(command: &mut Command) -> tokio::process::Child {
        command.spawn().expect("probe child did not start")
    }

    /// The pass rule for a row that ends by exit: it exits zero and its token
    /// file holds the pass token. A child that exits zero without the token
    /// exercised nothing. A refusal has already emptied the file at the fork,
    /// so it reads no pass; the token is removed before every return.
    fn row_result(tag: &str, name: &str, success: bool) -> Result<(), String> {
        let path = probe_token(tag, name);
        let stdout = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(path);
        if !success {
            return Err(format!("row {name} failed"));
        }
        if stdout.contains(PROBE_TOKEN) {
            Ok(())
        } else {
            Err(format!("row {name}: no pass token"))
        }
    }

    /// Runs one row's probe to its end: a killed row ends in SIGSYS and any
    /// other row exits zero with its pass token written.
    async fn finish_probe(
        tag: &str,
        name: &str,
        row: &Row,
        child: &mut tokio::process::Child,
    ) -> Option<String> {
        let deadline = std::time::Duration::from_secs(20);
        let result: Result<(), String> = match (run_probe(child, deadline).await, row.outcome) {
            (None, _) => Err(format!("row {name}: probe child did not finish")),
            (Some(status), KILLED) => {
                use std::os::unix::process::ExitStatusExt as _;
                if status.signal() == Some(libc::SIGSYS) {
                    Ok(())
                } else {
                    Err(format!("row {name}: expected SIGSYS, status {status:?}"))
                }
            }
            // The child must also prove it exercised the row.
            (Some(status), _) => row_result(tag, name, status.success()),
        };
        result.err()
    }

    /// Harness half: each row runs in its own filtered child through
    /// `install_on_command`, and one row's failure keeps the others reporting
    /// their own name. A row that exits zero without printing the pass token
    /// fails, so a probe that never exercised its syscall cannot pass. A probe
    /// child reaches its row here, before this test touches the test process or
    /// spawns a child, so it never re-enters a check on its parent's state.
    #[tokio::test]
    async fn every_denied_syscall_and_domain_has_a_row() {
        if let Ok(row) = std::env::var(ROW_VAR) {
            probe(&row);
            return;
        }
        // `run_probe` measures with the wall clock, so a sleeping row still
        // reaches its limit.
        let all = rows();
        // The victim rows act on a plain sibling of the filtered probe, so the
        // subject of the call is a real process with its own address space and
        // descriptors. The sibling ends with this test on every path.
        let victim = all
            .iter()
            .any(|row| is_victim(row.name))
            .then(Victim::start);
        let total = all.len();
        let mut failures = Vec::new();
        let tag = next_tag().to_string();
        // Victim rows also get one unfiltered sibling control each; their
        // failures are separate lines, never new rows in `rows()`.
        let mut defects = Vec::new();
        let controls = all.iter().filter(|row| is_victim(row.name)).count();
        // Control: every row's body answers without the filter, so only the
        // filter can refuse it. A send row answers a peer with no reader with
        // EAGAIN, and a receive row reads a message its own pair carries. Each
        // receive row's own body must also read its queued byte. The SIGSYS
        // row is killed before any unfiltered call can run. The victim row's
        // control borrows the helper's pid and gets a real descriptor back.
        for row in &all {
            if is_victim(row.name) {
                // The victim row runs once unfiltered here and once in its own
                // filtered probe below: only the filter can refuse it.
                let helper = victim.as_ref().expect("a victim row starts the helper");
                if row.name == WRITEV_ROW {
                    // This control stores other bytes: its own helper.
                    check_write_control(row);
                } else {
                    victim_control(helper, row);
                }
                continue;
            }
            // A receive row's control queues one descriptor-bearing message on
            // a pair of its own, so only the filter can refuse the same call.
            let receive = matches!(row.name, "recvmsg+cmsg" | "recvmmsg+cmsg");
            let rc = if receive {
                let fd = pair().expect("control socketpair");
                let descriptor = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
                let mut queued = message();
                queued.fill(1, descriptor);
                let sent = queued.send(fd[1], false, MSG_DONTWAIT);
                let received = recv_control(fd[0], row.name == "recvmmsg+cmsg");
                close_all(&[fd[0], fd[1], descriptor]);
                assert_eq!(sent, 1, "control queued no message: errno {}", errno());
                // The row's own body also runs unfiltered: it queues a byte on
                // a pair of its own, so it must read that byte (rc >= 0) and
                // only the filter can refuse the same call.
                let own = (row.body)(row.domain, row.kind, row.protocol);
                assert!(
                    own >= 0,
                    "row {} is not valid unfiltered: body rc {own}, errno {}",
                    row.name,
                    errno()
                );
                received
            } else {
                (row.body)(row.domain, row.kind, row.protocol)
            };
            // Only a descriptor the kernel returned is closed: a body that
            // reports success as 0 is not handing back fd 0, and closing it
            // would take this process's own stdin, then its stdout.
            if rc > 2 {
                unsafe { libc::close(rc as libc::c_int) };
            }
            assert!(
                rc >= 0 || errno() == libc::EAGAIN || errno() == libc::ENOSYS,
                "row {} is not valid unfiltered: {rc}, errno {}",
                row.name,
                errno()
            );
        }
        for row in all {
            let name = row.name;
            // A victim row's filtered probe is a sibling of the helper, so its
            // control runs from that same position without a filter. A
            // position the host refuses (Yama scope 1 for a non-ancestor) then
            // fails here by name instead of passing the row vacuously.
            if is_victim(name) {
                let run = sibling_control(victim.as_ref().expect("helper"), &row, "").await;
                if let Err(failure) = run {
                    defects.push(failure);
                }
            }
            // The descendant test serves the row that ends in a signal.
            let filter = match row.outcome {
                KILLED => DESCENDANT_TEST,
                _ => PROBE_TEST_NAME,
            };
            let mut command = Command::new(std::env::current_exe().expect("test executable path"));
            command
                .arg("--exact")
                .arg(filter)
                .arg("--nocapture")
                .env(ROW_VAR, row.name)
                .stdout(std::process::Stdio::from(token_file(&tag, row.name)));
            if is_victim(name) {
                let helper = victim.as_ref().expect("a victim row starts the helper");
                command
                    .env(VICTIM_PID_VAR, helper.pid.to_string())
                    .env(VICTIM_ADDRESS_VAR, helper.address.to_string());
            }
            if let Ok(path) = std::env::var(PROBE_LOG_VAR) {
                command
                    .stdout(std::process::Stdio::from(
                        std::fs::OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(probe_token(&tag, name))
                            .expect("probe log file"),
                    ))
                    .stderr(std::process::Stdio::from(
                        std::fs::OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(&path)
                            .expect("probe log file"),
                    ));
            } else {
                command.stderr(std::process::Stdio::null());
            }
            install_on_command(&mut command).expect("filter attach failed");
            let mut child = spawn_row(&mut command);
            if let Some(failure) = finish_probe(&tag, name, &row, &mut child).await {
                failures.push(failure);
            }
            // A killed row reads no token, so this side removes it.
            let _ = std::fs::remove_file(probe_token(&tag, name));
        }
        println!("ROWS: {total} checked, {} failed", failures.len());
        println!(
            "SIBLING CONTROLS: {controls} checked, {} failed",
            defects.len()
        );
        failures.extend(defects);
        assert!(
            failures.is_empty(),
            "{} of {} rows and controls failed:\n{}",
            failures.len(),
            total + controls,
            failures.join("\n")
        );
    }

    /// The unfiltered control from the filtered probe's position: a sibling of
    /// the helper, same command, no filter, which must get a real descriptor.
    async fn sibling_control(victim: &Victim, row: &Row, control: &str) -> Result<(), String> {
        let name = row.name;
        // Its own token file: a parallel control never truncates or unlinks it.
        let tag = format!("control-{}", next_tag());
        let mut command = Command::new(std::env::current_exe().expect("test executable path"));
        command
            .arg("--exact")
            .arg(PROBE_TEST_NAME)
            .arg("--nocapture")
            .env(ROW_VAR, name)
            .env(VICTIM_PID_VAR, victim.pid.to_string())
            .env(VICTIM_ADDRESS_VAR, victim.address.to_string())
            .env(UNFILTERED_VAR, "1")
            // Planted on this one child's command only.
            .env(CONTROL_VAR, control)
            .stdout(std::process::Stdio::from(token_file(&tag, name)))
            .stderr(std::process::Stdio::piped());
        let mut child = spawn_row(&mut command);
        // Read on the same runtime: a full pipe would block the child's write.
        let mut stderr = child.stderr.take().expect("control stderr pipe");
        let drain = tokio::spawn(async move {
            let mut diagnostics = String::new();
            match tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut diagnostics).await {
                Ok(_) => diagnostics,
                Err(error) => format!("stderr did not read: {error}"),
            }
        });
        let failure = finish_probe(&tag, name, row, &mut child).await;
        // The child is reaped, so its pipe end is here and the read ends.
        let diagnostics = drain
            .await
            .unwrap_or_else(|_| "stderr drain panicked".to_owned());
        // Only this control's token: one left here would read as a pass.
        let token = probe_token(&tag, name);
        assert!(!token.exists(), "control {tag} left its token {token:?}");
        match failure {
            None => {
                // The writev control child wrote into this same helper: its
                // report must hold those bytes, not a fresh helper's.
                if name == WRITEV_ROW {
                    check_write(&victim_report(victim), &write_bytes(), "wrote");
                    restores_pattern(victim);
                } else if name != READV_ROW {
                    pattern_control(victim);
                }
                Ok(())
            }
            Some(reason) => Err(format!(
                "row {name} sibling: unfiltered sibling control failed: {reason}; stderr {diagnostics:?}"
            )),
        }
    }

    /// Ends a [`CONTROL_VAR`] child: it writes its stderr and exits [`CONTROL_EXIT`].
    fn planted_control() {
        if let Ok(Some(bytes)) = std::env::var(CONTROL_VAR).map(|value| value.parse::<usize>().ok())
        {
            control_stderr(&control_text(bytes));
            std::process::exit(CONTROL_EXIT);
        }
    }

    /// Writes `text` to stderr, retried when interrupted, until every byte
    /// has been accepted by the pipe.
    fn control_stderr(text: &str) {
        let mut rest = text.as_bytes();
        while !rest.is_empty() {
            let written =
                unsafe { libc::write(2, rest.as_ptr() as *const libc::c_void, rest.len()) };
            if written <= 0 {
                if written == 0 || errno() != libc::EINTR {
                    return;
                }
                continue;
            }
            rest = &rest[written as usize..];
        }
    }

    /// The stderr a [`CONTROL_VAR`] control writes: the marker line, then
    /// `bytes` bytes, then a line end.
    fn control_text(bytes: usize) -> String {
        let mut text = format!("{CONTROL_STDERR}\n");
        text.extend(std::iter::repeat_n('f', bytes));
        text.push('\n');
        text
    }

    /// Runs the helper row's control once to its end.
    fn control_failure(control: &str) -> Result<(), String> {
        let row = rows()
            .into_iter()
            .find(|row| row.name == "pidfd_getfd sibling")
            .expect("a sibling row");
        let control = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("control runtime")
            .block_on(sibling_control(&Victim::start(), &row, control));
        control
    }

    /// Writes one readiness publication under `tag` and reads it back through
    /// the path `Victim::start` polls. The tag keeps each test's token and
    /// staging file apart; the file is unlinked whatever the read does.
    fn published_readiness(tag: &str, line: &str) -> Option<usize> {
        let pid = std::process::id() as libc::pid_t;
        let token = tagged_victim_token(tag, pid);
        let staging = token.with_extension("tmp");
        std::fs::write(&staging, line.replace("PID", &pid.to_string()))
            .expect("readiness publication");
        std::fs::rename(&staging, &token).expect("readiness rename");
        let address = read_readiness(&token, pid);
        let _ = std::fs::remove_file(staging);
        let _ = std::fs::remove_file(&token);
        address
    }

    /// A line with no address fails by name instead of becoming a retry, so
    /// the wait reports the missing field rather than a lost publication.
    #[test]
    #[should_panic(expected = "has no address field")]
    fn readiness_without_an_address_fails() {
        assert_eq!(published_readiness("no-address", "PID\n"), Some(1));
    }

    /// An address that is not a number fails by name.
    #[test]
    #[should_panic(expected = "has no address: ")]
    fn readiness_with_an_unparsable_address_fails() {
        assert_eq!(published_readiness("unparsable", "PID invalid\n"), Some(1));
    }

    /// A published zero address fails by name: zero is the retry state and
    /// must never come from a publication.
    #[test]
    #[should_panic(expected = "publishes address zero")]
    fn readiness_with_a_zero_address_fails() {
        assert_eq!(published_readiness("zero", "PID 0\n"), Some(1));
    }

    /// Runs one planted control and asserts the whole failure: the harness's
    /// text, the reason `finish_probe` returned (`row_result` keeps a bool, so
    /// an exit names no number) and the whole stderr written.
    #[track_caller]
    fn refused_control(bytes: usize) -> String {
        let failure = control_failure(&bytes.to_string()).expect_err("a control passed");
        let expected = format!(
            "row pidfd_getfd sibling sibling: unfiltered sibling control failed: \
             row pidfd_getfd sibling failed; stderr {:?}",
            control_text(bytes)
        );
        assert_eq!(failure, expected);
        failure
    }

    /// A control's exit 7 fails with `finish_probe`'s whole reason and stderr.
    #[test]
    fn a_control_that_exits_seven_reports_its_reason_and_stderr() {
        refused_control(0);
    }

    /// A 100 KiB flood still reports the exit reason with the whole stderr.
    #[test]
    fn a_control_that_floods_stderr_still_reports_its_exit() {
        let failure = refused_control(102_400);
        assert!(!failure.contains("not finish"), "{failure:?}");
    }

    /// A refused control that ends first leaves a parallel passing control its
    /// own token, so the pass still reads.
    #[test]
    fn a_refused_control_leaves_a_parallel_control_passing() {
        let row = rows()
            .into_iter()
            .find(|row| row.name == "pidfd_getfd sibling")
            .expect("a sibling row");
        let victim = Victim::start();
        let (refused, passed) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("control runtime")
            .block_on(async {
                tokio::join!(
                    sibling_control(&victim, &row, "0"),
                    sibling_control(&victim, &row, "")
                )
            });
        assert!(refused.is_err(), "the planted control passed");
        assert_eq!(passed, Ok(()));
    }

    /// One row under two tags reaches two files: no run shares a token.
    #[test]
    fn one_row_under_two_tags_reaches_two_probe_files() {
        let (one, two) = (next_tag(), next_tag());
        let path = probe_token(&one.to_string(), TOKEN_ROW);
        let other = probe_token(&two.to_string(), TOKEN_ROW);
        assert!(!path.exists(), "a token exists before the spawn");
        assert_ne!(one, two);
        assert_ne!(path, other);
        std::fs::write(&path, TOKEN_LINE).expect("token");
        assert!(!other.exists(), "fresh token exists");
        let got = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(got, TOKEN_LINE);
        let _ = std::fs::remove_file(&path);
    }
}
