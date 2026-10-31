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
    /// The harness test also dispatches a row when `ROW_VAR` is set, before it
    /// touches the test process, so a probe enters its own row there.
    const PROBE_TEST: &str =
        "provider::linux_model_seccomp::tests::every_denied_syscall_and_domain_has_a_row";
    /// The descendant test serves a row that ends in a signal, because a killed
    /// process cannot print the pass token.
    const DESCENDANT_TEST: &str =
        "provider::linux_model_seccomp::tests::child_and_descendant_have_no_inet_sockets";

    /// Expected result of a row: EPERM, a permitted call, or SIGSYS.
    const EPERM: u8 = 0;
    const PERMITTED: u8 = 1;
    const KILLED: u8 = 2;

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

    /// Counts message rows: the first sends on an empty pair (the unfiltered
    /// control), every later one finds one byte from it.
    static MESSAGE_ORDER: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

    /// Header bytes of one message.
    const MMSG_LEN: usize = 64;
    /// The ancillary buffer, in `u64` words so it is word-aligned as
    /// `CMSG_SPACE` asks. `CMSG_SPACE` for one `c_int` is 24 bytes here, so
    /// three words hold one `SCM_RIGHTS` header and its descriptor.
    const CONTROL: usize = 6;
    /// The `MSG_DONTWAIT` flag a queuing send or a draining receive passes to
    /// the kernel, so a peer that cannot take the message, or an empty queue,
    /// answers EAGAIN instead of waiting.
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
            let controllen = if fd >= 0 {
                // A send passes exactly one `CMSG_SPACE`, so its header sits
                // `space` bytes into `control`: the kernel drops the leading
                // zero words and reads the header and its descriptor. The same
                // header in the leading words, cleared before each call, is
                // the first header a receive offers, so a receive that ends
                // after the sent byte still answers with its own control.
                // SAFETY: `control` is word aligned and holds two `space`-sized
                // extents, so both headers and their descriptors fit.
                unsafe {
                    let cmsg =
                        (self.control.as_mut_ptr() as *mut u8).add(space) as *mut libc::cmsghdr;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(size as _) as _;
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    std::ptr::write(libc::CMSG_DATA(cmsg) as *mut libc::c_int, fd);
                }
                space
            } else {
                // A receive offers its first header and one `CMSG_SPACE`
                // more, so the answer lands where the next send reads it.
                space + space
            };
            self.iovec.iov_len = payload;
            self.hdr = libc::msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut self.iovec,
                msg_iovlen: 1,
                // A send's control pointer starts at its header, a receive's
                // at the start of the buffer.
                msg_control: unsafe {
                    (self.control.as_mut_ptr() as *mut u8).add(if fd >= 0 { space } else { 0 }) as _
                },
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
        /// where the kernel buffers the received message. The probe socket is
        /// non-blocking and the draining receive passes `MSG_DONTWAIT`, so a
        /// receive never waits for a peer.
        fn recv(&mut self, sock: libc::c_int, batched: bool, flags: u64) -> libc::c_long {
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

    /// `true` for the first message call in this process.
    fn first_message() -> bool {
        MESSAGE_ORDER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
    }

    /// Sends on `sock`, handing over `fd` when it is `Some`.
    fn sending(sock: libc::c_int, batched: bool, fd: Option<libc::c_int>) -> libc::c_long {
        let mut messages = message();
        messages.fill(1, fd.unwrap_or(-1));
        messages.send(sock, batched, MSG_DONTWAIT)
    }

    /// One `sendmsg`, or `sendmmsg` when `batched`, of one descriptor-bearing
    /// message on a socketpair made here; the first call sends on an empty
    /// pair, so `MSG_DONTWAIT` answers EAGAIN rather than blocking.
    /// The `first` flag is the caller's, not the send's: either a send row
    /// hands over a descriptor, or the unfiltered control has already sent.
    fn send_message(batched: bool, _first: bool) -> libc::c_long {
        let Some(fd) = pair() else {
            return -1;
        };
        let sender = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let rc = sending(fd[0], batched, Some(sender));
        close_all(&[sender]);
        close_all(&fd);
        rc
    }

    /// The pair and the messages a receive row reads: one from `sendto`, then
    /// one descriptor-bearing `sendmsg`, both already queued in this probe, so
    /// the receive below never waits for a peer.
    struct Queued {
        fds: [libc::c_int; 2],
        token: libc::c_int,
        descriptor: libc::c_int,
        /// One `sendmsg`, unbounded, in this probe. `c_int` is `i32`, which
        /// `c_long` holds on every target the crate builds for.
        sent: libc::c_long,
    }

    impl Drop for Queued {
        fn drop(&mut self) {
            close_all(&[self.fds[0], self.fds[1], self.token, self.descriptor]);
        }
    }

    /// Queues both messages on a new socketpair. A filtered probe child cannot
    /// make the second one itself: its deny list answers EPERM to `sendmsg`
    /// before the row runs.
    fn queued() -> Option<Queued> {
        let fds = pair()?;
        let token = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let descriptor = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let mut queued = Queued {
            fds,
            token,
            descriptor,
            sent: 0,
        };
        if sys(
            libc::SYS_sendto,
            [fds[1] as _, b"x".as_ptr() as _, 1, 0, 0, 0],
        ) < 0
        {
            return None;
        }
        // The message goes from the far end, so the receive below is what
        // meets it.
        let sent = sending(fds[1], false, Some(descriptor));
        if sent < 0 {
            return None;
        }
        queued.sent = sent;
        Some(queued)
    }

    /// One `recvmsg`, or `recvmmsg` when `batched`, on a socketpair made here.
    /// Later calls find the descriptor-bearing message; the first call is the
    /// filtered probe row, which the deny list answers EPERM before the pair
    /// matters.
    fn recv_message(batched: bool, first: bool) -> libc::c_long {
        let Some(queued) = queued() else {
            return -1;
        };
        let mut messages = message();
        // Drain the `sendto` byte first, so the row's receive meets the
        // descriptor-bearing message and its control is what stays checked.
        let mut drained = message();
        drained.fill(1, -1);
        let token = drained.recv(queued.fds[0], false, MSG_DONTWAIT);
        // The receive overwrote the buffer's first header with its own, so
        // the send below writes the descriptor's header again.
        messages.fill(MMSG_LEN, -1);
        // The row's receive is blocking on a non-blocking socket: the peer
        // above already queued the descriptor-bearing message, so the queue is
        // not empty and the call returns. Only the byte drain needs
        // `MSG_DONTWAIT`, because it can run after the last message.
        let rc = messages.recv(queued.fds[0], batched, 0);
        if !first {
            // The unfiltered control proves the receive path answered with the
            // descriptor the sender handed over: the message's own size, the
            // descriptor's header and value, then the drained byte.
            assert!(
                rc == queued.sent && token == 1 && messages.received_rights(),
                "control lost SCM_RIGHTS: rc {rc}, token {token}, errno {}",
                errno()
            );
        }
        rc
    }

    /// Each message row narrows the shared helper to one syscall pair. The
    /// process-wide counter tells the first message call apart from the rest.
    fn sendmsg_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        send_message(false, first_message())
    }

    fn recvmsg_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        recv_message(false, first_message())
    }

    fn sendmmsg_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        send_message(true, first_message())
    }

    fn recvmmsg_body(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_long {
        recv_message(true, first_message())
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

    /// Each denied family through `socket`, the Unix controls through both
    /// creators, the four message syscalls the deny list refuses, `getpid` and
    /// the x32 boundary. Each entry is its own probe run, so a removed deny
    /// entry turns exactly that row red.
    #[rustfmt::skip]
    fn rows() -> Vec<Row> {
        let row = |name, body, domain, kind, protocol, outcome| Row {
            name, body, domain, kind, protocol, outcome,
        };
        let (tcp, raw) = (libc::SOCK_STREAM, libc::SOCK_RAW);
        vec![
            row("socket+AF_INET", socket_body, libc::AF_INET, tcp, libc::IPPROTO_TCP, EPERM),
            row("socket+AF_INET6", socket_body, libc::AF_INET6, tcp, libc::IPPROTO_TCP, EPERM),
            row("socket+AF_NETLINK", socket_body, libc::AF_NETLINK, raw, 0, EPERM),
            row("socket+AF_UNIX", socket_body, libc::AF_UNIX, tcp, 0, PERMITTED),
            row("socketpair+AF_UNIX", socketpair_body, libc::AF_UNIX, tcp, 0, PERMITTED),
            row("sendmsg+SCM_RIGHTS", sendmsg_body, 0, 0, 0, EPERM),
            row("recvmsg+cmsg", recvmsg_body, 0, 0, 0, EPERM),
            row("sendmmsg+SCM_RIGHTS", sendmmsg_body, 0, 0, 0, EPERM),
            row("recvmmsg+cmsg", recvmmsg_body, 0, 0, 0, EPERM),
            row("io_uring_setup", io_uring_body, 0, 0, 0, EPERM),
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
        // The redirection runs the probe with the row variable in this
        // process, so only the filter's own state is proof here.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) },
            2,
            "the model filter was not attached"
        );
        let row = rows()
            .into_iter()
            .find(|row| row.name == wanted)
            .unwrap_or_else(|| panic!("row {wanted} was not requested by the harness"));
        let rc = (row.body)(row.domain, row.kind, row.protocol);
        check(row.name, row.outcome, rc);
        println!("{PROBE_TOKEN} {}", row.name);
    }

    #[tokio::test]
    async fn child_and_descendant_have_no_inet_sockets() {
        let name = DESCENDANT_TEST;
        let executable = std::env::current_exe().unwrap();
        // A row that ends in a signal runs here, because the harness test
        // proves the filter first and a killed process would fail that proof.
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

    /// Where one row's probe records its pass token. The filter closes the
    /// child's inherited descriptors before exec, so a pipe from
    /// `Stdio::piped` reaches the probe closed and its token is lost; this
    /// file is opened before the fork. Each row starts and ends with none.
    fn probe_token(name: &str) -> std::path::PathBuf {
        let safe: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        std::env::temp_dir().join(format!("elastos-row-probe-{}-{safe}", std::process::id()))
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
        let total = all.len();
        let mut failures = Vec::new();
        // Control: each EPERM row's call must succeed without the filter, so
        // only the filter can answer EPERM. The message rows reach their own
        // syscall over a Unix socketpair made here, and the receive row checks
        // that the kernel returned the descriptor it was given. The SIGSYS row
        // is killed before any unfiltered call can run.
        for row in &all {
            let rc = match row.outcome {
                EPERM => (row.body)(row.domain, row.kind, row.protocol),
                _ => 0,
            };
            // Only a descriptor the kernel returned is closed: a body that
            // reports success as 0 is not handing back fd 0, and closing it
            // would take this process's own stdin, then its stdout.
            if rc > 2 {
                unsafe { libc::close(rc as libc::c_int) };
            }
            assert!(
                rc >= 0,
                "row {} is not valid unfiltered: {rc}, errno {}",
                row.name,
                errno()
            );
        }
        for row in all {
            let name = row.name;
            let test = if row.outcome == KILLED {
                DESCENDANT_TEST
            } else {
                PROBE_TEST
            };
            let mut command = Command::new(std::env::current_exe().expect("test executable path"));
            command
                // No `--`: libtest reads the row variable as a name filter
                // and runs no test, so the probe would pass its row unused.
                .arg("--exact")
                .arg(test)
                .arg("--nocapture")
                .env(ROW_VAR, row.name)
                .stdout(std::process::Stdio::from(
                    std::fs::File::create(probe_token(row.name)).expect("probe token file"),
                ))
                .stderr(std::process::Stdio::null());
            install_on_command(&mut command).expect("filter attach failed");
            let mut child = command.spawn().expect("probe child did not start");
            let deadline = std::time::Duration::from_secs(20);
            let finished = run_probe(&mut child, deadline).await;
            let result: Result<(), String> = match (finished, row.outcome) {
                (None, _) => Err(format!("row {name}: probe child did not finish")),
                (Some(status), KILLED) => {
                    use std::os::unix::process::ExitStatusExt as _;
                    if status.signal() == Some(libc::SIGSYS) {
                        Ok(())
                    } else {
                        Err(format!("row {name}: expected SIGSYS, status {status:?}"))
                    }
                }
                (Some(status), _) if !status.success() => {
                    Err(format!("row {name} failed: {status:?}"))
                }
                // The child must also prove it exercised the row.
                (Some(_), _) => {
                    // The probe is reaped and its group ended, so the pipe has
                    // no writer left; `output` collects it to EOF.
                    let stdout = std::fs::read_to_string(probe_token(name)).unwrap_or_default();
                    let _ = std::fs::remove_file(probe_token(name));
                    if stdout.contains(PROBE_TOKEN) {
                        Ok(())
                    } else {
                        Err(format!("row {name}: no pass token"))
                    }
                }
            };
            if let Err(failure) = result {
                failures.push(failure);
            }
        }
        println!("ROWS: {total} checked, {} failed", failures.len());
        assert!(
            failures.is_empty(),
            "{} of {total} rows failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
