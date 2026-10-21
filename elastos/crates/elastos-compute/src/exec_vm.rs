//! Whether an agent test may be handed to a micro-VM adapter.
//!
//! `decide_exec` names the adapter. `begin_exec` calls a launcher only when
//! the file has an ext4 superblock. This module does not call `VzProvider`
//! or `CrosvmProvider`, and it does not boot the Browser image.

use std::path::Path;

/// The existing boot adapter for this host. Not the Browser VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecAdapter {
    AppleVirtualization,
    Crosvm,
}

/// The machine this process is running on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecHost {
    Macos,
    Linux,
    Other,
}

/// Admit names an adapter. It is not a boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecDecision {
    Refuse(&'static str),
    Admit { adapter: ExecAdapter },
}

/// A proposed test run. `grant` is a Runtime grant id, not a secret.
#[derive(Clone, Copy, Debug)]
pub struct ExecRequest<'a> {
    pub grant: Option<&'a str>,
    pub cancelled: bool,
    pub workspace: &'a str,
    pub argv: &'a [&'a str],
    pub rootfs: &'a Path,
    pub host: ExecHost,
}

/// Refuse a missing grant, a cancel, a host path, a missing Linux rootfs,
/// or a host that has no adapter. A ready decision still does not boot.
pub fn decide_exec(request: &ExecRequest<'_>) -> ExecDecision {
    if request.cancelled {
        return ExecDecision::Refuse("cancelled");
    }
    if request.grant.is_none_or(|grant| grant.is_empty()) {
        return ExecDecision::Refuse("missing grant");
    }
    if !request.workspace.starts_with("localhost://")
        || request.workspace.chars().any(char::is_whitespace)
        || host_path(request.workspace)
    {
        return ExecDecision::Refuse("host path");
    }
    if request.argv.is_empty() || request.argv.iter().any(|arg| host_path(arg)) {
        return ExecDecision::Refuse("host path");
    }
    if request.rootfs.file_name().and_then(|name| name.to_str()) != Some("rootfs.ext4")
        || !request.rootfs.is_file()
    {
        return ExecDecision::Refuse("rootfs missing");
    }
    match request.host {
        ExecHost::Macos => ExecDecision::Admit {
            adapter: ExecAdapter::AppleVirtualization,
        },
        ExecHost::Linux => ExecDecision::Admit {
            adapter: ExecAdapter::Crosvm,
        },
        ExecHost::Other => ExecDecision::Refuse("unsupported host"),
    }
}

fn host_path(text: &str) -> bool {
    text.starts_with('/') || text.contains('\\') || text.split('/').any(|part| part == "..")
}

const RUN_LOG_BUDGET: usize = 4_000;
/// ext4 superblock magic, little-endian, at byte 0x438.
const EXT4_MAGIC_OFFSET: usize = 0x438;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

/// What a launcher returns. This is not proof that a hypervisor ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecBody {
    pub exit_code: i32,
    pub log: String,
    pub artifact: String,
}

/// A program that is actually inside the small machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecCommand {
    ShellTrue,
    ShellFalse,
    TestPass,
    TestFail,
    TestEdited,
    Files,
    Note,
}

impl ExecCommand {
    /// The closed token placed on the kernel command line.
    pub const fn token(self) -> &'static str {
        match self {
            Self::ShellTrue => "true",
            Self::ShellFalse => "false",
            Self::TestPass => "test-pass",
            Self::TestFail => "test-fail",
            Self::TestEdited => "test-edited",
            Self::Files => "files",
            Self::Note => "note",
        }
    }
}

/// Files that may be placed in the machine for one project. Paths stay
/// relative. A host path, a `..` segment, or a workspace that is not
/// `localhost://Users/<root>/Projects/<name>` is refused. This does not copy
/// a directory from the host.
pub fn admit_project_files(workspace: &str, files: &[(&str, &str)]) -> Result<(), &'static str> {
    let Some(rest) = workspace.strip_prefix("localhost://Users/") else {
        return Err("host path");
    };
    let Some((root, name)) = rest.split_once("/Projects/") else {
        return Err("host path");
    };
    if root.is_empty()
        || name.is_empty()
        || root.contains('/')
        || name.contains('/')
        || root.contains('\\')
        || name.contains('\\')
        || host_path(workspace)
        || host_path(root)
        || host_path(name)
        || workspace.chars().any(char::is_whitespace)
        || files.is_empty()
    {
        return Err("host path");
    }
    for (path, text) in files {
        if path.is_empty()
            || path.starts_with('/')
            || host_path(path)
            || path.chars().any(char::is_whitespace)
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("host path");
        }
        if host_path(text) {
            return Err("host path");
        }
    }
    Ok(())
}

/// A file name from the machine's list. A host path, a slash, or an empty
/// name is refused. This does not read a directory.
pub fn admit_listed_file(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.starts_with('/')
        || host_path(name)
        || name.contains('/')
        || name.contains('\\')
        || name.contains(' ')
    {
        return Err("host path");
    }
    Ok(())
}

/// Name a program the image can run. `cargo` is not in the image.
/// Anything else is refused. This does not boot.
pub fn admit_exec_argv(argv: &[&str]) -> Result<ExecCommand, &'static str> {
    match argv {
        ["files"] => Ok(ExecCommand::Files),
        ["note"] => Ok(ExecCommand::Note),
        ["true"] => Ok(ExecCommand::ShellTrue),
        ["false"] => Ok(ExecCommand::ShellFalse),
        ["vm-smoke", "tests::project_is_ready"] => Ok(ExecCommand::TestPass),
        ["vm-smoke", "tests::a_missing_piece_fails"] => Ok(ExecCommand::TestFail),
        ["vm-smoke", "tests::project_was_edited"] => Ok(ExecCommand::TestEdited),
        ["cargo"] | ["cargo", _] => Err("program missing"),
        _ => Err("command refused"),
    }
}

/// The boot hook. It returns the guest console, not an exit code.
/// The Apple and crosvm providers are not called from here.
pub trait ExecLauncher {
    fn launch(
        &mut self,
        adapter: ExecAdapter,
        rootfs: &Path,
        command: ExecCommand,
    ) -> Result<String, String>;
}

/// One core and 256 MiB. The Browser VM is a different, larger machine.
pub const EXEC_MEMORY_MIB: u32 = 256;
/// One core, so a test run does not take the machine over.
pub const EXEC_VCPU_COUNT: u8 = 1;

const CUT_NOTICE: &str = "result cut to 4000 bytes\n";

/// Keep a console result inside the run budget. A short result is unchanged.
/// A longer one keeps the end of the log, where a failure usually sits, and
/// drops the artifact. A host path is refused.
pub fn cap_exec_output(log: &str, artifact: &str) -> Result<(String, String), &'static str> {
    if host_path(log) || host_path(artifact) {
        return Err("host path");
    }
    if log.len().saturating_add(artifact.len()) <= RUN_LOG_BUDGET {
        return Ok((log.to_string(), artifact.to_string()));
    }
    let room = RUN_LOG_BUDGET - CUT_NOTICE.len();
    let mut start = log.len().saturating_sub(room);
    while start < log.len() && !log.is_char_boundary(start) {
        start += 1;
    }
    let capped = format!("{CUT_NOTICE}{}", &log[start..]);
    if capped.len() > RUN_LOG_BUDGET || host_path(&capped) {
        return Err("log too long");
    }
    Ok((capped, String::new()))
}

/// The last line a guest prints once its command has finished.
pub const EXEC_EXIT_MARK: &str = "elastos-exec-exit ";

/// Read an exit code from console text. A missing mark, two different
/// codes, or a host path is refused. Silence is not exit 0.
pub fn parse_exec_console(text: &str) -> Result<ExecBody, &'static str> {
    let mut exit_code = None;
    let mut log_lines = Vec::new();
    for line in text.lines() {
        let Some(raw) = line.strip_prefix(EXEC_EXIT_MARK) else {
            if !line.is_empty() {
                log_lines.push(line);
            }
            continue;
        };
        let code: i32 = match raw.parse::<i32>() {
            Ok(code) if raw == code.to_string() => code,
            _ => return Err("exit missing"),
        };
        if let Some(previous) = exit_code {
            if previous != code {
                return Err("exit mismatch");
            }
        }
        exit_code = Some(code);
    }
    let Some(exit_code) = exit_code else {
        return Err("exit missing");
    };
    let (log, artifact) = cap_exec_output(&log_lines.join("\n"), "")?;
    Ok(ExecBody {
        exit_code,
        log,
        artifact,
    })
}

/// Hand a granted run to `launcher` only when the rootfs has an ext4
/// superblock. The exit code is read from the console mark. A launcher
/// cannot invent one. A missing mark, a host path, or a fake rootfs never
/// becomes a success. A long console log is cut to the budget.
pub fn begin_exec(
    request: &ExecRequest<'_>,
    launcher: &mut impl ExecLauncher,
) -> Result<ExecBody, &'static str> {
    let adapter = match decide_exec(request) {
        ExecDecision::Refuse(reason) => return Err(reason),
        ExecDecision::Admit { adapter } => adapter,
    };
    if !ext4_superblock(request.rootfs) {
        return Err("rootfs not bootable");
    }
    let command = admit_exec_argv(request.argv)?;
    let console = launcher
        .launch(adapter, request.rootfs, command)
        .map_err(|_| "launcher failed")?;
    parse_exec_console(&console)
}

/// The text a granted edit would store. A missing grant, a moved version,
/// a host path, or old text that is not unique is refused. This does not
/// write a file.
pub fn perform_edit(
    grant: Option<&str>,
    resource: &str,
    seen_version: u64,
    current_version: u64,
    current_text: &str,
    old: &str,
    new_text: &str,
) -> Result<String, &'static str> {
    if grant.is_none_or(|grant| grant.is_empty()) {
        return Err("missing grant");
    }
    if host_path(resource) || host_path(old) || host_path(new_text) {
        return Err("host path");
    }
    if seen_version != current_version {
        return Err("stale");
    }
    if old.is_empty() || current_text.matches(old).count() != 1 {
        return Err("not unique");
    }
    Ok(current_text.replacen(old, new_text, 1))
}

/// Name the adapter for a bootable image. A Browser disk, a missing ELF
/// kernel, or a rootfs without an ext4 superblock is refused. This does not
/// call the hypervisor.
pub fn admit_boot_image(
    host: ExecHost,
    kernel: &Path,
    rootfs: &Path,
) -> Result<ExecAdapter, &'static str> {
    if rootfs
        .components()
        .any(|component| component.as_os_str() == "browser-vm")
    {
        return Err("browser image");
    }
    if !elf_kernel(kernel) {
        return Err("kernel missing");
    }
    if !ext4_superblock(rootfs) {
        return Err("rootfs not bootable");
    }
    match host {
        ExecHost::Macos => Ok(ExecAdapter::AppleVirtualization),
        ExecHost::Linux => Ok(ExecAdapter::Crosvm),
        ExecHost::Other => Err("unsupported host"),
    }
}

fn elf_kernel(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut header = [0_u8; 0x3c];
    use std::io::Read;
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    header[..4] == [0x7f, b'E', b'L', b'F'] || header[0x38..0x3c] == *b"ARM\x64"
}

fn ext4_superblock(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 2];
    use std::io::{Read, Seek, SeekFrom};
    let mut file = file;
    if file
        .seek(SeekFrom::Start(EXT4_MAGIC_OFFSET as u64))
        .is_err()
    {
        return false;
    }
    file.read_exact(&mut magic).is_ok() && magic == EXT4_MAGIC
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn rootfs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("rootfs.ext4"), b"not-an-image").expect("rootfs");
        dir
    }

    fn request<'a>(rootfs: &'a Path, grant: Option<&'a str>, host: ExecHost) -> ExecRequest<'a> {
        ExecRequest {
            grant,
            cancelled: false,
            workspace: "localhost://Users/self/Projects/demo",
            argv: &["cargo", "test"],
            rootfs,
            host,
        }
    }

    #[test]
    fn a_missing_grant_or_a_cancel_does_not_admit_a_boot() {
        let dir = rootfs();
        let image = dir.path().join("rootfs.ext4");
        assert_eq!(
            decide_exec(&request(&image, None, ExecHost::Macos)),
            ExecDecision::Refuse("missing grant")
        );
        assert_eq!(
            decide_exec(&request(&image, Some(""), ExecHost::Linux)),
            ExecDecision::Refuse("missing grant")
        );
        let mut cancelled = request(&image, Some("grant-1"), ExecHost::Macos);
        cancelled.cancelled = true;
        assert_eq!(decide_exec(&cancelled), ExecDecision::Refuse("cancelled"));
    }

    #[test]
    fn a_host_path_or_a_missing_rootfs_does_not_admit_a_boot() {
        let dir = rootfs();
        let image = dir.path().join("rootfs.ext4");
        let mut workspace = request(&image, Some("grant-1"), ExecHost::Macos);
        workspace.workspace = "/tmp/demo";
        assert_eq!(decide_exec(&workspace), ExecDecision::Refuse("host path"));
        let mut argv = request(&image, Some("grant-1"), ExecHost::Macos);
        argv.argv = &["/bin/sh"];
        assert_eq!(decide_exec(&argv), ExecDecision::Refuse("host path"));
        let absent = dir.path().join("other.ext4");
        let mut missing = request(&image, Some("grant-1"), ExecHost::Macos);
        missing.rootfs = &absent;
        assert_eq!(
            decide_exec(&missing),
            ExecDecision::Refuse("rootfs missing")
        );
    }

    #[test]
    fn a_granted_run_names_the_host_adapter_and_does_not_boot() {
        let dir = rootfs();
        let image = dir.path().join("rootfs.ext4");
        assert_eq!(
            decide_exec(&request(&image, Some("grant-1"), ExecHost::Macos)),
            ExecDecision::Admit {
                adapter: ExecAdapter::AppleVirtualization,
            }
        );
        assert_eq!(
            decide_exec(&request(&image, Some("grant-1"), ExecHost::Linux)),
            ExecDecision::Admit {
                adapter: ExecAdapter::Crosvm,
            }
        );
        assert_eq!(
            decide_exec(&request(&image, Some("grant-1"), ExecHost::Other)),
            ExecDecision::Refuse("unsupported host")
        );
        assert!(image.is_file());
    }

    struct RecordingLauncher {
        called: bool,
        console: String,
    }

    impl ExecLauncher for RecordingLauncher {
        fn launch(
            &mut self,
            adapter: ExecAdapter,
            _rootfs: &Path,
            command: ExecCommand,
        ) -> Result<String, String> {
            assert_eq!(adapter, ExecAdapter::AppleVirtualization);
            assert_eq!(command, ExecCommand::TestPass);
            self.called = true;
            Ok(self.console.clone())
        }
    }

    fn ready<'a>(rootfs: &'a Path, grant: Option<&'a str>, host: ExecHost) -> ExecRequest<'a> {
        ExecRequest {
            grant,
            cancelled: false,
            workspace: "localhost://Users/self/Projects/demo",
            argv: &["vm-smoke", "tests::project_is_ready"],
            rootfs,
            host,
        }
    }

    fn ext4_image(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let image = dir.path().join("rootfs.ext4");
        let mut bytes = vec![0_u8; EXT4_MAGIC_OFFSET + 2];
        bytes[EXT4_MAGIC_OFFSET] = EXT4_MAGIC[0];
        bytes[EXT4_MAGIC_OFFSET + 1] = EXT4_MAGIC[1];
        std::fs::write(&image, bytes).expect("ext4 stub");
        image
    }

    #[test]
    fn a_fake_rootfs_never_reaches_the_launcher() {
        let dir = rootfs();
        let image = dir.path().join("rootfs.ext4");
        let mut launcher = RecordingLauncher {
            called: false,
            console: "must not run\nelastos-exec-exit 0".into(),
        };
        assert_eq!(
            begin_exec(
                &ready(&image, Some("grant-1"), ExecHost::Macos),
                &mut launcher
            ),
            Err("rootfs not bootable")
        );
        assert!(!launcher.called);
    }

    #[test]
    fn an_ext4_rootfs_is_handed_to_the_launcher_and_a_host_path_is_dropped() {
        let dir = tempfile::tempdir().expect("temp dir");
        let image = ext4_image(&dir);
        let mut launcher = RecordingLauncher {
            called: false,
            console: "cargo test: ok\nelastos-exec-exit 0".into(),
        };
        let body = begin_exec(
            &ready(&image, Some("grant-1"), ExecHost::Macos),
            &mut launcher,
        )
        .expect("capped result");
        assert!(launcher.called);
        assert_eq!(body.exit_code, 0);
        assert_eq!(body.log, "cargo test: ok");

        launcher.called = false;
        launcher.console = "init: hello from vm smoke test".into();
        assert_eq!(
            begin_exec(
                &ready(&image, Some("grant-1"), ExecHost::Macos),
                &mut launcher
            ),
            Err("exit missing")
        );

        launcher.called = false;
        launcher.console = "/tmp/out\nelastos-exec-exit 0".into();
        assert_eq!(
            begin_exec(
                &ready(&image, Some("grant-1"), ExecHost::Macos),
                &mut launcher
            ),
            Err("host path")
        );
        assert!(launcher.called);
    }

    fn elf_kernel_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let kernel = dir.path().join("vmlinux");
        let mut bytes = vec![0_u8; 0x3c];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        std::fs::write(&kernel, bytes).expect("elf stub");
        kernel
    }

    fn arm64_kernel_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let kernel = dir.path().join("Image");
        let mut bytes = vec![0_u8; 0x3c];
        bytes[0x38..0x3c].copy_from_slice(b"ARM\x64");
        std::fs::write(&kernel, bytes).expect("arm64 stub");
        kernel
    }

    #[test]
    fn a_browser_disk_or_a_missing_kernel_is_not_an_exec_image() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kernel = elf_kernel_file(&dir);
        let browser = dir.path().join("browser-vm");
        std::fs::create_dir_all(&browser).expect("browser dir");
        let browser_disk = browser.join("rootfs.ext4");
        let mut bytes = vec![0_u8; EXT4_MAGIC_OFFSET + 2];
        bytes[EXT4_MAGIC_OFFSET] = EXT4_MAGIC[0];
        bytes[EXT4_MAGIC_OFFSET + 1] = EXT4_MAGIC[1];
        std::fs::write(&browser_disk, &bytes).expect("browser disk");
        assert_eq!(
            admit_boot_image(ExecHost::Macos, &kernel, &browser_disk),
            Err("browser image")
        );

        let exec_disk = ext4_image(&dir);
        let missing = dir.path().join("missing-vmlinux");
        assert_eq!(
            admit_boot_image(ExecHost::Macos, &missing, &exec_disk),
            Err("kernel missing")
        );
        std::fs::write(dir.path().join("text-kernel"), b"not-elf").expect("text kernel");
        assert_eq!(
            admit_boot_image(ExecHost::Macos, &dir.path().join("text-kernel"), &exec_disk),
            Err("kernel missing")
        );
        assert_eq!(
            admit_boot_image(ExecHost::Macos, &kernel, &exec_disk),
            Ok(ExecAdapter::AppleVirtualization)
        );
        assert_eq!(
            admit_boot_image(ExecHost::Linux, &kernel, &exec_disk),
            Ok(ExecAdapter::Crosvm)
        );
        let arm64 = arm64_kernel_file(&dir);
        assert_eq!(
            admit_boot_image(ExecHost::Macos, &arm64, &exec_disk),
            Ok(ExecAdapter::AppleVirtualization)
        );
    }

    #[test]
    fn the_hello_line_is_a_short_run_result_and_a_long_log_keeps_its_ending() {
        let (log, artifact) =
            cap_exec_output("init: hello from vm smoke test", "").expect("hello fits");
        assert_eq!(log, "init: hello from vm smoke test");
        assert!(artifact.is_empty());
        assert_eq!(EXEC_MEMORY_MIB, 256);
        assert_eq!(EXEC_VCPU_COUNT, 1);

        let dir = tempfile::tempdir().expect("temp dir");
        let image = ext4_image(&dir);
        let mut launcher = RecordingLauncher {
            called: false,
            console: format!("{log}\nelastos-exec-exit 0"),
        };
        let body = begin_exec(
            &ready(&image, Some("grant-1"), ExecHost::Macos),
            &mut launcher,
        )
        .expect("hello result");
        assert_eq!(body.exit_code, 0);
        assert_eq!(body.log, "init: hello from vm smoke test");

        let long = format!("{}END-OF-LOG", "x".repeat(5_000));
        let (cut, dropped) = cap_exec_output(&long, "notes").expect("cut log");
        assert!(dropped.is_empty());
        assert!(cut.len() <= 4_000);
        assert!(cut.starts_with("result cut to 4000 bytes\n"));
        assert!(cut.ends_with("END-OF-LOG"));
        launcher.console = format!("{long}\nelastos-exec-exit 1");
        let cut_body = begin_exec(
            &ready(&image, Some("grant-1"), ExecHost::Macos),
            &mut launcher,
        )
        .expect("cut result");
        assert_eq!(cut_body.exit_code, 1);
        assert!(cut_body.log.ends_with("END-OF-LOG"));
        assert!(cut_body.artifact.is_empty());
    }

    #[test]
    fn a_console_without_an_exit_mark_is_not_success_and_a_failed_command_stays_failed() {
        assert_eq!(
            parse_exec_console("init: hello from vm smoke test"),
            Err("exit missing")
        );
        assert_eq!(
            parse_exec_console("elastos-exec-exit\nelastos-exec-exit 0 extra"),
            Err("exit missing")
        );
        assert_eq!(
            parse_exec_console("elastos-exec-exit 0\nelastos-exec-exit 1"),
            Err("exit mismatch")
        );
        let ok = parse_exec_console(
            "init: hello from vm smoke test\nelastos-exec-exit 0\nelastos-exec-exit 0",
        )
        .expect("exit 0");
        assert_eq!(ok.exit_code, 0);
        assert_eq!(ok.log, "init: hello from vm smoke test");
        assert!(ok.artifact.is_empty());
        let failed =
            parse_exec_console("init: command failed\nelastos-exec-exit 1").expect("exit 1");
        assert_eq!(failed.exit_code, 1);
        assert_eq!(failed.log, "init: command failed");
        assert_eq!(
            parse_exec_console("/tmp/out\nelastos-exec-exit 0"),
            Err("host path")
        );
    }

    #[test]
    fn cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch() {
        assert!(admit_listed_file("notes.txt").is_ok());
        assert_eq!(admit_listed_file("/tmp/secret"), Err("host path"));
        assert_eq!(admit_exec_argv(&["cargo", "test"]), Err("program missing"));
        assert_eq!(admit_exec_argv(&["nope"]), Err("command refused"));
        assert_eq!(
            admit_exec_argv(&["vm-smoke", "tests::project_is_ready"]),
            Ok(ExecCommand::TestPass)
        );
        assert_eq!(
            admit_exec_argv(&["vm-smoke", "tests::a_missing_piece_fails"]),
            Ok(ExecCommand::TestFail)
        );
        assert_eq!(ExecCommand::TestPass.token(), "test-pass");
        assert_eq!(ExecCommand::TestFail.token(), "test-fail");
        assert!(admit_project_files(
            "localhost://Users/self/Projects/demo",
            &[("index.html", "<h1>demo</h1>"), ("style.css", "body{}")]
        )
        .is_ok());
        assert_eq!(
            admit_project_files(
                "localhost://Users/self/Projects/demo",
                &[("/tmp/index.html", "<h1>demo</h1>\n")]
            ),
            Err("host path")
        );
        assert_eq!(
            admit_project_files("/tmp/demo", &[("index.html", "<h1>demo</h1>\n")]),
            Err("host path")
        );
        assert_eq!(
            admit_project_files(
                "localhost://Users/self/Projects/demo",
                &[("index.html", "/tmp/out")]
            ),
            Err("host path")
        );

        let dir = tempfile::tempdir().expect("temp dir");
        let image = ext4_image(&dir);
        let mut launcher = RecordingLauncher {
            called: false,
            console: "must not run\nelastos-exec-exit 0".into(),
        };
        let mut ask = ready(&image, Some("grant-1"), ExecHost::Macos);
        ask.argv = &["cargo", "test"];
        assert_eq!(begin_exec(&ask, &mut launcher), Err("program missing"));
        assert!(!launcher.called);
        ask.argv = &["nope"];
        assert_eq!(begin_exec(&ask, &mut launcher), Err("command refused"));
        assert!(!launcher.called);
    }

    #[test]
    fn a_provider_edit_returns_text_and_writes_no_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wrote = perform_edit(
            Some("grant-1"),
            "localhost://Users/self/Projects/demo/style.css",
            1,
            1,
            "body{}",
            "body{}",
            "h1{}",
        )
        .expect("edit text");
        assert_eq!(wrote, "h1{}");
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        assert_eq!(
            perform_edit(
                None,
                "localhost://Users/self/Projects/demo/style.css",
                1,
                1,
                "body{}",
                "body{}",
                "h1{}",
            ),
            Err("missing grant")
        );
        assert_eq!(
            perform_edit(
                Some("grant-1"),
                "localhost://Users/self/Projects/demo/style.css",
                1,
                2,
                "body{}\n/* touched */",
                "body{}",
                "h1{}",
            ),
            Err("stale")
        );
        assert_eq!(
            perform_edit(
                Some("grant-1"),
                "/tmp/style.css",
                1,
                1,
                "body{}",
                "body{}",
                "h1{}",
            ),
            Err("host path")
        );
    }

    /// Counts launches. It answers with a clean exit, so a launch that should
    /// not have happened would look like a success.
    struct CountingLauncher {
        launches: usize,
    }

    impl ExecLauncher for CountingLauncher {
        fn launch(
            &mut self,
            _adapter: ExecAdapter,
            _rootfs: &Path,
            _command: ExecCommand,
        ) -> Result<String, String> {
            self.launches += 1;
            Ok("must not run\nelastos-exec-exit 0".into())
        }
    }

    #[test]
    fn begin_exec_obeys_every_refused_decision_before_the_launcher() {
        let dir = tempfile::tempdir().expect("temp dir");
        let image = ext4_image(&dir);
        let absent = dir.path().join("rootfs-missing").join("rootfs.ext4");
        let mut launcher = CountingLauncher { launches: 0 };

        let mut cancelled = ready(&image, Some("grant-1"), ExecHost::Macos);
        cancelled.cancelled = true;
        let mut host_workspace = ready(&image, Some("grant-1"), ExecHost::Macos);
        host_workspace.workspace = "/tmp/demo";
        let mut host_argv = ready(&image, Some("grant-1"), ExecHost::Macos);
        host_argv.argv = &["vm-smoke", "../tests::project_is_ready"];
        let mut missing = ready(&image, Some("grant-1"), ExecHost::Macos);
        missing.rootfs = &absent;
        for (request, reason) in [
            (ready(&image, None, ExecHost::Macos), "missing grant"),
            (ready(&image, Some(""), ExecHost::Linux), "missing grant"),
            (cancelled, "cancelled"),
            (host_workspace, "host path"),
            (host_argv, "host path"),
            (missing, "rootfs missing"),
            (
                ready(&image, Some("grant-1"), ExecHost::Other),
                "unsupported host",
            ),
        ] {
            assert_eq!(decide_exec(&request), ExecDecision::Refuse(reason));
            assert_eq!(begin_exec(&request, &mut launcher), Err(reason));
        }
        assert_eq!(launcher.launches, 0);

        assert!(begin_exec(
            &ready(&image, Some("grant-1"), ExecHost::Linux),
            &mut launcher
        )
        .is_ok());
        assert_eq!(launcher.launches, 1);
    }

    #[test]
    fn a_project_workspace_must_be_a_users_project() {
        let files = [("index.html", "<h1>demo</h1>")];
        assert!(admit_project_files("localhost://Users/self/Projects/demo", &files).is_ok());
        for workspace in [
            "localhost://Shared/Projects/demo",
            "localhost://UsersAI/self/Projects/demo",
            "localhost://Users/self/demo",
            "localhost://Users/self/Documents/demo",
            "localhost://Users//Projects/demo",
            "localhost://Users/self/Projects/",
            "localhost://Users/a/b/Projects/demo",
            "localhost://Users/self/Projects/demo/src",
            "localhost://Users/self/Projects/my demo",
            "localhost://Users/../Projects/demo",
        ] {
            assert_eq!(
                admit_project_files(workspace, &files),
                Err("host path"),
                "{workspace}"
            );
        }
        assert_eq!(
            admit_project_files("localhost://Users/self/Projects/demo", &[]),
            Err("host path")
        );
        for path in [
            "",
            "src//main.rs",
            "./index.html",
            "src/../index.html",
            "my file",
        ] {
            assert_eq!(
                admit_project_files("localhost://Users/self/Projects/demo", &[(path, "text")]),
                Err("host path"),
                "{path:?}"
            );
        }
    }

    #[test]
    fn a_boot_image_needs_a_whole_kernel_a_readable_ext4_rootfs_and_a_known_host() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kernel = elf_kernel_file(&dir);
        let exec_disk = ext4_image(&dir);
        assert_eq!(
            admit_boot_image(ExecHost::Other, &kernel, &exec_disk),
            Err("unsupported host")
        );

        let short_kernel = dir.path().join("short-vmlinux");
        std::fs::write(&short_kernel, [0x7f, b'E', b'L', b'F']).expect("short kernel");
        assert_eq!(
            admit_boot_image(ExecHost::Linux, &short_kernel, &exec_disk),
            Err("kernel missing")
        );

        let plain = dir.path().join("plain").join("rootfs.ext4");
        std::fs::create_dir_all(plain.parent().unwrap()).expect("plain dir");
        std::fs::write(&plain, vec![0_u8; EXT4_MAGIC_OFFSET + 2]).expect("plain disk");
        let short = dir.path().join("short").join("rootfs.ext4");
        std::fs::create_dir_all(short.parent().unwrap()).expect("short dir");
        std::fs::write(&short, vec![0_u8; 16]).expect("short disk");
        let unreadable = dir.path().join("absent").join("rootfs.ext4");
        for rootfs in [&plain, &short, &unreadable] {
            assert_eq!(
                admit_boot_image(ExecHost::Linux, &kernel, rootfs),
                Err("rootfs not bootable"),
                "{rootfs:?}"
            );
        }
    }

    #[test]
    fn an_edit_needs_old_text_that_occurs_exactly_once() {
        let edit = |current: &str, old: &str| {
            perform_edit(
                Some("grant-1"),
                "localhost://Users/self/Projects/demo/style.css",
                1,
                1,
                current,
                old,
                "h1{}",
            )
        };
        assert_eq!(edit("body{}", "body{}"), Ok("h1{}".to_string()));
        assert_eq!(edit("body{}", ""), Err("not unique"));
        assert_eq!(edit("", ""), Err("not unique"));
        assert_eq!(edit("body{} body{}", "body{}"), Err("not unique"));
        assert_eq!(edit("body{}", "p{}"), Err("not unique"));
    }
}
