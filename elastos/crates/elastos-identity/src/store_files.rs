//! Identity files below the operator-selected, trusted Runtime data root.
//! Unix uses descriptor-bound paths. On Windows `load_or_create_device_key`
//! creates and reads the device key through the owner-only helper: the current
//! user owns it, the DACL does not inherit, a reparse point is refused, and the
//! open is handle-relative. The key bytes go to a temporary file in the identity
//! directory and are renamed onto `device.key`. An existing data root may be
//! owned by the current user, SYSTEM, or Administrators. A file or directory
//! this code creates is owned by the current user. Credential writes stay refused
//! on Windows. The stable identity lock orders key creation and credential
//! mutations. Callers must release it before taking an auth-state lock, or
//! acquire auth before identity.

#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::fs::{MetadataExt, OpenOptionsExt},
};

#[cfg(unix)]
pub(super) struct IdentityFiles {
    root: File,
    directory: File,
    _lock: File,
}

#[cfg(windows)]
pub(super) use device_key::IdentityFiles;

#[cfg(not(any(unix, windows)))]
pub(super) use portable::IdentityFiles;

#[cfg(unix)]
impl IdentityFiles {
    pub(super) fn open(data_dir: &Path) -> anyhow::Result<Self> {
        Self::open_mode(data_dir, true)
    }

    pub(super) fn open_existing(data_dir: &Path) -> anyhow::Result<Self> {
        Self::open_mode(data_dir, false)
    }

    fn open_mode(data_dir: &Path, create: bool) -> anyhow::Result<Self> {
        if create {
            std::fs::create_dir_all(data_dir)?;
        }
        let root = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(data_dir)?;
        validate_data_root(&root.metadata()?)?;
        if create {
            if unsafe { libc::mkdirat(root.as_raw_fd(), c"identity".as_ptr(), 0o700) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
            } else {
                root.sync_all()?;
            }
        }
        let directory = open_at(&root, c"identity", libc::O_RDONLY | libc::O_DIRECTORY)?;
        validate_owner(&directory.metadata()?)?;
        let lock = match open_at(
            &directory,
            c"identity.lock",
            libc::O_RDWR
                | if create {
                    libc::O_CREAT | libc::O_EXCL
                } else {
                    0
                },
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                open_at(&directory, c"identity.lock", libc::O_RDWR)
                    .context("open existing identity lock")?
            }
            Err(error) => return Err(error).context("create identity lock"),
        };
        validate_file(&lock)?;
        lock.lock()?;
        let files = Self {
            root,
            directory,
            _lock: lock,
        };
        files.ensure_attached()?;
        // A replaced lock must not create two independent writer groups.
        let current = open_at(&files.directory, c"identity.lock", libc::O_RDWR)?;
        if !same_file(&current, &files._lock)? {
            anyhow::bail!("identity lock changed while being acquired");
        }
        Ok(files)
    }

    fn ensure_attached(&self) -> anyhow::Result<()> {
        let current = open_at(&self.root, c"identity", libc::O_RDONLY | libc::O_DIRECTORY)?;
        if !same_file(&current, &self.directory)? {
            anyhow::bail!("identity directory changed during persistence");
        }
        validate_owner(&current.metadata()?)
    }

    pub(super) fn sync(&self) -> anyhow::Result<()> {
        self.ensure_attached()?;
        self.directory
            .sync_all()
            .map_err(|_| anyhow::anyhow!("identity replacement durability indeterminate"))?;
        Ok(())
    }

    pub(super) fn read(&self, name: &std::ffi::CStr) -> anyhow::Result<Option<Vec<u8>>> {
        self.ensure_attached()?;
        let mut file = match open_at(&self.directory, name, libc::O_RDONLY | libc::O_NONBLOCK) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_file(&file)?;
        if name == c"device.key" && file.metadata()?.mode() & 0o077 != 0 {
            anyhow::bail!("identity device.key must be owner-only");
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        if name == c"device.key" {
            file.take(33).read_to_end(&mut bytes)?;
        } else {
            file.read_to_end(&mut bytes)?;
        }
        self.ensure_attached()?;
        Ok(Some(std::mem::take(&mut *bytes)))
    }

    /// Before rename, errors preserve the old file. After rename, errors mean
    /// durability is indeterminate; the caller must reload, never roll back.
    pub(super) fn replace(
        &self,
        name: &std::ffi::CStr,
        bytes: &[u8],
        #[cfg(test)] fault: Option<SaveFault>,
    ) -> anyhow::Result<()> {
        self.ensure_attached()?;
        // Validate the existing destination without following it.
        if let Some(bytes) = self.read(name)? {
            let _bytes = zeroize::Zeroizing::new(bytes);
        }
        let temp = std::ffi::CString::new(format!(".identity-{}.tmp", uuid::Uuid::new_v4()))?;
        let mut file = open_at(
            &self.directory,
            &temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            #[cfg(test)]
            if fault == Some(SaveFault::BeforeReplace) {
                anyhow::bail!("injected pre-replacement failure");
            }
            self.ensure_attached()?;
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temp.as_ptr(),
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            #[cfg(test)]
            if fault == Some(SaveFault::AfterReplace) {
                anyhow::bail!("identity replacement durability indeterminate (injected)");
            }
            self.directory
                .sync_all()
                .map_err(|_| anyhow::anyhow!("identity replacement durability indeterminate"))?;
            self.ensure_attached().map_err(|_| {
                anyhow::anyhow!("identity replacement durability indeterminate: directory changed")
            })?;
            Ok(())
        })();
        // Only this operation's exclusively created temporary name is removed.
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), temp.as_ptr(), 0);
            }
        }
        result
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SaveFault {
    BeforeReplace,
    AfterReplace,
    /// One byte reaches the temporary file, then the replace stops.
    #[cfg(windows)]
    PartialWrite,
}

// Unix tests keep this path adapter. Windows device-key opens are `device_key`.
// Targets other than Unix and Windows still refuse every identity file.
#[cfg(any(all(unix, test), not(any(unix, windows))))]
mod portable {
    #[cfg(test)]
    use super::SaveFault;
    #[cfg(unix)]
    use std::io::{Read, Write};
    use std::{
        ffi::CStr,
        fs::File,
        path::{Path, PathBuf},
    };

    pub(crate) struct IdentityFiles {
        directory: PathBuf,
        _lock: File,
    }

    impl IdentityFiles {
        pub(crate) fn open(data_dir: &Path) -> anyhow::Result<Self> {
            Self::open_mode(data_dir, true)
        }

        pub(crate) fn open_existing(data_dir: &Path) -> anyhow::Result<Self> {
            Self::open_mode(data_dir, false)
        }

        #[cfg(unix)]
        fn open_mode(data_dir: &Path, create: bool) -> anyhow::Result<Self> {
            let directory = data_dir.join("identity");
            if create {
                std::fs::create_dir_all(&directory)?;
            }
            let path = directory.join("identity.lock");
            let lock = match File::options()
                .create_new(create)
                .read(true)
                .write(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    File::options().read(true).write(true).open(&path)?
                }
                Err(error) => return Err(error.into()),
            };
            lock.lock()?;
            Ok(Self {
                directory,
                _lock: lock,
            })
        }

        #[cfg(unix)]
        pub(crate) fn read(&self, name: &CStr) -> anyhow::Result<Option<Vec<u8>>> {
            let mut file = match File::open(self.directory.join(name.to_str()?)) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            if name == c"device.key" {
                file.take(33).read_to_end(&mut bytes)?;
            } else {
                file.read_to_end(&mut bytes)?;
            }
            Ok(Some(std::mem::take(&mut *bytes)))
        }

        #[cfg(unix)]
        pub(crate) fn sync(&self) -> anyhow::Result<()> {
            // std does not expose a portable parent-directory sync operation.
            std::fs::metadata(&self.directory)?;
            Ok(())
        }

        #[cfg(unix)]
        pub(crate) fn replace(
            &self,
            name: &CStr,
            bytes: &[u8],
            #[cfg(test)] fault: Option<SaveFault>,
        ) -> anyhow::Result<()> {
            let temp = self
                .directory
                .join(format!(".identity-{}.tmp", uuid::Uuid::new_v4()));
            let mut file = File::options().create_new(true).write(true).open(&temp)?;
            let result = (|| {
                file.write_all(bytes)?;
                file.sync_all()?;
                drop(file);
                #[cfg(test)]
                if fault == Some(SaveFault::BeforeReplace) {
                    anyhow::bail!("injected pre-replacement failure");
                }
                std::fs::rename(&temp, self.directory.join(name.to_str()?))?;
                #[cfg(test)]
                if fault == Some(SaveFault::AfterReplace) {
                    anyhow::bail!("identity replacement durability indeterminate (injected)");
                }
                Ok(())
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&temp);
            }
            result
        }

        #[cfg(not(unix))]
        fn open_mode(_data_dir: &Path, _create: bool) -> anyhow::Result<Self> {
            Err(unsupported_identity_files())
        }

        #[cfg(not(unix))]
        pub(crate) fn read(&self, _name: &CStr) -> anyhow::Result<Option<Vec<u8>>> {
            Err(unsupported_identity_files())
        }

        #[cfg(not(unix))]
        pub(crate) fn sync(&self) -> anyhow::Result<()> {
            Err(unsupported_identity_files())
        }

        #[cfg(not(unix))]
        pub(crate) fn replace(
            &self,
            _name: &CStr,
            _bytes: &[u8],
            #[cfg(test)] _fault: Option<SaveFault>,
        ) -> anyhow::Result<()> {
            Err(unsupported_identity_files())
        }
    }

    #[cfg(not(unix))]
    fn unsupported_identity_files() -> anyhow::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported on this platform",
        )
        .into()
    }

    #[cfg(unix)]
    #[test]
    fn portable_existing_reader_requires_state_without_creating_it() {
        let root = tempfile::tempdir().unwrap();
        assert!(IdentityFiles::open_existing(root.path()).is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        let files = IdentityFiles::open(root.path()).unwrap();
        files.replace(c"device.key", &[7; 32], None).unwrap();
        drop(files);
        let files = IdentityFiles::open_existing(root.path()).unwrap();
        assert_eq!(files.read(c"device.key").unwrap().unwrap(), vec![7; 32]);
        drop(files);
        let lock = root.path().join("identity/identity.lock");
        std::fs::remove_file(&lock).unwrap();
        assert!(IdentityFiles::open_existing(root.path()).is_err());
        assert!(!lock.exists());
    }

    #[cfg(unix)]
    #[test]
    fn portable_adapter_locks_and_replaces_without_changing_format() {
        let root = tempfile::tempdir().unwrap();
        let files = IdentityFiles::open(root.path()).unwrap();
        let other = File::options()
            .read(true)
            .write(true)
            .open(root.path().join("identity/identity.lock"))
            .unwrap();
        assert!(matches!(
            other.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        files.replace(c"credentials.json", b"old", None).unwrap();
        assert!(files
            .replace(c"credentials.json", b"new", Some(SaveFault::BeforeReplace))
            .is_err());
        assert_eq!(files.read(c"credentials.json").unwrap().unwrap(), b"old");
        assert!(files
            .replace(c"credentials.json", b"new", Some(SaveFault::AfterReplace))
            .is_err());
        assert_eq!(files.read(c"credentials.json").unwrap().unwrap(), b"new");
        files.replace(c"device.key", &[7; 64], None).unwrap();
        assert_eq!(files.read(c"device.key").unwrap().unwrap().len(), 33);
        files.sync().unwrap();
        assert!(std::fs::read_dir(root.path().join("identity"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
        drop(files);
        other.try_lock().unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn windows_identity_files_refuse_without_writing() {
        let root = tempfile::tempdir().unwrap();
        let Err(opened) = IdentityFiles::open(root.path()) else {
            panic!("identity files opened on a platform without owner checks");
        };
        assert_eq!(
            opened
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::Unsupported)
        );
        assert!(opened.to_string().contains("unsupported on this platform"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);

        let files = IdentityFiles {
            directory: root.path().to_path_buf(),
            _lock: File::create(root.path().join("lock")).unwrap(),
        };
        for err in [
            files.read(c"device.key").unwrap_err(),
            files.replace(c"device.key", &[7; 32], None).unwrap_err(),
            files.sync().unwrap_err(),
        ] {
            assert!(
                err.to_string().contains("unsupported on this platform"),
                "{err}"
            );
        }
        assert!(!root.path().join("identity").exists());
        assert!(!root.path().join("device.key").exists());
    }
}

#[cfg(unix)]
fn open_at(directory: &File, name: &std::ffi::CStr, flags: libc::c_int) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn validate_owner(metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        anyhow::bail!("identity path must be owned by the Runtime user and not writable by others");
    }
    Ok(())
}

/// The data root keeps its owner's group permissions (Ubuntu umask 002), as the
/// installation writer admits it; the identity folder and files stay strict.
#[cfg(unix)]
fn validate_data_root(metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o002 != 0 {
        anyhow::bail!(
            "identity data root must be owned by the Runtime user and not world-writable"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file(file: &File) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    validate_owner(&metadata)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        anyhow::bail!("identity file must be regular with one link");
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &File, right: &File) -> std::io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

/// Windows device key. The identity directory, the lock, and `device.key` go
/// through the owner-only helper. Credential bytes are still not written here.
#[cfg(windows)]
mod device_key {
    use std::ffi::{CStr, OsStr};
    use std::fs::File;
    use std::io::Read;
    #[cfg(test)]
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use elastos_win_custody::{
        create_owner_dir, flush_accepted_directory, one_component_name, open_owner_dir,
        open_owner_file, refuse_other_writers, reopen_owner_file, replace_owner_file, CustodyError,
        Disp, ReplaceStep, READ_EXISTING, READ_WRITE,
    };

    // Visible in `crate::store` only. That is the same reach as the Unix
    // `pub(super)` type in `store::files`: `store` can use it, and the rest of
    // the crate cannot. `pub(super)` on this struct would stop at `store::files`,
    // so the re-export above could not name the type in `store`.
    #[derive(Debug)]
    pub(in crate::store) struct IdentityFiles {
        root: PathBuf,
        directory: PathBuf,
        _lock: File,
    }

    impl IdentityFiles {
        pub(in crate::store) fn open(data_dir: &Path) -> anyhow::Result<Self> {
            Self::open_mode(data_dir, true)
        }

        pub(in crate::store) fn open_existing(data_dir: &Path) -> anyhow::Result<Self> {
            Self::open_mode(data_dir, false)
        }

        fn open_mode(data_dir: &Path, create: bool) -> anyhow::Result<Self> {
            let root = data_dir.to_path_buf();
            if create {
                create_missing_owner_dirs(&root)?;
            }
            refuse_other_writers(&root)?;
            let directory = ensure_identity(&root, create)?;
            let _lock = open_lock(&directory, create)?;
            Ok(Self {
                root,
                directory,
                _lock,
            })
        }

        pub(in crate::store) fn sync(&self) -> anyhow::Result<()> {
            self.admit()?;
            match flush_accepted_directory(&self.directory) {
                Ok(()) => Ok(()),
                Err(CustodyError::DurabilityIndeterminate) => Err(anyhow::anyhow!(
                    "identity replacement durability indeterminate"
                )),
                Err(error) => Err(error.into()),
            }
        }

        pub(in crate::store) fn read(&self, name: &CStr) -> anyhow::Result<Option<Vec<u8>>> {
            self.admit()?;
            let name = one_component(name)?;
            let mut file = match open_owner_file(
                &self.directory.join(name),
                READ_EXISTING,
                Disp::OpenExisting,
            ) {
                Ok(file) => file,
                Err(error) if io_kind(&error) == Some(std::io::ErrorKind::NotFound) => {
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            };
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            if name == "device.key" {
                file.take(33).read_to_end(&mut bytes)?;
            } else {
                file.read_to_end(&mut bytes)?;
            }
            self.admit()?;
            Ok(Some(std::mem::take(&mut *bytes)))
        }

        /// Creates `device.key` when it is absent. The shared helper writes the
        /// bytes to a temporary file in the identity directory, flushes them,
        /// and renames them onto `device.key`. An existing key is left as it
        /// is. Any other name stays refused.
        pub(in crate::store) fn replace(
            &self,
            name: &CStr,
            bytes: &[u8],
            #[cfg(test)] fault: Option<super::SaveFault>,
        ) -> anyhow::Result<()> {
            self.admit()?;
            let name = one_component(name)?;
            if name != "device.key" {
                return Err(unsupported_other_identity_file());
            }
            let path = self.directory.join(name);
            match open_owner_file(&path, READ_EXISTING, Disp::OpenExisting) {
                Ok(existing) => {
                    drop(existing);
                    anyhow::bail!("identity device.key already exists");
                }
                Err(error) if io_kind(&error) == Some(std::io::ErrorKind::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
            // The helper owns the write, flush, rename, discard, and directory
            // flush. These steps keep the identity directory owner-only and the
            // same injected failures as before.
            let result = replace_owner_file(&path, bytes, false, |step| match step {
                ReplaceStep::Prepare(file) => {
                    #[cfg(test)]
                    if fault == Some(super::SaveFault::PartialWrite) {
                        let prefix = if bytes.is_empty() { bytes } else { &bytes[..1] };
                        file.write_all(prefix).map_err(CustodyError::Io)?;
                        return Err(injected("injected partial write"));
                    }
                    let _ = file;
                    Ok(())
                }
                ReplaceStep::AfterFileSync => {
                    #[cfg(test)]
                    if fault == Some(super::SaveFault::BeforeReplace) {
                        return Err(injected("injected pre-replacement failure"));
                    }
                    self.admit()
                        .map_err(|error| CustodyError::Io(std::io::Error::other(error.to_string())))
                }
                ReplaceStep::AfterRename => {
                    #[cfg(test)]
                    if fault == Some(super::SaveFault::AfterReplace) {
                        return Err(injected(
                            "identity replacement durability indeterminate (injected)",
                        ));
                    }
                    self.admit()
                        .map_err(|_| injected("identity replacement durability indeterminate"))
                }
            });
            match result {
                Ok(()) => Ok(()),
                Err(CustodyError::DurabilityIndeterminate) => Err(anyhow::anyhow!(
                    "identity replacement durability indeterminate"
                )),
                Err(error) => Err(error.into()),
            }
        }

        fn admit(&self) -> anyhow::Result<()> {
            refuse_other_writers(&self.root)?;
            drop(open_owner_dir(&self.directory)?);
            // The lock handle is already held. Re-open the name so a replaced
            // lock file cannot keep a foreign DACL. Unix compares the lock inode
            // after acquire; this is that check for the DACL.
            drop(reopen_owner_file(&self.directory.join("identity.lock"))?);
            Ok(())
        }
    }

    /// Create each missing directory from the first existing ancestor down to
    /// `path`. Each new directory uses the owner-only helper. An existing path
    /// is left unchanged; the caller checks the data root.
    fn create_missing_owner_dirs(path: &Path) -> anyhow::Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut missing = vec![path.to_path_buf()];
        loop {
            let parent = missing
                .last()
                .and_then(|dir| dir.parent())
                .map(Path::to_path_buf)
                .filter(|dir| !dir.as_os_str().is_empty());
            let Some(parent) = parent else {
                anyhow::bail!("absolute local disk path required");
            };
            match std::fs::symlink_metadata(&parent) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing.push(parent),
                Err(error) => return Err(error.into()),
            }
        }
        for dir in missing.iter().rev() {
            match create_owner_dir(dir) {
                Ok(created) => created.sync_all()?,
                Err(error) if io_kind(&error) == Some(std::io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn injected(message: &'static str) -> CustodyError {
        CustodyError::Io(std::io::Error::other(message))
    }

    fn ensure_identity(root: &Path, create: bool) -> anyhow::Result<PathBuf> {
        let path = root.join("identity");
        if create {
            match create_owner_dir(&path) {
                Ok(file) => {
                    file.sync_all()?;
                    return Ok(path);
                }
                Err(error) if io_kind(&error) == Some(std::io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error.into()),
            }
        }
        drop(open_owner_dir(&path)?);
        Ok(path)
    }

    fn open_lock(directory: &Path, create: bool) -> anyhow::Result<File> {
        let path = directory.join("identity.lock");
        let file = if create {
            match open_owner_file(&path, READ_WRITE, Disp::CreateNew) {
                Ok(file) => file,
                Err(error) if io_kind(&error) == Some(std::io::ErrorKind::AlreadyExists) => {
                    open_owner_file(&path, READ_WRITE, Disp::OpenExisting)?
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            open_owner_file(&path, READ_WRITE, Disp::OpenExisting)?
        };
        file.lock()?;
        // Unix re-checks the lock inode after acquire. Re-open this name and
        // require the owner-only DACL on whatever the directory now has.
        drop(reopen_owner_file(&path)?);
        Ok(file)
    }

    fn one_component(name: &CStr) -> anyhow::Result<&str> {
        let text = name
            .to_str()
            .map_err(|_| anyhow::anyhow!("identity file name is not one component"))?;
        if !one_component_name(OsStr::new(text)) {
            anyhow::bail!("identity file name is not one component");
        }
        Ok(text)
    }

    fn unsupported_other_identity_file() -> anyhow::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported on this platform",
        )
        .into()
    }

    fn io_kind(error: &CustodyError) -> Option<std::io::ErrorKind> {
        match error {
            CustodyError::Io(inner) => Some(inner.kind()),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;
        use std::process::Command;

        use super::super::super::load_or_create_device_key;
        use super::super::SaveFault;
        use super::IdentityFiles;

        const MARKER: &[u8] = b"target-bytes-stay";

        fn icacls(args: &[&str]) {
            let output = Command::new("icacls").args(args).output().expect("icacls");
            assert!(
                output.status.success(),
                "icacls {args:?}\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn grant_users_full(dir: &Path) {
            let path = dir.display().to_string();
            // A directory this slice created already has a protected DACL, so
            // removing inherited ACEs can report that there is nothing to
            // remove. The grant is the ACE the refusal has to see.
            let _removed = Command::new("icacls")
                .args([&path, "/inheritance:r"])
                .output();
            icacls(&[&path, "/grant", "*S-1-5-32-545:(OI)(CI)(F)"]);
        }

        fn junction(link: &Path, target: &Path) {
            let status = Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &link.display().to_string(),
                    &target.display().to_string(),
                ])
                .status()
                .expect("mklink");
            assert!(status.success(), "mklink /J");
        }

        #[test]
        fn junction_at_device_key_is_refused_and_target_bytes_stay() {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let files = IdentityFiles::open(&data).unwrap();
            let outside = tempfile::tempdir().unwrap();
            let marker = outside.path().join("kept.bin");
            std::fs::write(&marker, MARKER).unwrap();
            junction(&data.join("identity").join("device.key"), outside.path());
            let read_err = files.read(c"device.key").unwrap_err();
            assert!(
                read_err.to_string().contains("reparse point refused"),
                "{read_err}"
            );
            let replace_err = files.replace(c"device.key", &[9; 32], None).unwrap_err();
            assert!(
                replace_err.to_string().contains("reparse point refused"),
                "{replace_err}"
            );
            assert_eq!(std::fs::read(&marker).unwrap(), MARKER);
            assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
        }

        #[test]
        fn device_key_second_open_returns_the_same_32_bytes() {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let first = load_or_create_device_key(&data).unwrap();
            let second = load_or_create_device_key(&data).unwrap();
            assert_eq!(first.as_slice(), second.as_slice());
            assert_eq!(first.len(), 32);
            assert_ne!(first.as_slice(), &[0u8; 32]);
            assert_eq!(
                std::fs::read(data.join("identity").join("device.key")).unwrap(),
                first.as_slice()
            );
        }

        #[test]
        fn parent_writable_by_other_users_is_refused() {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            std::fs::create_dir(&data).unwrap();
            let marker = data.join("kept.bin");
            std::fs::write(&marker, MARKER).unwrap();
            grant_users_full(&data);
            let opened = IdentityFiles::open(&data).unwrap_err();
            assert!(
                opened.to_string().contains("DACL is not owner-only"),
                "{opened}"
            );
            assert!(!data.join("identity").exists());
            assert!(!data.join("identity").join("device.key").exists());
            assert_eq!(std::fs::read(&marker).unwrap(), MARKER);

            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let key = load_or_create_device_key(&data).unwrap();
            let path = data.join("identity").join("device.key");
            assert_eq!(std::fs::read(&path).unwrap(), key.as_ref());
            grant_users_full(&data.join("identity"));
            let again = load_or_create_device_key(&data).unwrap_err();
            assert!(
                again.to_string().contains("DACL is not owner-only"),
                "{again}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), key.as_ref());
        }

        #[test]
        fn windows_credentials_replace_stays_refused() {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let files = IdentityFiles::open(&data).unwrap();
            let err = files
                .replace(c"credentials.json", b"secret", None)
                .unwrap_err();
            assert!(
                err.to_string().contains("unsupported on this platform"),
                "{err}"
            );
            assert!(!data.join("identity").join("credentials.json").exists());
        }

        fn current_user_ace() -> String {
            let output = Command::new("whoami")
                .args(["/user", "/fo", "csv", "/nh"])
                .output()
                .expect("whoami");
            assert!(
                output.status.success(),
                "whoami /user\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8_lossy(&output.stdout);
            let sid = text
                .lines()
                .next()
                .and_then(|line| line.split(',').nth(1))
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            assert!(
                sid.starts_with("S-1-"),
                "whoami did not print a SID: {text}"
            );
            format!("*{sid}:(OI)(CI)(F)")
        }

        /// Explicit user, SYSTEM, and Administrators full control, with inherited
        /// ACEs removed. `extra` is appended before that removal, so a Users or
        /// Everyone grant stays explicit.
        fn grant_profile_aces(dir: &Path, extra: &[&str]) {
            let path = dir.display().to_string();
            let mut aces = vec![
                current_user_ace(),
                "*S-1-5-18:(OI)(CI)(F)".to_string(),
                "*S-1-5-32-544:(OI)(CI)(F)".to_string(),
            ];
            aces.extend(extra.iter().map(|ace| (*ace).to_string()));
            for ace in &aces {
                icacls(&[&path, "/grant", ace]);
            }
            icacls(&[&path, "/inheritance:r"]);
        }

        fn identity_names(data: &Path) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(data.join("identity"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }

        /// Plan check: `load_or_create_device_key` on an empty data directory that
        /// already exists. The directory is not a missing child this code creates.
        /// Its DACL is the accepted profile shape (user, SYSTEM, Administrators).
        /// Its owner may be the current user, SYSTEM, or Administrators.
        /// A raw temp directory can also grant Users, and that grant stays refused.
        #[test]
        fn preexisting_empty_data_root_with_system_and_administrators_is_accepted() {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("empty-data");
            std::fs::create_dir(&data).unwrap();
            assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
            grant_profile_aces(&data, &[]);
            let first = load_or_create_device_key(&data).unwrap();
            let second = load_or_create_device_key(&data).unwrap();
            assert_eq!(first.as_slice(), second.as_slice());
            assert_eq!(first.len(), 32);
            assert_ne!(first.as_slice(), &[0u8; 32]);
            assert_eq!(
                std::fs::read(data.join("identity").join("device.key")).unwrap(),
                first.as_slice()
            );
        }

        #[test]
        fn preexisting_data_root_writable_by_users_or_everyone_is_refused() {
            for sid in ["*S-1-5-32-545:(OI)(CI)(F)", "*S-1-1-0:(OI)(CI)(F)"] {
                let root = tempfile::tempdir().unwrap();
                let data = root.path().join("empty-data");
                std::fs::create_dir(&data).unwrap();
                grant_profile_aces(&data, &[sid]);
                let opened = IdentityFiles::open(&data).unwrap_err();
                assert!(
                    opened.to_string().contains("DACL is not owner-only"),
                    "{sid}: {opened}"
                );
                assert!(!data.join("identity").exists());
                assert!(!data.join("identity").join("device.key").exists());
            }
        }

        #[test]
        fn partial_device_key_write_leaves_no_device_key_and_the_next_start_creates_one() {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            let files = IdentityFiles::open(&data).unwrap();
            let err = files
                .replace(c"device.key", &[7; 32], Some(SaveFault::PartialWrite))
                .unwrap_err();
            assert!(err.to_string().contains("injected partial write"), "{err}");
            drop(files);
            assert!(!data.join("identity").join("device.key").exists());
            assert_eq!(identity_names(&data), vec!["identity.lock".to_string()]);
            let key = load_or_create_device_key(&data).unwrap();
            assert_eq!(key.len(), 32);
            assert_ne!(key.as_slice(), &[0u8; 32]);
            assert_eq!(
                std::fs::read(data.join("identity").join("device.key")).unwrap(),
                key.as_slice()
            );
            assert!(
                identity_names(&data)
                    .iter()
                    .all(|name| { !name.ends_with(".tmp") && !name.contains(".tmp-") }),
                "a temporary key file remains"
            );
        }

        #[test]
        fn missing_intermediate_directories_are_created_owner_only() {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("a").join("b").join("data");
            assert!(IdentityFiles::open_existing(&data).is_err());
            assert!(!root.path().join("a").exists());
            let first = load_or_create_device_key(&data).unwrap();
            let second = load_or_create_device_key(&data).unwrap();
            assert_eq!(first.as_slice(), second.as_slice());
            assert_eq!(first.len(), 32);
            assert_ne!(first.as_slice(), &[0u8; 32]);
            for dir in [
                root.path().join("a"),
                root.path().join("a").join("b"),
                data.clone(),
                data.join("identity"),
            ] {
                elastos_win_custody::open_owner_dir(&dir)
                    .unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
            }
            elastos_win_custody::open_owner_file(
                &data.join("identity").join("device.key"),
                elastos_win_custody::READ_EXISTING,
                elastos_win_custody::Disp::OpenExisting,
            )
            .unwrap();
        }
    }
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn fresh_identity_lock_creation_is_safe_with_concurrent_openers() {
        let root = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    barrier.wait();
                    let files = IdentityFiles::open(root.path()).unwrap();
                    assert!(files.read(c"device.key").unwrap().is_none());
                });
            }
        });
        assert_eq!(
            std::fs::read_dir(root.path().join("identity"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn identity_files_are_private_and_parent_or_file_redirection_is_rejected() {
        for name in [
            "identity",
            "device.key",
            "credentials.json",
            "identity.lock",
        ] {
            let root = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let sentinel = outside.path().join("sentinel");
            std::fs::write(&sentinel, b"preserved").unwrap();
            if name == "identity" {
                symlink(outside.path(), root.path().join(name)).unwrap();
                assert!(IdentityFiles::open(root.path()).is_err());
            } else {
                drop(IdentityFiles::open(root.path()).unwrap());
                let target = root.path().join("identity").join(name);
                if target.exists() {
                    std::fs::remove_file(&target).unwrap();
                }
                symlink(&sentinel, &target).unwrap();
                if name == "identity.lock" {
                    assert!(IdentityFiles::open(root.path()).is_err());
                } else {
                    let files = IdentityFiles::open(root.path()).unwrap();
                    let name = std::ffi::CString::new(name).unwrap();
                    assert!(files.read(&name).is_err());
                    assert!(files.replace(&name, b"replacement", None).is_err());
                }
            }
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserved");
        }
        let root = tempfile::tempdir().unwrap();
        let files = IdentityFiles::open(root.path()).unwrap();
        files.replace(c"device.key", &[7; 32], None).unwrap();
        files
            .replace(c"credentials.json", b"encrypted fixture", None)
            .unwrap();
        for name in ["device.key", "credentials.json", "identity.lock"] {
            let mode = std::fs::metadata(root.path().join("identity").join(name))
                .unwrap()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(files.directory.metadata().unwrap().mode() & 0o777, 0o700);
        files.replace(c"device.key", &[7; 64], None).unwrap();
        assert_eq!(files.read(c"device.key").unwrap().unwrap().len(), 33);
    }

    #[test]
    fn identity_descriptor_refuses_replaced_parent_without_touching_redirect() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let files = IdentityFiles::open(root.path()).unwrap();
        files.replace(c"credentials.json", b"old", None).unwrap();
        std::fs::rename(root.path().join("identity"), root.path().join("retained")).unwrap();
        symlink(outside.path(), root.path().join("identity")).unwrap();
        assert!(files.replace(c"credentials.json", b"new", None).is_err());
        assert!(files.read(c"credentials.json").is_err());
        assert_eq!(
            std::fs::read(root.path().join("retained/credentials.json")).unwrap(),
            b"old"
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn identity_files_reject_hard_links_non_files_and_unsafe_permissions() {
        let root = tempfile::tempdir().unwrap();
        let files = IdentityFiles::open(root.path()).unwrap();
        let target = root.path().join("identity/credentials.json");
        files.replace(c"credentials.json", b"old", None).unwrap();
        let link = root.path().join("alias");
        std::fs::hard_link(&target, &link).unwrap();
        assert!(files.replace(c"credentials.json", b"new", None).is_err());
        assert_eq!(std::fs::read(&link).unwrap(), b"old");
        std::fs::remove_file(&link).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(files.read(c"credentials.json").is_err());
        std::fs::remove_file(&target).unwrap();
        std::fs::create_dir(&target).unwrap();
        assert!(files.read(c"credentials.json").is_err());
        std::fs::set_permissions(
            root.path().join("identity"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(files.read(c"device.key").is_err());
        assert!(IdentityFiles::open(root.path()).is_err());
    }

    #[test]
    fn identity_accepts_group_writable_data_root_and_keeps_identity_folder_strict() {
        let root = tempfile::tempdir().unwrap();
        let set = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        set(root.path(), 0o770);
        drop(IdentityFiles::open(root.path()).unwrap());
        IdentityFiles::open_existing(root.path()).unwrap();
        set(&root.path().join("identity"), 0o770);
        assert!(IdentityFiles::open_existing(root.path()).is_err());
        set(&root.path().join("identity"), 0o700);
        set(root.path(), 0o777);
        assert!(IdentityFiles::open_existing(root.path()).is_err());
        set(root.path(), 0o700);
    }

    #[test]
    fn identity_key_replacement_faults_leave_complete_old_or_new_bytes() {
        for fault in [SaveFault::BeforeReplace, SaveFault::AfterReplace] {
            let root = tempfile::tempdir().unwrap();
            let files = IdentityFiles::open(root.path()).unwrap();
            assert!(files.replace(c"device.key", &[7; 32], Some(fault)).is_err());
            let key = files.read(c"device.key").unwrap();
            assert_eq!(
                key,
                if fault == SaveFault::BeforeReplace {
                    None
                } else {
                    Some(vec![7; 32])
                }
            );
            assert!(std::fs::read_dir(root.path().join("identity"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")));
        }
    }
}
