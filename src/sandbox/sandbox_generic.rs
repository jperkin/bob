use crate::sandbox::Sandbox;
use std::path::Path;
use std::process::ExitStatus;

impl Sandbox {
    pub fn mount_bindfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &Vec<&str>,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn mount_devfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &[&str],
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn mount_fdfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &Vec<&str>,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn mount_nfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &Vec<&str>,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn mount_procfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &Vec<&str>,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn mount_tmpfs(
        &self,
        _src: &Path,
        _dest: &Path,
        _opts: &Vec<&str>,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn unmount_bindfs(
        &self,
        _dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn unmount_devfs(
        &self,
        _dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn unmount_fdfs(
        &self,
        _dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn unmount_nfs(
        &self,
        _dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn unmount_procfs(
        &self,
        _dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }

    pub fn unmount_tmpfs(
        &self,
        _dest: &Path,
    ) -> anyhow::Result<Option<ExitStatus>> {
        Ok(None)
    }
}
