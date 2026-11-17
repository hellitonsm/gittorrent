//! Escrita atômica (temp + rename) e permissão restrita de segredos locais.

use std::fs;
use std::path::Path;

/// Grava `bytes` em `path` via arquivo temporário no mesmo diretório e `rename`.
/// Um crash no meio da escrita não deixa o destino pela metade.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(parent)?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("caminho sem nome de arquivo: {}", path.display()))?;
    let tmp = parent.join(format!(".{}.tmp", file_name.to_string_lossy()));

    if let Err(e) = fs::write(&tmp, bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Dono lê e escreve; grupo e outros não. No-op fora de Unix.
pub fn restrict_owner_readwrite(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path)?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(path, perm)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("p2pgit-fsutil-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn atomic_write_replaces_whole_file() {
        let dir = scratch();
        let path = dir.join("commit.json");
        atomic_write(&path, b"primeiro").unwrap();
        atomic_write(&path, b"segundo").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"segundo");
        assert!(!dir.join(".commit.json.tmp").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn restrict_owner_readwrite_is_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let path = dir.join("identity.json");
        fs::write(&path, b"{}").unwrap();
        restrict_owner_readwrite(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }
}
