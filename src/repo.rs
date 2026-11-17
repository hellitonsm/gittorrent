use crate::identity::RepoIdentity;
use crate::sanitizer::{inspect_file_content, ContentStatus};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const MAX_COMMIT_SIZE_BYTES: usize = 512 * 1024; // 512 KB exatos

/// Arquivo de padrões de exclusão da varredura (sintaxe gitignore simples).
const IGNORE_FILE: &str = ".p2pgitignore";

/// Diretórios que nunca entram em um commit.
const SKIP_DIRS: [&str; 4] = [".p2pgit", ".git", "target", "node_modules"];

/// Entrada do arquivo `.binary`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct BinaryManifestEntry {
    pub file_path: String,
    pub md5_hash: String,
    /// Opcional; quando presente, é preferido na verificação.
    #[serde(default)]
    pub sha256_hash: Option<String>,
    pub torrent_infohash: Option<String>, // Hash para busca na rede BitTorrent comum
    pub description: String,
}

/// Repositórios essenciais linkados (Submódulos P2P).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LinkedRepository {
    pub name: String,
    pub target_address_or_alias: String, // Endereço .p2pgit ou alias
    pub pinned_commit_hash: String,
    pub mount_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Commit {
    pub parent_hash: Option<String>,
    pub author_pubkey: String,
    pub timestamp: u64,
    pub message: String,
    /// Mapa de caminho_arquivo -> conteúdo em texto puro.
    /// `BTreeMap` garante ordem determinística (hash canônico).
    pub files: BTreeMap<String, String>,
    /// Lista de binários externos referenciados via MD5/Torrent.
    pub external_binaries: Vec<BinaryManifestEntry>,
    /// Repositórios essenciais vinculados.
    pub linked_repos: Vec<LinkedRepository>,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PullRequest {
    pub pr_id: String,
    pub target_repo_address: String,
    pub fork_author_pubkey: String,
    /// HEAD do fork no momento da proposta (detecta PRs desatualizados).
    pub fork_head_hash: String,
    /// Commit do repositório original de onde o fork divergiu.
    /// É o que permite ao original calcular conflitos sem ter a cadeia do fork.
    #[serde(default)]
    pub base_commit_hash: Option<String>,
    pub proposed_commit: Commit,
    /// Ed25519 do autor do fork sobre o payload canônico do PR.
    pub signature: String,
}

impl PullRequest {
    /// Payload canônico que é assinado pela chave privada do fork.
    fn payload(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.pr_id,
            self.target_repo_address,
            self.fork_author_pubkey,
            self.fork_head_hash,
            self.base_commit_hash.as_deref().unwrap_or(""),
            self.proposed_commit.compute_hash()
        )
    }

    /// Cria e assina um PR com a chave privada do fork.
    pub fn create(
        identity: &RepoIdentity,
        target_address: String,
        proposed_commit: Commit,
        fork_head_hash: String,
        base_commit_hash: Option<String>,
    ) -> anyhow::Result<Self> {
        let pr_id: String = fork_head_hash.chars().take(16).collect();
        let mut pr = Self {
            pr_id,
            target_repo_address: target_address,
            fork_author_pubkey: identity.public_key_hex.clone(),
            fork_head_hash,
            base_commit_hash,
            proposed_commit,
            signature: String::new(),
        };
        pr.signature = identity.sign_data(pr.payload().as_bytes())?;
        Ok(pr)
    }

    /// Verifica a integridade do PR: assinatura do fork E autor do commit
    /// proposta idêntico ao autor do PR (impede reencaminhamento de commit
    /// de terceiros como se fosse trabalho do fork).
    pub fn is_valid(&self) -> bool {
        self.fork_author_pubkey == self.proposed_commit.author_pubkey
            && RepoIdentity::verify_signature(
                &self.fork_author_pubkey,
                self.payload().as_bytes(),
                &self.signature,
            )
    }
}

impl Commit {
    pub fn create_signed(
        identity: &RepoIdentity,
        parent_hash: Option<String>,
        message: String,
        files: BTreeMap<String, String>,
        external_binaries: Vec<BinaryManifestEntry>,
        linked_repos: Vec<LinkedRepository>,
        force_allow_suspicious: bool,
    ) -> anyhow::Result<Self> {
        let mut total_size = 0;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        for (path, content) in &files {
            total_size += content.len();

            // 1. Verifica limite de 512 KB.
            if total_size > MAX_COMMIT_SIZE_BYTES {
                anyhow::bail!(
                    "Commit excedeu o limite máximo de 512 KB ({} bytes).",
                    total_size
                );
            }

            // 2. Bloqueia binários e Base64 no upload.
            match inspect_file_content(Path::new(path), content.as_bytes()) {
                ContentStatus::CleanText => {}
                ContentStatus::BinaryDetected(reason) => {
                    anyhow::bail!(
                        "BLOQUEADO: Arquivo binário não permitido no código puro ({}). Adicione-o ao arquivo '.binary' com seu MD5.",
                        reason
                    );
                }
                ContentStatus::Base64PayloadDetected(reason) => {
                    if !force_allow_suspicious {
                        anyhow::bail!(
                            "BLOQUEADO: Possível Base64 detectado ({}). Use '--force-text' apenas se for código legítimo.",
                            reason
                        );
                    }
                }
            }
        }

        let mut commit = Self {
            parent_hash,
            author_pubkey: identity.public_key_hex.clone(),
            timestamp: now,
            message,
            files,
            external_binaries,
            linked_repos,
            signature: String::new(),
        };

        // Valida timestamp: não pode ser muito no futuro (skew de 5 min).
        if commit.timestamp > now + 300 {
            anyhow::bail!("Timestamp do commit está no futuro (skew > 5 min).");
        }

        let payload_hash = commit.compute_hash();
        commit.signature = identity.sign_data(payload_hash.as_bytes())?;

        Ok(commit)
    }

    /// Hash canônico do conteúdo do commit (sem assinatura).
    ///
    /// Serializa o commit inteiro em JSON com os vetores ordenados, de modo
    /// que TODO campo (inclusive `mount_path`, `torrent_infohash`,
    /// `description`) seja coberto pelo hash — sem risco de campos esquecidos.
    pub fn compute_hash(&self) -> String {
        let mut canonical = self.clone();
        canonical.signature = String::new();
        canonical
            .external_binaries
            .sort_by(|a, b| a.file_path.cmp(&b.file_path));
        canonical.linked_repos.sort_by(|a, b| a.name.cmp(&b.name));

        let json = serde_json::to_vec(&canonical).expect("commit é sempre serializável");
        hex::encode(Sha256::digest(&json))
    }

    /// Verifica a integridade criptográfica do commit.
    pub fn is_signature_valid(&self) -> bool {
        let hash = self.compute_hash();
        RepoIdentity::verify_signature(&self.author_pubkey, hash.as_bytes(), &self.signature)
    }
}

/// Valida o MD5 de um arquivo baixado contra a entrada do manifesto `.binary`.
pub fn verify_md5(content: &[u8], expected_hex: &str) -> anyhow::Result<()> {
    let mut hasher = Md5::new();
    hasher.update(content);
    let actual = hex::encode(hasher.finalize());

    if !actual.eq_ignore_ascii_case(expected_hex) {
        anyhow::bail!(
            "MD5 não confere! esperado='{}', obtido='{}'. Não execute o arquivo.",
            expected_hex,
            actual
        );
    }
    Ok(())
}

/// MD5 (hex, lowercase) do conteúdo — usado pelo `add-binary`.
pub fn compute_md5_hex(content: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// SHA-256 (hex, lowercase) do conteúdo — alternativa forte ao MD5.
pub fn compute_sha256_hex(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    hex::encode(digest)
}

/// Valida o SHA-256 de um arquivo baixado (preferido quando presente).
pub fn verify_sha256(content: &[u8], expected_hex: &str) -> anyhow::Result<()> {
    let actual = compute_sha256_hex(content);
    if !actual.eq_ignore_ascii_case(expected_hex) {
        anyhow::bail!(
            "SHA-256 não confere! esperado='{}', obtido='{}'. Não execute o arquivo.",
            expected_hex,
            actual
        );
    }
    Ok(())
}

/// Magnet URI BitTorrent a partir de um infohash (`urn:btih:<infohash>`).
pub fn magnet_from_infohash(infohash: &str, file_name: &str) -> String {
    format!("magnet:?xt=urn:btih:{}&dn={}", infohash, file_name)
}

/// Varre o diretório recursivamente e coleta todos os arquivos de texto puro.
///
/// Ignora `SKIP_DIRS`, diretórios/arquivos ocultos (exceto `.p2pgitignore`),
/// os padrões declarados em `.p2pgitignore` e os binários já listados no
/// manifesto `.binary` (que saem do commit de código puro). Arquivos
/// não-UTF8 abortam o commit com instrução para movê-los ao `.binary`.
pub fn collect_files(root: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    let patterns = load_ignore_patterns(root);
    let manifest = load_manifest_paths(root);
    let mut files = BTreeMap::new();
    walk_tree(root, root, &patterns, &manifest, &mut files)?;
    Ok(files)
}

/// Caminhos (`file_path`) listados no manifesto `.binary`, para que a
/// varredura não tente embutir binários no commit de código puro.
fn load_manifest_paths(root: &Path) -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string(root.join(".binary")) else {
        return Vec::new();
    };
    let Ok(entries) = serde_json::from_str::<Vec<BinaryManifestEntry>>(&raw) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .map(|e| e.file_path.trim_start_matches("./").replace('\\', "/"))
        .collect()
}

fn load_ignore_patterns(root: &Path) -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string(root.join(IGNORE_FILE)) else {
        return Vec::new();
    };
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.trim_end_matches('/').to_string())
        .collect()
}

/// Um padrão sem `/` casa com o nome do arquivo/diretório em qualquer
/// profundidade; um padrão com `/` casa com o caminho relativo completo.
fn matches_ignore(pattern: &str, rel_path: &str) -> bool {
    if pattern.contains('/') {
        glob_match(pattern.as_bytes(), rel_path.as_bytes())
    } else {
        let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        glob_match(pattern.as_bytes(), name.as_bytes())
    }
}

/// Glob mínimo: `*` não atravessa separadores, `**` atravessa, `?` = 1 caractere.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            if pattern.get(1) == Some(&b'*') {
                let rest = &pattern[2..];
                glob_match(rest, text) || (!text.is_empty() && glob_match(pattern, &text[1..]))
            } else {
                let rest = &pattern[1..];
                glob_match(rest, text)
                    || (!text.is_empty() && text[0] != b'/' && glob_match(pattern, &text[1..]))
            }
        }
        (Some(b'?'), Some(&c)) if c != b'/' => glob_match(&pattern[1..], &text[1..]),
        (Some(&a), Some(&b)) if a == b => glob_match(&pattern[1..], &text[1..]),
        _ => false,
    }
}

fn walk_tree(
    base: &Path,
    dir: &Path,
    patterns: &[String],
    manifest_paths: &[String],
    out: &mut BTreeMap<String, String>,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        if path.is_dir() {
            let skipped = SKIP_DIRS.contains(&name.as_str())
                || name.starts_with('.')
                || patterns.iter().any(|p| matches_ignore(p, &rel));
            if !skipped {
                walk_tree(base, &path, patterns, manifest_paths, out)?;
            }
        } else if name == IGNORE_FILE
            || (!name.starts_with('.')
                && !patterns.iter().any(|p| matches_ignore(p, &rel))
                && !manifest_paths.iter().any(|p| p == &rel))
        {
            let bytes = std::fs::read(&path)?;
            let content = String::from_utf8(bytes).map_err(|_| {
                anyhow::anyhow!("Arquivo '{}' é binário! Mova para o '.binary'.", rel)
            })?;
            out.insert(rel, content);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_files() -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        files.insert("main.rs".into(), "fn main() {}".into());
        files
    }

    #[test]
    fn signed_commit_is_valid_and_tampering_detected() {
        let id = RepoIdentity::generate(None);
        let mut commit = Commit::create_signed(
            &id,
            None,
            "initial".into(),
            base_files(),
            vec![],
            vec![],
            false,
        )
        .unwrap();
        assert!(commit.is_signature_valid());

        commit.files.insert("x.rs".into(), "fn x() {}".into());
        assert!(!commit.is_signature_valid());
    }

    #[test]
    fn binary_file_is_rejected() {
        let id = RepoIdentity::generate(None);
        let mut files = base_files();
        files.insert("bad.bin".into(), String::from_utf8(vec![0, 1, 2]).unwrap());
        assert!(
            Commit::create_signed(&id, None, "x".into(), files, vec![], vec![], false).is_err()
        );
    }

    #[test]
    fn md5_verification() {
        let data = b"hello";
        // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
        verify_md5(data, "5d41402abc4b2a76b9719d911017c592").unwrap();
        assert!(verify_md5(data, "00000000000000000000000000000000").is_err());
    }

    #[test]
    fn oversized_commit_is_rejected() {
        let id = RepoIdentity::generate(None);
        let mut files = BTreeMap::new();
        files.insert("big.txt".into(), "a".repeat(MAX_COMMIT_SIZE_BYTES + 1));
        assert!(
            Commit::create_signed(&id, None, "x".into(), files, vec![], vec![], false).is_err()
        );
    }

    #[test]
    fn hash_is_canonical_and_covers_all_metadata() {
        let id = RepoIdentity::generate(None);
        let binaries = vec![BinaryManifestEntry {
            file_path: "assets/t.png".into(),
            md5_hash: "d41d8cd98f00b204e9800998ecf8427e".into(),
            sha256_hash: None,
            torrent_infohash: Some("8a9b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b".into()),
            description: "textura".into(),
        }];
        let deps = vec![LinkedRepository {
            name: "crypto-utils".into(),
            target_address_or_alias: "crypto-lib.open.p2pgit".into(),
            pinned_commit_hash: "a".repeat(64),
            mount_path: "deps/crypto".into(),
        }];

        let a = Commit::create_signed(
            &id,
            None,
            "m".into(),
            base_files(),
            binaries.clone(),
            deps.clone(),
            false,
        )
        .unwrap();
        let b = Commit::create_signed(&id, None, "m".into(), base_files(), binaries, deps, false)
            .unwrap();
        assert_eq!(a.compute_hash(), b.compute_hash());

        // O hash deve cobrir o metadata dos binários e deps.
        let mut c = a.clone();
        c.external_binaries[0].torrent_infohash = Some("bbbb".repeat(10));
        assert_ne!(a.compute_hash(), c.compute_hash());

        let mut d = a.clone();
        d.linked_repos[0].mount_path = "deps/other".into();
        assert_ne!(a.compute_hash(), d.compute_hash());
    }

    #[test]
    fn pr_signature_roundtrip_and_forgery() {
        let fork = RepoIdentity::generate(None);
        let commit = Commit::create_signed(
            &fork,
            None,
            "patch".into(),
            base_files(),
            vec![],
            vec![],
            false,
        )
        .unwrap();
        let head = commit.compute_hash();

        let pr = PullRequest::create(
            &fork,
            "g7x9k2m.p2pgit".into(),
            commit.clone(),
            head.clone(),
            None,
        )
        .unwrap();
        assert!(pr.is_valid());

        // Assinatura forjada.
        let mut bad = pr.clone();
        bad.signature = "deadbeef".into();
        assert!(!bad.is_valid());

        // A base do fork entra no payload assinado: alterá-la invalida o PR.
        let mut tampered_base = pr.clone();
        tampered_base.base_commit_hash = Some("aa".repeat(32));
        assert!(!tampered_base.is_valid());

        // PR que apresenta commit de um TERCEIRO como se fosse do fork.
        let third = RepoIdentity::generate(None);
        let foreign = Commit::create_signed(
            &third,
            None,
            "malicioso".into(),
            base_files(),
            vec![],
            vec![],
            false,
        )
        .unwrap();
        let smuggle = PullRequest {
            fork_head_hash: head,
            proposed_commit: foreign,
            ..pr.clone()
        };
        assert!(!smuggle.is_valid());
    }

    #[test]
    fn collect_files_walks_recursively_and_respects_ignores() {
        let base = std::env::temp_dir().join(format!("p2pgit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("src/nested")).unwrap();
        std::fs::create_dir_all(base.join("target")).unwrap();
        std::fs::create_dir_all(base.join("build")).unwrap();
        std::fs::create_dir_all(base.join(".p2pgit")).unwrap();
        std::fs::write(base.join("src/main.rs"), "fn main() {}").unwrap();
        std::fs::write(base.join("src/nested/util.rs"), "pub fn u() {}").unwrap();
        std::fs::write(base.join("target/junk.rs"), "fn j() {}").unwrap();
        std::fs::write(base.join(".p2pgit/identity.json"), "{}").unwrap();
        std::fs::write(base.join("secret.txt"), "hush").unwrap();
        std::fs::write(
            base.join(".p2pgitignore"),
            "# comentário\nsecret.txt\nbuild/\n",
        )
        .unwrap();
        std::fs::write(base.join("build/out.rs"), "x").unwrap();

        let files = collect_files(&base).unwrap();
        assert!(files.contains_key("src/main.rs"));
        assert!(files.contains_key("src/nested/util.rs"));
        assert!(files.contains_key(".p2pgitignore"));
        assert!(!files.contains_key("target/junk.rs"));
        assert!(!files.contains_key(".p2pgit/identity.json"));
        assert!(!files.contains_key("secret.txt"));
        assert!(!files.contains_key("build/out.rs"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn collect_files_skips_binary_manifest_entries() {
        let base = std::env::temp_dir().join(format!("p2pgit-test-bin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("assets")).unwrap();
        std::fs::write(base.join("main.rs"), "fn main() {}").unwrap();
        // Binário já registrado no '.binary' (ex.: textura PNG).
        std::fs::write(base.join("assets/textura.png"), [0x89, b'P', b'N', b'G']).unwrap();
        std::fs::write(
            base.join(".binary"),
            serde_json::to_string_pretty(&vec![BinaryManifestEntry {
                file_path: "assets/textura.png".into(),
                md5_hash: "d41d8cd98f00b204e9800998ecf8427e".into(),
                sha256_hash: None,
                torrent_infohash: None,
                description: "textura".into(),
            }])
            .unwrap(),
        )
        .unwrap();

        let files = collect_files(&base).unwrap();
        assert!(files.contains_key("main.rs"));
        assert!(!files.contains_key("assets/textura.png"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn binary_entry_serde_tolerates_legacy_json() {
        // JSON legado (sem `sha256_hash`) deve deserializar com default null.
        let legacy: BinaryManifestEntry = serde_json::from_str(
            r#"{
                "file_path": "assets/t.png",
                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                "torrent_infohash": "8a9b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
                "description": "textura"
            }"#,
        )
        .unwrap();
        assert_eq!(legacy.sha256_hash, None);
        assert_eq!(legacy.file_path, "assets/t.png");
        assert_eq!(legacy.md5_hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn magnet_link_is_well_formed() {
        let magnet = magnet_from_infohash(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "assets/textura.png",
        );
        assert!(magnet.starts_with("magnet:?xt=urn:btih:aaaa"));
        assert!(magnet.contains("dn=assets/textura.png"));

        assert_eq!(
            magnet_from_infohash("bbbb", "img.png"),
            "magnet:?xt=urn:btih:bbbb&dn=img.png"
        );
    }

    #[test]
    fn md5_and_sha256_helpers_roundtrip() {
        let content = b"hello p2pgit";
        let md5 = compute_md5_hex(content);
        assert_eq!(md5, "55db65c74c79ab20f1aaf6c6d9d9b8e1");
        assert!(verify_md5(content, &md5).is_ok());
        assert!(verify_md5(content, "00000000000000000000000000000000").is_err());

        let sha = compute_sha256_hex(content);
        assert_eq!(sha.len(), 64);
        assert!(verify_sha256(content, &sha).is_ok());
        assert!(verify_sha256(content, "00".repeat(32).as_str()).is_err());
    }
}
