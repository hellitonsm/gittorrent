use crate::identity::RepoIdentity;
use crate::repo::Commit;
use crate::sanitizer::{inspect_file_content, ContentStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Namespace padrão do cliente para aliases soltos ("meu-projeto" -> "meu-projeto.open.p2pgit").
pub const DEFAULT_NAMESPACE: &str = "open.p2pgit";

// ============ Chaves de registro na DHT ============
// (usadas pelo transporte `network`; sem a feature elas ficam ociosas)

/// Chave Kademlia de um commit:
/// - HEAD do repositório: `<endereço>`
/// - commit do histórico: `<endereço>#<hash>`
#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub fn commit_record_key(address: &str, hash: Option<&str>) -> String {
    match hash {
        Some(h) => format!("{}#{}", address, h),
        None => address.to_string(),
    }
}

/// Chave do registro mutável de um alias: `alias:<namespace>:<alias>`.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub fn alias_record_key(namespace: &str, alias: &str) -> String {
    format!("alias:{}:{}", namespace, alias)
}

/// Como o cliente reage a conteúdo suspeito ao baixar um commit.
///
/// - `Interactive`      — alerta e pergunta (padrão em TTY).
/// - `DenyAll`          — rejeita qualquer suspeito (não-TTY ou `--strict`).
/// - `AllowAllAfterWarning` — alerta e prossegue (`--yes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardPolicy {
    Interactive,
    DenyAll,
    AllowAllAfterWarning,
}

/// Registro de Alias publicado na DHT e assinado pelo dono da chave.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AliasRecord {
    pub alias: String,          // ex: "meu-projeto"
    pub namespace: String,      // ex: "default.p2pgit" (padrão do cliente)
    pub target_address: String, // ex: "g7x9k2m...v4q.p2pgit"
    pub pubkey_hex: String,
    pub signature: String,
}

impl AliasRecord {
    pub fn new(
        identity: &RepoIdentity,
        alias: &str,
        client_default_domain: &str,
    ) -> anyhow::Result<Self> {
        let payload = format!(
            "{}:{}:{}",
            alias, client_default_domain, identity.onion_like_address
        );
        let signature = identity.sign_data(payload.as_bytes())?;

        Ok(Self {
            alias: alias.to_string(),
            namespace: client_default_domain.to_string(),
            target_address: identity.onion_like_address.clone(),
            pubkey_hex: identity.public_key_hex.clone(),
            signature,
        })
    }

    pub fn is_valid(&self) -> bool {
        let payload = format!("{}:{}:{}", self.alias, self.namespace, self.target_address);
        RepoIdentity::verify_signature(&self.pubkey_hex, payload.as_bytes(), &self.signature)
    }

    /// Alias totalmente qualificado, ex: "meu-projeto.open.p2pgit".
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.alias, self.namespace)
    }
}

/// Registro local de aliases (substitui a DHT no MVP local; em produção cada
/// registro é um `kad.put_record` assinado, BEP-44 style).
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AliasRegistry {
    pub records: BTreeMap<String, AliasRecord>,
}

impl AliasRegistry {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn insert(&mut self, record: AliasRecord) -> anyhow::Result<()> {
        if !record.is_valid() {
            anyhow::bail!("Assinatura do registro de alias inválida");
        }
        // Garante que o endereço não foi trocado por outro pubkey.
        let derived = RepoIdentity::verify_address(&record.target_address)?;
        if hex::encode(derived.to_bytes()) != record.pubkey_hex {
            anyhow::bail!("O endereço não corresponde à chave pública do registro");
        }
        self.records.insert(record.qualified(), record);
        Ok(())
    }

    pub fn resolve(&self, query: &str, default_namespace: &str) -> Option<&AliasRecord> {
        let key = if query.contains('.') {
            query.to_string()
        } else {
            format!("{}.{}", query, default_namespace)
        };
        self.records.get(&key)
    }
}

/// Validação de segurança executada pelo cliente ao baixar/clonar um commit da rede torrent.
///
/// Binários listados no `.binary` são procurados em `<base>/binaries/<file_path>`
/// (`base` = diretório raiz do repositório; `.` no repo corrente).
pub fn client_download_guard(commit: &Commit, policy: GuardPolicy) -> anyhow::Result<()> {
    client_download_guard_at(commit, policy, Path::new("."))
}

/// Como [`client_download_guard`], mas com base explícita para localizar
/// `binaries/` — usado no clone, onde a saída é `--out <dir>`.
pub fn client_download_guard_at(
    commit: &Commit,
    policy: GuardPolicy,
    base: &Path,
) -> anyhow::Result<()> {
    // 1. Verifica assinatura criptográfica do commit.
    if !commit.is_signature_valid() {
        anyhow::bail!(
            "ERRO CRÍTICO: Assinatura do commit inválida! Possível adulteração na rede P2P."
        );
    }

    // 2. Verifica tamanho máximo de 512 KB.
    let total_size: usize = commit.files.values().map(|v| v.len()).sum();
    if total_size > crate::repo::MAX_COMMIT_SIZE_BYTES {
        anyhow::bail!("BLOQUEADO PELO CLIENTE: Commit remoto excede 512 KB.");
    }

    // 3. Inspeciona cada arquivo baixado contra binários ocultos ou Base64.
    for (path, content) in &commit.files {
        match inspect_file_content(Path::new(path), content.as_bytes()) {
            ContentStatus::CleanText => continue,
            ContentStatus::BinaryDetected(msg) | ContentStatus::Base64PayloadDetected(msg) => {
                println!("\n==================== ALERTA DE SEGURANÇA ====================");
                println!("O repositório remoto tentou enviar conteúdo suspeito/binário!");
                println!("Detalhe: {}", msg);
                println!("RISCOS: Execução de código malicioso oculto, payloads ofuscados");
                println!("        ou abuso da rede de código puro.");
                println!("=============================================================");

                let proceed = match policy {
                    GuardPolicy::DenyAll => false,
                    GuardPolicy::AllowAllAfterWarning => true,
                    GuardPolicy::Interactive => {
                        print!("Deseja realmente baixar e salvar este arquivo? [s/N]: ");
                        io::stdout().flush()?;
                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        input.trim().to_lowercase() == "s"
                    }
                };
                if !proceed {
                    anyhow::bail!(
                        "Download abortado por motivo de segurança ({:?}). Use --yes para aceitar os avisos ou --strict para negar tudo automaticamente.",
                        policy
                    );
                }
            }
        }
    }

    // 4. Binários externos: verificados quando presentes; ausentes → aviso
    //    com instrução para rodar `p2pgit fetch-binaries`.
    for bin in &commit.external_binaries {
        let bin_path = base.join("binaries").join(&bin.file_path);
        if !bin_path.exists() {
            println!(
                "\n[AVISO] Binário '{}' ainda não baixado (esperado MD5 {}).",
                bin.file_path, bin.md5_hash
            );
            println!(
                "        Rode 'p2pgit fetch-binaries' para obtê-lo da rede BitTorrent e depois 'p2pgit check-binary <arquivo> {}'.",
                bin.md5_hash
            );
            continue;
        }
        let content = fs::read(&bin_path)?;
        crate::repo::verify_md5(&content, &bin.md5_hash)?;
        if let Some(sha) = &bin.sha256_hash {
            crate::repo::verify_sha256(&content, sha)?;
        }
    }

    // 5. Informa sobre repositórios essenciais vinculados.
    if !commit.linked_repos.is_empty() {
        println!("\n[INFO] Repositórios essenciais vinculados:");
        for dep in &commit.linked_repos {
            let short: String = dep.pinned_commit_hash.chars().take(8).collect();
            println!(
                "  - {} -> {} @ {}",
                dep.name, dep.target_address_or_alias, short
            );
        }
    }

    Ok(())
}

// ============ Registro mutável de alias (BEP-44 style) ============

/// Envelope para DHT: alias já assinado + número de sequência monotônico,
/// assinado pela chave do dono. Peers rejeitam `seq` menor que o conhecido.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AliasEnvelope {
    pub record: AliasRecord,
    pub seq: u64,
    pub signature: String,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
impl AliasEnvelope {
    fn payload(&self) -> String {
        format!(
            "seq={}|alias={}|namespace={}|target={}|pub={}",
            self.seq,
            self.record.alias,
            self.record.namespace,
            self.record.target_address,
            self.record.pubkey_hex
        )
    }

    pub fn create(
        id: &RepoIdentity,
        seq: u64,
        alias: &str,
        namespace: &str,
    ) -> anyhow::Result<Self> {
        let record = AliasRecord::new(id, alias, namespace)?;
        let mut envelope = Self {
            record,
            seq,
            signature: String::new(),
        };
        envelope.signature = id.sign_data(envelope.payload().as_bytes())?;
        Ok(envelope)
    }

    pub fn is_valid(&self) -> bool {
        self.seq > 0
            && self.record.is_valid()
            && RepoIdentity::verify_signature(
                &self.record.pubkey_hex,
                self.payload().as_bytes(),
                &self.signature,
            )
    }
}

// ============ Anúncio de novo HEAD (gossipsub) ============

#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub const ANNOUNCE_MAX_AGE_SECS: u64 = 24 * 3600;

/// Mensagem do tópico `p2pgit/announce/v1`: "meu HEAD agora é X".
#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeadAnnouncement {
    pub address: String,
    pub head_hash: String,
    pub pubkey_hex: String,
    pub timestamp: u64,
    pub signature: String,
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
impl HeadAnnouncement {
    fn payload(&self) -> String {
        format!(
            "announce|{}|{}|{}",
            self.address, self.head_hash, self.timestamp
        )
    }

    pub fn new(id: &RepoIdentity, head_hash: &str) -> anyhow::Result<Self> {
        let mut ann = Self {
            address: id.onion_like_address.clone(),
            head_hash: head_hash.to_string(),
            pubkey_hex: id.public_key_hex.clone(),
            timestamp: now_secs(),
            signature: String::new(),
        };
        ann.signature = id.sign_data(ann.payload().as_bytes())?;
        Ok(ann)
    }

    pub fn is_valid(&self) -> bool {
        // Frescor (anti-replay) + endereço deriva da pubkey + assinatura.
        if self.timestamp.abs_diff(now_secs()) > ANNOUNCE_MAX_AGE_SECS {
            return false;
        }
        match RepoIdentity::verify_address(&self.address) {
            Ok(key) => {
                hex::encode(key.to_bytes()) == self.pubkey_hex
                    && RepoIdentity::verify_signature(
                        &self.pubkey_hex,
                        self.payload().as_bytes(),
                        &self.signature,
                    )
            }
            Err(_) => false,
        }
    }
}

#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============ Validação de registros na borda da rede ============

/// Único caminho de entrada de registros Kademlia no cliente.
///
/// Regra da rede: nada entra (nem sai) sem passar por aqui — valida
/// chave ↔ commit ↔ assinatura ↔ sanitização ↔ limite de tamanho.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub fn validate_commit_record(
    key: &str,
    value: &[u8],
    policy: GuardPolicy,
) -> anyhow::Result<Commit> {
    let (address, expected_hash) = match key.split_once('#') {
        Some((a, h)) => (a, Some(h)),
        None => (key, None),
    };
    anyhow::ensure!(
        address.ends_with(".p2pgit"),
        "Chave de registro inválida: '{}'",
        key
    );

    let key_owner = RepoIdentity::verify_address(address)?;
    let commit: Commit = serde_json::from_slice(value).map_err(|e| {
        anyhow::anyhow!("Registro na chave '{}' não é um commit válido: {}", key, e)
    })?;

    // O autor do commit deve ser o dono do endereço da chave (anti-spoofing).
    let owner_hex = hex::encode(key_owner.to_bytes());
    if !commit.author_pubkey.eq_ignore_ascii_case(&owner_hex) {
        anyhow::bail!(
            "Commit na chave '{}' foi publicado por outra chave que não o dono do endereço.",
            key
        );
    }

    // Chave com hash fixado: o commit deve corresponder exatamente.
    if let Some(h) = expected_hash {
        if commit.compute_hash() != h {
            anyhow::bail!(
                "Commit na chave '{}' não corresponde ao hash fixado na chave.",
                key
            );
        }
    }

    client_download_guard(&commit, policy)?;
    Ok(commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Commit;

    fn sample_commit() -> Commit {
        let id = RepoIdentity::generate(None);
        let mut files = BTreeMap::new();
        files.insert("a.rs".into(), "fn a() {}".into());
        Commit::create_signed(&id, None, "m".into(), files, vec![], vec![], false).unwrap()
    }

    fn suspicious_commit() -> Commit {
        let id = RepoIdentity::generate(None);
        let mut files = BTreeMap::new();
        files.insert(
            "x.js".into(),
            format!("const img = \"{}\";", "Ab3".repeat(70)),
        );
        Commit::create_signed(&id, None, "m".into(), files, vec![], vec![], true).unwrap()
    }

    #[test]
    fn alias_record_signature_roundtrip() {
        let id = RepoIdentity::generate(None);
        let rec = AliasRecord::new(&id, "meu-projeto", "open.p2pgit").unwrap();
        assert!(rec.is_valid());
        assert_eq!(rec.qualified(), "meu-projeto.open.p2pgit");
    }

    #[test]
    fn registry_rejects_forged_alias() {
        let id = RepoIdentity::generate(None);
        let mut rec = AliasRecord::new(&id, "proj", "open.p2pgit").unwrap();
        rec.signature = "deadbeef".into();
        let mut reg = AliasRegistry::default();
        assert!(reg.insert(rec).is_err());
    }

    #[test]
    fn guard_rejects_bad_signature() {
        let mut commit = sample_commit();
        commit.signature = "00".into();
        assert!(client_download_guard(&commit, GuardPolicy::DenyAll).is_err());
    }

    #[test]
    fn guard_deny_all_blocks_suspicious_content() {
        assert!(client_download_guard(&suspicious_commit(), GuardPolicy::DenyAll).is_err());
    }

    #[test]
    fn guard_allow_all_accepts_after_warning() {
        assert!(
            client_download_guard(&suspicious_commit(), GuardPolicy::AllowAllAfterWarning).is_ok()
        );
    }

    fn make_commit() -> (RepoIdentity, Commit) {
        let id = RepoIdentity::generate(None);
        let mut files = BTreeMap::new();
        files.insert("a.rs".into(), "fn a() {}".into());
        let commit =
            Commit::create_signed(&id, None, "m".into(), files, vec![], vec![], false).unwrap();
        (id, commit)
    }

    #[test]
    fn alias_envelope_roundtrip_and_forgery() {
        let id = RepoIdentity::generate(None);
        let env = AliasEnvelope::create(&id, 1, "meu-projeto", DEFAULT_NAMESPACE).unwrap();
        assert!(env.is_valid());
        assert_eq!(env.record.qualified(), "meu-projeto.open.p2pgit");

        // seq precisa ser > 0.
        let env0 = AliasEnvelope::create(&id, 0, "x", DEFAULT_NAMESPACE).unwrap();
        assert!(!env0.is_valid());

        // Assinatura do envelope forjada.
        let mut forged = env.clone();
        forged.signature = "deadbeef".into();
        assert!(!forged.is_valid());

        // seq retrocedido não muda a validade da assinatura (o peer compara com o cache).
        let mut rewound = env.clone();
        rewound.seq = 99;
        assert!(!rewound.is_valid());
    }

    #[test]
    fn head_announcement_roundtrip_and_forgery() {
        let id = RepoIdentity::generate(None);
        let ann = HeadAnnouncement::new(&id, "ab".repeat(32).as_str()).unwrap();
        assert!(ann.is_valid());

        let mut forged = ann.clone();
        forged.head_hash = "cd".repeat(32);
        assert!(!forged.is_valid());

        // Endereço incompatível com a pubkey.
        let other = RepoIdentity::generate(None);
        let mut mismatch = ann.clone();
        mismatch.address = other.onion_like_address.clone();
        assert!(!mismatch.is_valid());

        // Anúncio velho (replay) é rejeitado.
        let mut stale = ann;
        stale.timestamp = now_secs().saturating_sub(ANNOUNCE_MAX_AGE_SECS + 60);
        assert!(!stale.is_valid());
    }

    #[test]
    fn validate_commit_record_accepts_valid_and_rejects_spoofing() {
        let (id, commit) = make_commit();
        let value = serde_json::to_vec(&commit).unwrap();

        // HEAD sob o endereço.
        let key = commit_record_key(&id.onion_like_address, None);
        let ok = validate_commit_record(&key, &value, GuardPolicy::DenyAll).unwrap();
        assert_eq!(ok.compute_hash(), commit.compute_hash());

        // Commit histórico fixado na chave.
        let h = commit.compute_hash();
        let key = commit_record_key(&id.onion_like_address, Some(&h));
        assert!(validate_commit_record(&key, &value, GuardPolicy::DenyAll).is_ok());

        // Hash fixado não bate.
        let key = commit_record_key(&id.onion_like_address, Some(&"00".repeat(32)));
        assert!(validate_commit_record(&key, &value, GuardPolicy::DenyAll).is_err());

        // Spoofing: commit de um autor sob o endereço de outro.
        let (other, _) = make_commit();
        let key = commit_record_key(&other.onion_like_address, None);
        assert!(validate_commit_record(&key, &value, GuardPolicy::DenyAll).is_err());

        // Chave fora do formato do sistema.
        assert!(validate_commit_record("chave-aleatoria", &value, GuardPolicy::DenyAll).is_err());
    }
}
