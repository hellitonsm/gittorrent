mod identity;
mod network;
#[cfg(feature = "network")]
mod p2p;
mod repo;
mod sanitizer;

use clap::{Parser, Subcommand};
use identity::RepoIdentity;
use network::{
    client_download_guard, client_download_guard_at, AliasRecord, AliasRegistry, GuardPolicy,
    DEFAULT_NAMESPACE,
};
use repo::{BinaryManifestEntry, Commit, LinkedRepository, PullRequest};
use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
// `warn` só é usado nos caminhos com feature 'network'.
#[cfg_attr(not(feature = "network"), allow(unused_imports))]
use tracing::{info, warn, Level};
use tracing_subscriber::EnvFilter;

const DEFAULT_CLIENT_NAMESPACE: &str = DEFAULT_NAMESPACE;

const IDENTITY_FILE: &str = ".p2pgit/identity.json";
const HEAD_FILE: &str = ".p2pgit/HEAD";
const ALIASES_FILE: &str = ".p2pgit/aliases.json";
const BINARIES_FILE: &str = ".binary";
const DEPS_FILE: &str = ".p2pdeps";

/// Inicializa o subscriber de logging com base em P2PGIT_LOG ou padrão.
fn init_tracing() {
    let filter = EnvFilter::from_default_env().add_directive(Level::INFO.into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[derive(Parser)]
#[command(
    name = "p2pgit",
    about = "Git descentralizado sobre Torrent/DHT em Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Aceita automaticamente os avisos de conteúdo suspeito (modo não-interativo)
    #[arg(long, global = true)]
    yes: bool,
    /// Modo estrito: rejeita qualquer conteúdo suspeito, sem perguntar
    #[arg(long, global = true)]
    strict: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Cria um novo repositório, gera chaves (pública/privada) e endereço estilo Tor
    Init {
        #[arg(short, long)]
        alias: Option<String>,
    },
    /// Registra um alias amigável para o endereço do repositório
    RegisterAlias {
        alias: String,
        #[arg(long, default_value = DEFAULT_CLIENT_NAMESPACE)]
        namespace: String,
        /// Nodes bootstrap da DHT (feature 'network'); padrão: ~/.p2pgit/bootstrap.txt
        #[arg(long)]
        bootstrap: Vec<String>,
    },
    /// Cria um commit de código puro (máx 512 KB) assinado com a chave privada
    Commit {
        #[arg(short, long)]
        message: String,
        #[arg(long, default_value_t = false)]
        force_text: bool,
    },
    /// Lista o histórico (HEAD -> raiz) seguindo parent_hash
    Log,
    /// Mostra os detalhes de um commit (padrão: HEAD)
    Show {
        /// Prefixo do hash (mínimo 4 caracteres)
        hash: Option<String>,
    },
    /// Restaura o diretório de trabalho em um commit antigo (HEAD detached)
    Checkout {
        /// Prefixo do hash (mínimo 4 caracteres)
        hash: String,
    },
    /// Clona um repositório via endereço Tor, Alias ou arquivo de commit local
    Clone {
        target: String,
        #[arg(short, long, default_value = "clone")]
        out: String,
        /// Nodes bootstrap da DHT (feature 'network'); padrão: ~/.p2pgit/bootstrap.txt
        #[arg(long)]
        bootstrap: Vec<String>,
        /// Profundidade de dependências `.p2pdeps` a montar (padrão: 1)
        #[arg(long, default_value_t = 1)]
        depth: u32,
    },
    /// Cria um Pull Request assinado para o repositório original (se recusado, vira Fork)
    CreatePr {
        target_address: String,
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Verifica a assinatura de um PR e re-assina o merge com a chave original
    ApprovePr { pr_file: String },
    /// Mostra o endereço, a chave pública e o estado atual do repositório
    Status,
    /// Valida um endereço .p2pgit ou um arquivo de commit
    Verify { target: String },
    /// Valida o MD5 de um arquivo baixado do manifesto '.binary'
    CheckBinary { file: String, expected_md5: String },
    /// Adiciona um arquivo binário ao manifesto '.binary' (MD5/SHA-256 + infohash opcional)
    AddBinary {
        file: String,
        #[arg(long)]
        description: Option<String>,
        /// BitTorrent infohash (40 hex) para busca/download via rede
        #[arg(long)]
        torrent_infohash: Option<String>,
    },
    /// Busca na rede BitTorrent os binários referenciados no `.binary` (via magnet) e valida
    FetchBinaries {
        /// Diretório de destino dos downloads (padrão: `binaries`)
        #[arg(long, default_value = "binaries")]
        out_dir: String,
    },
    /// Adiciona uma dependência `.p2pdeps` (repositório linkado fixado por hash)
    AddDep {
        /// Endereço `.p2pgit` ou alias do repositório dependente
        target: String,
        /// Hash completo (64 hex) do commit fixado; default: HEAD atual do alvo na DHT
        #[arg(long)]
        pin: Option<String>,
        /// Caminho de montagem relativo (ex: deps/crypto)
        #[arg(long)]
        mount: String,
        /// Nome da dependência (default: último segmento do mount)
        #[arg(long)]
        name: Option<String>,
        /// Nodes bootstrap da DHT (feature 'network'); padrão: ~/.p2pgit/bootstrap.txt
        #[arg(long)]
        bootstrap: Vec<String>,
    },
    /// Inicia um nó DHT Kademlia (requer a feature 'network')
    #[cfg(feature = "network")]
    Daemon {
        #[arg(long)]
        bootstrap: Vec<String>,
    },
}

/// Resolve a política do guard: --strict vence, depois --yes, e em TTY
/// não-interativo o padrão é negar tudo (segurança em scripts/daemon).
fn resolve_policy(strict: bool, yes: bool) -> GuardPolicy {
    if strict {
        GuardPolicy::DenyAll
    } else if yes {
        GuardPolicy::AllowAllAfterWarning
    } else if std::io::stdin().is_terminal() {
        GuardPolicy::Interactive
    } else {
        GuardPolicy::DenyAll
    }
}

fn read_identity() -> anyhow::Result<RepoIdentity> {
    if !Path::new(IDENTITY_FILE).exists() {
        anyhow::bail!("Repositório não inicializado. Execute 'p2pgit init' primeiro.");
    }
    Ok(serde_json::from_str(&fs::read_to_string(IDENTITY_FILE)?)?)
}

fn read_head() -> Option<String> {
    fs::read_to_string(HEAD_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn require_head() -> anyhow::Result<String> {
    read_head()
        .ok_or_else(|| anyhow::anyhow!("Nenhum commit local. Execute 'p2pgit commit' primeiro."))
}

fn write_head(hash: &str) -> anyhow::Result<()> {
    fs::write(HEAD_FILE, hash)?;
    Ok(())
}

/// Salva o commit indexado pelo hash COMPLETO e atualiza o HEAD.
/// Escrita atômica: salva em .tmp, renomeia, depois atualiza o HEAD.
fn save_commit(commit: &Commit) -> anyhow::Result<String> {
    let hash = commit.compute_hash();
    let tmp = format!(".p2pgit/.tmp_commit_{}.json", &hash[..8]);
    let final_path = format!(".p2pgit/commit_{}.json", hash);

    // Garante que o diretório .p2pgit existe.
    fs::create_dir_all(".p2pgit")?;

    // Escreve no arquivo temporário.
    fs::write(&tmp, serde_json::to_string_pretty(commit)?)?;

    // Rename atômico para o destino final.
    fs::rename(&tmp, &final_path)?;

    // Atualiza o HEAD por último — se falhar, o commit já está salvo.
    write_head(&hash)?;

    Ok(hash)
}

/// Localiza um commit pelo prefixo do hash (mínimo 4 caracteres).
fn find_commit_file(prefix: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        prefix.len() >= 4,
        "Prefixo de hash muito curto (mínimo 4 caracteres)."
    );
    if let Ok(entries) = fs::read_dir(".p2pgit") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(mid) = name
                .strip_prefix("commit_")
                .and_then(|s| s.strip_suffix(".json"))
            {
                if mid.starts_with(prefix) {
                    return Ok(entry.path());
                }
            }
        }
    }
    anyhow::bail!("Nenhum commit encontrado com o prefixo '{}'.", prefix)
}

fn load_commit(prefix: &str) -> anyhow::Result<Commit> {
    let path = find_commit_file(prefix)?;
    serde_json::from_str(&fs::read_to_string(&path)?)
        .map_err(|e| anyhow::anyhow!("Commit inválido em {}: {}", path.display(), e))
}

/// Escreve os arquivos do commit no diretório de saída do clone.
fn write_clone(out_path: &Path, commit: &Commit) -> anyhow::Result<()> {
    write_commit_files(out_path, commit)?;
    info!(
        "Código verificado e clonado em '{}' ({} arquivo(s)).",
        out_path.display(),
        commit.files.len()
    );
    info!("Commit clonado: {}", commit.compute_hash());
    Ok(())
}

/// Escreve apenas os arquivos do commit (sem log) — usado no `mount_path`
/// das dependências `.p2pdeps`.
fn write_commit_files(out_path: &Path, commit: &Commit) -> anyhow::Result<()> {
    fs::create_dir_all(out_path)?;
    for (path, content) in &commit.files {
        let dest = out_path.join(path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(dest, content)?;
    }
    Ok(())
}

/// Monta as dependências `.p2pdeps` do commit em `<base>/<mount_path>`.
///
/// Cada dependência é resolvida na DHT (`fetch_pinned_commit`, que valida
/// assinatura, autor e o **hash fixado**) e gravada no `mount_path`.
/// A recursão respeita `depth` e detecta ciclos pela dupla
/// (alvo, hash fixado) já visitada — um ciclo é ignorado, não trava.
/// Falhas individuais são registradas em `resolved` sem abortar o clone.
#[cfg(feature = "network")]
#[allow(clippy::too_many_arguments)]
async fn mount_dependencies(
    head: &Commit,
    base: &Path,
    boot: &[String],
    policy: GuardPolicy,
    depth: u32,
    visited: &mut HashSet<String>,
    resolved: &mut Vec<serde_json::Value>,
) -> anyhow::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    for dep in &head.linked_repos {
        let id = network::dep_identity_key(&dep.target_address_or_alias, &dep.pinned_commit_hash);
        if !visited.insert(id) {
            warn!(
                "[deps] ciclo detectado em '{}' — dependência ignorada",
                dep.target_address_or_alias
            );
            continue;
        }

        match p2p::fetch_pinned_commit(
            &dep.target_address_or_alias,
            &dep.pinned_commit_hash,
            boot,
            policy,
        )
        .await
        {
            Ok((address, commit)) => {
                let mount = base.join(&dep.mount_path);
                write_commit_files(&mount, &commit)?;
                // Metadados da dep no mount point (permite `log` local ali).
                let meta = mount.join(".p2pgit");
                fs::create_dir_all(&meta)?;
                fs::write(
                    meta.join(format!("commit_{}.json", commit.compute_hash())),
                    serde_json::to_string_pretty(&commit)?,
                )?;
                fs::write(meta.join("HEAD"), commit.compute_hash())?;
                resolved.push(serde_json::json!({
                    "name": dep.name,
                    "target": dep.target_address_or_alias,
                    "address": address,
                    "pinned_commit_hash": dep.pinned_commit_hash,
                    "mount_path": dep.mount_path,
                    "status": "ok",
                }));
                info!(
                    "Dependência '{}' montada em '{}' ({} arquivo(s)).",
                    dep.name,
                    mount.display(),
                    commit.files.len()
                );
                // Recursão: deps da dep (um nível menos).
                if depth > 1 {
                    Box::pin(mount_dependencies(
                        &commit,
                        &mount,
                        boot,
                        policy,
                        depth - 1,
                        visited,
                        resolved,
                    ))
                    .await?;
                }
            }
            Err(e) => {
                resolved.push(serde_json::json!({
                    "name": dep.name,
                    "target": dep.target_address_or_alias,
                    "pinned_commit_hash": dep.pinned_commit_hash,
                    "mount_path": dep.mount_path,
                    "status": "failed",
                    "reason": e.to_string(),
                }));
                warn!("[deps] falha ao resolver '{}': {}", dep.name, e);
            }
        }
    }
    Ok(())
}

/// Baixa um magnet BitTorrent via cliente externo (`aria2c`).
/// Requer `aria2c` instalado no sistema (ou outro cliente compatível).
/// Faz download para um .tmp e só move para o destino após validação.
async fn download_via_magnet(magnet: &str, out_path: &Path) -> anyhow::Result<()> {
    let tmp_path = out_path.with_extension("tmp");

    // Garante que o diretório de destino existe.
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut cmd = tokio::process::Command::new("aria2c");
    cmd.arg(magnet).arg("-o").arg(&tmp_path);
    let status = match cmd.status().await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "cliente de torrent 'aria2c' não encontrado. Instale (ex.: 'sudo apt install aria2') \
                 ou use outro cliente compatível com magnet links."
            );
        }
        Err(e) => return Err(e.into()),
    };
    if !status.success() {
        // Limpa o tmp em caso de falha.
        let _ = fs::remove_file(&tmp_path);
        anyhow::bail!("aria2c falhou com exit code {:?}", status.code());
    }
    if !tmp_path.exists() {
        anyhow::bail!("aria2c não produziu o arquivo em {}", tmp_path.display());
    }

    // Move para o destino final.
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

/// Resolve `bootstrap` (padrão `~/.p2pgit/bootstrap.txt`), monta as
/// dependências `.p2pdeps` do clone e grava `.p2pgit/deps.lock`.
#[cfg(feature = "network")]
async fn mount_cloned_dependencies(
    head: &Commit,
    out_path: &Path,
    bootstrap: &[String],
    policy: GuardPolicy,
    depth: u32,
) -> anyhow::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    let boot = if bootstrap.is_empty() {
        p2p::default_bootstrap()
    } else {
        bootstrap.to_vec()
    };
    let mut visited = HashSet::new();
    let mut resolved: Vec<serde_json::Value> = Vec::new();
    mount_dependencies(
        head,
        out_path,
        &boot,
        policy,
        depth,
        &mut visited,
        &mut resolved,
    )
    .await?;

    let meta = out_path.join(".p2pgit");
    fs::create_dir_all(&meta)?;
    fs::write(
        meta.join("deps.lock"),
        serde_json::to_string_pretty(&resolved)?,
    )?;
    Ok(())
}

fn resolve_target(target: &str) -> anyhow::Result<PathBuf> {
    // 1. É um caminho de arquivo existente?
    let path = PathBuf::from(target);
    if path.exists() {
        return Ok(path);
    }

    // 2. Tenta resolver como alias no registro local.
    let registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
    if let Some(record) = registry.resolve(target, DEFAULT_CLIENT_NAMESPACE) {
        // No MVP local, procura qualquer commit cujo autor corresponda ao alias.
        let expected_pub = &record.pubkey_hex;
        if let Ok(entries) = fs::read_dir(".p2pgit") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with("commit_") {
                    continue;
                }
                if let Ok(c) = serde_json::from_str::<Commit>(&fs::read_to_string(entry.path())?) {
                    if &c.author_pubkey == expected_pub {
                        return Ok(entry.path());
                    }
                }
            }
        }
        anyhow::bail!(
            "Alias '{}' -> {} resolvido, mas nenhum commit local desse autor foi encontrado (a DHT ainda não está conectada).",
            target, record.target_address
        );
    }

    // 3. Parece um endereço .p2pgit mas não há upload local.
    if target.ends_with(".p2pgit") {
        let key = RepoIdentity::verify_address(target)?;
        anyhow::bail!(
            "Endereço {} válido (pubkey {}). Aguardando peers na DHT — forneça um arquivo de commit para o MVP local.",
            target,
            hex::encode(key.to_bytes())
        );
    }

    anyhow::bail!("Não foi possível resolver '{}'. Forneça um arquivo .json de commit ou um alias registrado.", target)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { alias } => {
            if Path::new(IDENTITY_FILE).exists() {
                anyhow::bail!("Já existe um repositório deste diretório.");
            }

            let id = RepoIdentity::generate(alias.clone());
            fs::create_dir_all(".p2pgit")?;
            fs::write(IDENTITY_FILE, serde_json::to_string_pretty(&id)?)?;

            // Protege a identidade com permissões 600 (somente dono).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(IDENTITY_FILE) {
                    let mut perm = meta.permissions();
                    perm.set_mode(0o600);
                    let _ = fs::set_permissions(IDENTITY_FILE, perm);
                }
            }

            // Arquivos padrão `.binary` e `.p2pdeps`.
            let default_binaries: Vec<BinaryManifestEntry> = vec![];
            let default_deps: Vec<LinkedRepository> = vec![];
            fs::write(
                BINARIES_FILE,
                serde_json::to_string_pretty(&default_binaries)?,
            )?;
            fs::write(DEPS_FILE, serde_json::to_string_pretty(&default_deps)?)?;

            info!("Repositório inicializado com sucesso!");
            info!("Endereço Tor-style : {}", id.onion_like_address);
            info!("Chave Pública      : {}", id.public_key_hex);
            info!(
                "Chave Privada      : [SALVA EM {} - NÃO COMPARTILHE]",
                IDENTITY_FILE
            );

            if let Some(a) = alias {
                let record = AliasRecord::new(&id, &a, DEFAULT_CLIENT_NAMESPACE)?;
                let mut registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
                registry.insert(record.clone())?;
                registry.save(Path::new(ALIASES_FILE))?;
                info!(
                    "Alias registrado   : {} -> {}",
                    record.qualified(),
                    record.target_address
                );
            }
        }

        Commands::RegisterAlias {
            alias,
            namespace,
            bootstrap,
        } => {
            let id = read_identity()?;
            let record = AliasRecord::new(&id, &alias, &namespace)?;
            let mut registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
            registry.insert(record.clone())?;
            registry.save(Path::new(ALIASES_FILE))?;

            info!("Registro assinado pronto para propagação na DHT (BEP-44):");
            info!("{}", serde_json::to_string_pretty(&record)?);
            info!("\nSalvo localmente em {}", ALIASES_FILE);

            // Publica o registro mutável assinado na DHT (feature network).
            #[cfg(feature = "network")]
            {
                let boot = if bootstrap.is_empty() {
                    p2p::default_bootstrap()
                } else {
                    bootstrap
                };
                match p2p::publish_alias(&id, &alias, &namespace, &boot).await {
                    Ok(()) => {}
                    Err(e) => warn!("[DHT] alias não publicado agora: {}", e),
                }
            }
            #[cfg(not(feature = "network"))]
            let _ = bootstrap;
        }

        Commands::Commit {
            message,
            force_text,
        } => {
            let id = read_identity()?;

            // Varredura recursiva do diretório (respeita .p2pgitignore).
            let files =
                tokio::task::spawn_blocking(|| repo::collect_files(Path::new("."))).await??;

            let binaries: Vec<BinaryManifestEntry> =
                serde_json::from_str(&fs::read_to_string(BINARIES_FILE)?)?;
            let linked_repos: Vec<LinkedRepository> =
                serde_json::from_str(&fs::read_to_string(DEPS_FILE)?)?;

            let commit = Commit::create_signed(
                &id,
                read_head(),
                message,
                files,
                binaries,
                linked_repos,
                force_text,
            )?;

            let hash = save_commit(&commit)?;
            info!("Commit criado e assinado! Hash: {}", hash);
            info!(
                "Pronto para semear (seed) via DHT/Torrent: .p2pgit/commit_{}.json",
                &hash[..12]
            );
        }

        Commands::Log => {
            let mut current = require_head()?;
            let mut visited = HashSet::new();
            let mut index = 0u64;

            while !visited.contains(&current) {
                visited.insert(current.clone());
                let commit = match load_commit(&current) {
                    Ok(c) => c,
                    Err(_) => {
                        // Commits vindos de forks podem não existir localmente.
                        info!(
                            "{}  (commit ausente localmente — histórico incompleto)",
                            &current[..12.min(current.len())]
                        );
                        break;
                    }
                };
                info!(
                    "{}  {}  {}",
                    &current[..12.min(current.len())],
                    commit.timestamp,
                    commit.message
                );
                index += 1;
                match commit.parent_hash {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
            info!("({} commit(s) no histórico)", index);
        }

        Commands::Show { hash } => {
            let prefix = match hash {
                Some(h) => h,
                None => require_head()?,
            };
            let commit = load_commit(&prefix)?;
            info!("Hash     : {}", commit.compute_hash());
            info!("Autor    : {}", commit.author_pubkey);
            info!("Timestamp: {}", commit.timestamp);
            info!("Mensagem : {}", commit.message);
            info!(
                "Parent   : {}",
                commit.parent_hash.as_deref().unwrap_or("(raiz)")
            );
            info!("Arquivos ({}):", commit.files.len());
            for (path, content) in &commit.files {
                info!("  - {} ({} bytes)", path, content.len());
            }
        }

        Commands::Checkout { hash } => {
            let policy = resolve_policy(cli.strict, cli.yes);
            let commit = load_commit(&hash)?;

            // Restaura apenas código assinado e inspecionado.
            client_download_guard(&commit, policy)?;

            let files: Vec<(String, String)> = commit.files.clone().into_iter().collect();
            let write_result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                for (path, content) in &files {
                    let dest = Path::new(path);
                    if let Some(parent) = dest.parent() {
                        if !parent.as_os_str().is_empty() {
                            fs::create_dir_all(parent)?;
                        }
                    }
                    fs::write(dest, content)?;
                }
                Ok(())
            })
            .await?;
            write_result?;

            let full = commit.compute_hash();
            write_head(&full)?;
            info!(
                "Checkout do commit {} concluído (HEAD detached). Arquivos não commitados podem ter sido sobrescritos.",
                &full[..12]
            );
        }

        Commands::Clone {
            target,
            out,
            bootstrap,
            depth,
        } => {
            let policy = resolve_policy(cli.strict, cli.yes);
            let out_path = Path::new(&out);

            // 1. Caminho local simples: arquivo de commit existente.
            if Path::new(&target).exists() {
                let commit: Commit = serde_json::from_str(&fs::read_to_string(&target)?)?;
                client_download_guard_at(&commit, policy, out_path)?;
                write_clone(out_path, &commit)?;

                // Fase 3: monta dependências (a DHT continua disponível).
                #[cfg(feature = "network")]
                let _ =
                    mount_cloned_dependencies(&commit, out_path, &bootstrap, policy, depth).await;
                #[cfg(not(feature = "network"))]
                let _ = depth;
                return Ok(());
            }

            // 2. Feature network: tenta a DHT (endereço .p2pgit ou alias BEP-44).
            //    fetch_commit valida CADA registro com validate_commit_record.
            #[cfg(feature = "network")]
            {
                let boot = if bootstrap.is_empty() {
                    p2p::default_bootstrap()
                } else {
                    bootstrap
                };
                match p2p::fetch_commit(&target, &boot, policy).await {
                    Ok(fetched) => {
                        // Guard de segurança com base no diretório de saída.
                        client_download_guard_at(&fetched.head, policy, out_path)?;
                        // Histórico completo primeiro (do mais antigo p/ o mais recente).
                        let meta = out_path.join(".p2pgit");
                        fs::create_dir_all(&meta)?;
                        for commit in fetched.chain.iter().rev() {
                            let h = commit.compute_hash();
                            fs::write(
                                meta.join(format!("commit_{}.json", h)),
                                serde_json::to_string_pretty(commit)?,
                            )?;
                        }
                        write_clone(out_path, &fetched.head)?;
                        let h = fetched.head.compute_hash();
                        fs::write(meta.join("HEAD"), &h)?;
                        info!(
                            "Clonado da DHT: {} ({} commit(s) no histórico).",
                            fetched.address,
                            fetched.chain.len() + 1
                        );
                        // Fase 3: monta as dependências .p2pdeps (recursivo, com ciclo).
                        let _ = mount_cloned_dependencies(
                            &fetched.head,
                            out_path,
                            &boot,
                            policy,
                            depth,
                        )
                        .await;
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("[DHT] não foi possível buscar '{}': {}", target, e);
                    }
                }
            }
            #[cfg(not(feature = "network"))]
            let _ = bootstrap;

            // 3. Fallback local: registro de aliases ou commits locais.
            let commit_path = resolve_target(&target)?;
            let commit: Commit = serde_json::from_str(&fs::read_to_string(&commit_path)?)?;
            client_download_guard(&commit, policy)?;
            write_clone(out_path, &commit)?;
        }

        Commands::CreatePr {
            target_address,
            out,
        } => {
            let id = read_identity()?;

            // O alvo precisa ser um endereço .p2pgit válido ou um alias registrado.
            if target_address.ends_with(".p2pgit") {
                RepoIdentity::verify_address(&target_address)?;
            } else {
                let registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
                if registry
                    .resolve(&target_address, DEFAULT_CLIENT_NAMESPACE)
                    .is_none()
                {
                    anyhow::bail!(
                        "Alvo '{}' não é um endereço .p2pgit válido nem um alias registrado.",
                        target_address
                    );
                }
            }

            let head = require_head()?;
            let proposed = load_commit(&head)?;

            let pr = PullRequest::create(&id, target_address.clone(), proposed, head)?;

            let out_file = out.unwrap_or_else(|| format!("pr_{}.json", pr.pr_id));
            fs::write(&out_file, serde_json::to_string_pretty(&pr)?)?;

            info!(
                "Pull Request {} assinado por {}",
                pr.pr_id, id.onion_like_address
            );
            info!("Para: {}", target_address);
            info!("Salvo em: {}", out_file);
            info!("Nota: se o autor original recusar/ignorar, seu repositório permanece como Fork válido.");
        }

        Commands::ApprovePr { pr_file } => {
            let id = read_identity()?;
            let pr: PullRequest = serde_json::from_str(&fs::read_to_string(&pr_file)?)?;

            // 1. O PR deve ser destinado a ESTE repositório.
            if pr.target_repo_address != id.onion_like_address {
                anyhow::bail!(
                    "Este PR é destinado a outro repositório ({}), não a este ({})",
                    pr.target_repo_address,
                    id.onion_like_address
                );
            }

            // 2. Verifica assinatura do fork E autor do commit (anti-reencaminhamento).
            if !pr.is_valid() {
                anyhow::bail!(
                    "ERRO CRÍTICO: PR com assinatura inválida ou autor do commit divergente do autor do PR. Recusado."
                );
            }

            // 3. Bloqueios de segurança do cliente sobre o código proposto.
            let policy = resolve_policy(cli.strict, cli.yes);
            client_download_guard(&pr.proposed_commit, policy)?;

            // Re-assina o código aprovado com a chave privada do repositório original.
            let merged_commit = Commit::create_signed(
                &id,
                Some(pr.proposed_commit.compute_hash()),
                format!(
                    "Merge PR de {}: {}",
                    pr.fork_author_pubkey, pr.proposed_commit.message
                ),
                pr.proposed_commit.files,
                pr.proposed_commit.external_binaries,
                pr.proposed_commit.linked_repos,
                false,
            )?;

            let hash = save_commit(&merged_commit)?;
            info!("PR aprovado! Novo commit oficial assinado: {}", hash);
        }

        Commands::Status => {
            let id = read_identity()?;
            info!("Endereço : {}", id.onion_like_address);
            info!("Pubkey   : {}", id.public_key_hex);
            match read_head() {
                Some(h) => info!("HEAD     : {}", h),
                None => info!("HEAD     : (sem commits)"),
            }
            let registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
            if !registry.records.is_empty() {
                info!("Aliases  :");
                for key in registry.records.keys() {
                    info!("  - {}", key);
                }
            }
        }

        Commands::Verify { target } => {
            let policy = resolve_policy(cli.strict, cli.yes);
            if target.ends_with(".p2pgit") {
                let key = RepoIdentity::verify_address(&target)?;
                info!("Endereço VÁLIDO: {}", target);
                info!("Chave pública: {}", hex::encode(key.to_bytes()));
            } else {
                let commit: Commit = serde_json::from_str(&fs::read_to_string(&target)?)?;
                client_download_guard(&commit, policy)?;
                info!("Commit VÁLIDO: {}", commit.compute_hash());
                info!("Autor: {}", commit.author_pubkey);
            }
        }

        Commands::CheckBinary { file, expected_md5 } => {
            let content = fs::read(&file)?;
            repo::verify_md5(&content, &expected_md5)?;
            info!("MD5 OK: '{}' confere com o manifesto '.binary'.", file);
        }

        Commands::AddBinary {
            file,
            description,
            torrent_infohash,
        } => {
            let content = fs::read(&file)?;
            let md5 = repo::compute_md5_hex(&content);
            let sha256 = repo::compute_sha256_hex(&content);
            let entry = BinaryManifestEntry {
                file_path: Path::new(&file)
                    .to_string_lossy()
                    .replace('\\', "/")
                    .trim_start_matches("./")
                    .to_string(),
                md5_hash: md5.clone(),
                sha256_hash: Some(sha256.clone()),
                torrent_infohash: torrent_infohash.clone(),
                description: description.unwrap_or_else(|| "binário externo".to_string()),
            };

            let mut binaries: Vec<BinaryManifestEntry> =
                serde_json::from_str(&fs::read_to_string(BINARIES_FILE)?).unwrap_or_default();
            let file_path = entry.file_path.clone();
            if let Some(existing) = binaries.iter_mut().find(|b| b.file_path == entry.file_path) {
                *existing = entry;
                info!("Binário ATUALIZADO no '.binary': {}", file_path);
            } else {
                binaries.push(entry);
                info!("Binário ADICIONADO ao '.binary': {}", file_path);
            }
            fs::write(BINARIES_FILE, serde_json::to_string_pretty(&binaries)?)?;

            info!("MD5   : {}", md5);
            info!("SHA256: {}", sha256);
            if let Some(info) = &torrent_infohash {
                info!("InfoHash: {}", info);
            }
            info!(
                "\nO binário NÃO entra no commit de código puro — o commit referencia via '.binary'."
            );
        }

        Commands::FetchBinaries { out_dir } => {
            let binaries: Vec<BinaryManifestEntry> =
                serde_json::from_str(&fs::read_to_string(BINARIES_FILE)?).unwrap_or_default();
            let mut results: Vec<serde_json::Value> = Vec::new();

            for bin in &binaries {
                let Some(infohash) = bin.torrent_infohash.clone() else {
                    results.push(serde_json::json!({
                        "file_path": bin.file_path,
                        "status": "skipped",
                        "reason": "sem torrent_infohash",
                    }));
                    continue;
                };

                let magnet = repo::magnet_from_infohash(&infohash, &bin.file_path);
                let target = Path::new(&out_dir).join(&bin.file_path);
                let status = download_via_magnet(&magnet, &target).await;

                let result = if status.is_ok() {
                    let content = fs::read(&target)?;
                    let md5_ok = repo::verify_md5(&content, &bin.md5_hash).is_ok();
                    let sha_ok = bin
                        .sha256_hash
                        .as_ref()
                        .is_none_or(|s| repo::verify_sha256(&content, s).is_ok());
                    if md5_ok && sha_ok {
                        fs::write(&target, &content)?; // garante conteúdo verificado
                        serde_json::json!({
                            "file_path": bin.file_path,
                            "status": "ok",
                            "md5": bin.md5_hash,
                            "sha256": bin.sha256_hash.clone().unwrap_or_default(),
                        })
                    } else {
                        serde_json::json!({
                            "file_path": bin.file_path,
                            "status": "failed",
                            "reason": format!("integridade falhou (md5_ok={} sha_ok={})", md5_ok, sha_ok),
                        })
                    }
                } else {
                    serde_json::json!({
                        "file_path": bin.file_path,
                        "status": "failed",
                        "reason": status.err().map_or_else(|| "download error".into(), |e| e.to_string()),
                    })
                };
                results.push(result);
            }

            fs::create_dir_all(".p2pgit")?;
            fs::write(
                ".p2pgit/binaries.lock",
                serde_json::to_string_pretty(&results)?,
            )?;
            info!("Resultados de fetch-binaries salvos em .p2pgit/binaries.lock");

            for r in &results {
                let status = r["status"].as_str().unwrap_or("unknown");
                let path = r["file_path"].as_str().unwrap_or("?");
                if status == "ok" {
                    info!(
                        "OK      : {} (download + validação MD5/SHA-256 concluídos)",
                        path
                    );
                } else if status == "skipped" {
                    info!(
                        "IGNORADO: {} ({})",
                        path,
                        r["reason"].as_str().unwrap_or("sem infohash")
                    );
                } else {
                    info!(
                        "FALHOU  : {} ({})",
                        path,
                        r["reason"].as_str().unwrap_or("erro")
                    );
                }
            }
        }

        Commands::AddDep {
            target,
            pin,
            mount,
            name,
            bootstrap,
        } => {
            read_identity()?; // precisa de repositório inicializado

            // 1. O mount_path é relativo e não pode colidir com o metadata.
            anyhow::ensure!(
                !mount.starts_with('/')
                    && !mount.starts_with("../")
                    && mount != ".."
                    && !mount.starts_with(".p2pgit"),
                "mount_path inválido: '{mount}' (use caminho relativo, ex: deps/crypto)"
            );

            // 2. Endereço: válido localmente → alias local → DHT (feature network).
            let target_address = if RepoIdentity::verify_address(&target).is_ok() {
                target
            } else {
                let registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
                if let Some(rec) = registry.resolve(&target, DEFAULT_CLIENT_NAMESPACE) {
                    rec.target_address.clone()
                } else {
                    #[cfg(feature = "network")]
                    {
                        let boot = if bootstrap.is_empty() {
                            p2p::default_bootstrap()
                        } else {
                            bootstrap.clone()
                        };
                        p2p::resolve_target_address(&target, &boot).await?
                    }
                    #[cfg(not(feature = "network"))]
                    {
                        let _ = &bootstrap;
                        anyhow::bail!(
                                "'{target}' não é endereço válido nem alias local — resolva alias pela DHT compilando com --features network (ou informe o endereço)."
                            );
                    }
                }
            };

            // 3. Hash fixado: informado ou HEAD atual do alvo na DHT.
            let pinned_hash = match pin {
                Some(p) => {
                    anyhow::ensure!(
                        p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()),
                        "use o hash completo (64 hex) em --pin (veja 'p2pgit log')."
                    );
                    p
                }
                None => {
                    #[cfg(feature = "network")]
                    {
                        let policy = resolve_policy(cli.strict, cli.yes);
                        let boot = if bootstrap.is_empty() {
                            p2p::default_bootstrap()
                        } else {
                            bootstrap.clone()
                        };
                        let fetched = p2p::fetch_commit(&target_address, &boot, policy).await?;
                        let head_hash = fetched.head.compute_hash();
                        info!(
                            "HEAD atual de {} resolvido: {}",
                            target_address,
                            &head_hash[..12]
                        );
                        head_hash
                    }
                    #[cfg(not(feature = "network"))]
                    {
                        let _ = &bootstrap;
                        anyhow::bail!(
                            "sem --pin é preciso resolver o HEAD do alvo na DHT — compile com --features network."
                        );
                    }
                }
            };

            // 4. Grava (upsert por nome) em `.p2pdeps`.
            let dep_name = name.unwrap_or_else(|| {
                mount
                    .rsplit('/')
                    .next()
                    .unwrap_or(mount.as_str())
                    .to_string()
            });
            let entry = LinkedRepository {
                name: dep_name.clone(),
                target_address_or_alias: target_address.clone(),
                pinned_commit_hash: pinned_hash.clone(),
                mount_path: mount.clone(),
            };
            let mut deps: Vec<LinkedRepository> =
                serde_json::from_str(&fs::read_to_string(DEPS_FILE)?).unwrap_or_default();
            if let Some(existing) = deps.iter_mut().find(|d| d.name == dep_name) {
                *existing = entry;
                info!("Dependência '{}' ATUALIZADA em {}.", dep_name, DEPS_FILE);
            } else {
                deps.push(entry);
                info!("Dependência '{}' adicionada a {}.", dep_name, DEPS_FILE);
            }
            fs::write(DEPS_FILE, serde_json::to_string_pretty(&deps)?)?;

            info!(
                "{} # {} -> {} (será montada no clone)",
                target_address,
                &pinned_hash[..12.min(pinned_hash.len())],
                mount
            );
        }

        #[cfg(feature = "network")]
        Commands::Daemon { bootstrap } => {
            // Bootstrap padrão: ~/.p2pgit/bootstrap.txt quando não informado.
            let boot = if bootstrap.is_empty() {
                p2p::default_bootstrap()
            } else {
                bootstrap
            };
            p2p::run_dht(boot).await?;
        }
    }

    Ok(())
}
