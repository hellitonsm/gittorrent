mod identity;
mod network;
#[cfg(feature = "network")]
mod p2p;
mod repo;
mod sanitizer;

use clap::{Parser, Subcommand};
use identity::RepoIdentity;
use network::{client_download_guard, AliasRecord, AliasRegistry, GuardPolicy, DEFAULT_NAMESPACE};
use repo::{BinaryManifestEntry, Commit, LinkedRepository, PullRequest};
use std::collections::HashSet;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

const DEFAULT_CLIENT_NAMESPACE: &str = DEFAULT_NAMESPACE;

const IDENTITY_FILE: &str = ".p2pgit/identity.json";
const HEAD_FILE: &str = ".p2pgit/HEAD";
const ALIASES_FILE: &str = ".p2pgit/aliases.json";
const BINARIES_FILE: &str = ".binary";
const DEPS_FILE: &str = ".p2pdeps";

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
fn save_commit(commit: &Commit) -> anyhow::Result<String> {
    let hash = commit.compute_hash();
    fs::write(
        format!(".p2pgit/commit_{}.json", hash),
        serde_json::to_string_pretty(commit)?,
    )?;
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
    fs::create_dir_all(out_path)?;
    for (path, content) in &commit.files {
        let dest = out_path.join(path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(dest, content)?;
    }
    println!(
        "Código verificado e clonado em '{}' ({} arquivo(s)).",
        out_path.display(),
        commit.files.len()
    );
    println!("Commit clonado: {}", commit.compute_hash());
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
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { alias } => {
            if Path::new(IDENTITY_FILE).exists() {
                anyhow::bail!("Já existe um repositório neste diretório.");
            }

            let id = RepoIdentity::generate(alias.clone());
            fs::create_dir_all(".p2pgit")?;
            fs::write(IDENTITY_FILE, serde_json::to_string_pretty(&id)?)?;

            // Arquivos padrão `.binary` e `.p2pdeps`.
            let default_binaries: Vec<BinaryManifestEntry> = vec![];
            let default_deps: Vec<LinkedRepository> = vec![];
            fs::write(
                BINARIES_FILE,
                serde_json::to_string_pretty(&default_binaries)?,
            )?;
            fs::write(DEPS_FILE, serde_json::to_string_pretty(&default_deps)?)?;

            println!("Repositório inicializado com sucesso!");
            println!("Endereço Tor-style : {}", id.onion_like_address);
            println!("Chave Pública      : {}", id.public_key_hex);
            println!(
                "Chave Privada      : [SALVA EM {} - NÃO COMPARTILHE]",
                IDENTITY_FILE
            );

            if let Some(a) = alias {
                let record = AliasRecord::new(&id, &a, DEFAULT_CLIENT_NAMESPACE)?;
                let mut registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
                registry.insert(record.clone())?;
                registry.save(Path::new(ALIASES_FILE))?;
                println!(
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

            println!("Registro assinado pronto para propagação na DHT (BEP-44):");
            println!("{}", serde_json::to_string_pretty(&record)?);
            println!("\nSalvo localmente em {}", ALIASES_FILE);

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
                    Err(e) => eprintln!("[DHT] alias não publicado agora: {}", e),
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
            let files = repo::collect_files(Path::new("."))?;

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
            println!("Commit criado e assinado! Hash: {}", hash);
            println!(
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
                        println!(
                            "{}  (commit ausente localmente — histórico incompleto)",
                            &current[..12.min(current.len())]
                        );
                        break;
                    }
                };
                println!(
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
            println!("({} commit(s) no histórico)", index);
        }

        Commands::Show { hash } => {
            let prefix = match hash {
                Some(h) => h,
                None => require_head()?,
            };
            let commit = load_commit(&prefix)?;
            println!("Hash     : {}", commit.compute_hash());
            println!("Autor    : {}", commit.author_pubkey);
            println!("Timestamp: {}", commit.timestamp);
            println!("Mensagem : {}", commit.message);
            println!(
                "Parent   : {}",
                commit.parent_hash.as_deref().unwrap_or("(raiz)")
            );
            println!("Arquivos ({}):", commit.files.len());
            for (path, content) in &commit.files {
                println!("  - {} ({} bytes)", path, content.len());
            }
        }

        Commands::Checkout { hash } => {
            let policy = resolve_policy(cli.strict, cli.yes);
            let commit = load_commit(&hash)?;

            // Restaura apenas código assinado e inspecionado.
            client_download_guard(&commit, policy)?;

            for (path, content) in &commit.files {
                let dest = Path::new(path);
                if let Some(parent) = dest.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent)?;
                    }
                }
                fs::write(dest, content)?;
            }

            let full = commit.compute_hash();
            write_head(&full)?;
            println!(
                "Checkout do commit {} concluído (HEAD detached). Arquivos não commitados podem ter sido sobrescritos.",
                &full[..12]
            );
        }

        Commands::Clone {
            target,
            out,
            bootstrap,
        } => {
            let policy = resolve_policy(cli.strict, cli.yes);
            let out_path = Path::new(&out);

            // 1. Caminho local simples: arquivo de commit existente.
            if Path::new(&target).exists() {
                let commit: Commit = serde_json::from_str(&fs::read_to_string(&target)?)?;
                client_download_guard(&commit, policy)?;
                write_clone(out_path, &commit)?;
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
                        println!(
                            "Clonado da DHT: {} ({} commit(s) no histórico).",
                            fetched.address,
                            fetched.chain.len() + 1
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("[DHT] não foi possível buscar '{}': {}", target, e);
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

            println!(
                "Pull Request {} assinado por {}",
                pr.pr_id, id.onion_like_address
            );
            println!("Para: {}", target_address);
            println!("Salvo em: {}", out_file);
            println!("Nota: se o autor original recusar/ignorar, seu repositório permanece como Fork válido.");
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
            println!("PR aprovado! Novo commit oficial assinado: {}", hash);
        }

        Commands::Status => {
            let id = read_identity()?;
            println!("Endereço : {}", id.onion_like_address);
            println!("Pubkey   : {}", id.public_key_hex);
            match read_head() {
                Some(h) => println!("HEAD     : {}", h),
                None => println!("HEAD     : (sem commits)"),
            }
            let registry = AliasRegistry::load(Path::new(ALIASES_FILE))?;
            if !registry.records.is_empty() {
                println!("Aliases  :");
                for key in registry.records.keys() {
                    println!("  - {}", key);
                }
            }
        }

        Commands::Verify { target } => {
            let policy = resolve_policy(cli.strict, cli.yes);
            if target.ends_with(".p2pgit") {
                let key = RepoIdentity::verify_address(&target)?;
                println!("Endereço VÁLIDO: {}", target);
                println!("Chave pública: {}", hex::encode(key.to_bytes()));
            } else {
                let commit: Commit = serde_json::from_str(&fs::read_to_string(&target)?)?;
                client_download_guard(&commit, policy)?;
                println!("Commit VÁLIDO: {}", commit.compute_hash());
                println!("Autor: {}", commit.author_pubkey);
            }
        }

        Commands::CheckBinary { file, expected_md5 } => {
            let content = fs::read(&file)?;
            repo::verify_md5(&content, &expected_md5)?;
            println!("MD5 OK: '{}' confere com o manifesto '.binary'.", file);
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
