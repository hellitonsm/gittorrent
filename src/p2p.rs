//! Transporte P2P real (Kademlia DHT + Gossipsub) usando libp2p.
//!
//! Habilitado com `cargo run --features network -- daemon`.
//!
//! Registros Kademlia:
//! - `<endereço>`         → HEAD do repositório (commit JSON assinado)
//! - `<endereço>#<hash>`  → commits do histórico
//! - `alias:<ns>:<alias>` → AliasEnvelope (registro mutável BEP-44 style)
//!
//! Toda entrada/saída de registro passa por `network::validate_commit_record`.
//!
//! Arquitetura: o `Swarm` vive em uma task de eventos em background
//! (o swarm precisa ser polulado continuamente para responder a conexões
//! de outros nós). Os comandos entram por um canal de comandos e os
//! eventos saem por um canal de eventos — `P2pNode` é a fachada.

use anyhow::{anyhow, bail, Context};
use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{gossipsub, identify, kad, noise, tcp, yamux, Multiaddr, PeerId};
use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

use crate::identity::RepoIdentity;
use crate::network::{
    alias_record_key, commit_record_key, validate_commit_record, AliasEnvelope, AliasRegistry,
    GuardPolicy, HeadAnnouncement, DEFAULT_NAMESPACE,
};
use crate::repo::Commit;

pub const ANNOUNCE_TOPIC: &str = "p2pgit/announce/v1";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
const GET_TIMEOUT: Duration = Duration::from_secs(20);
const PUT_TIMEOUT: Duration = Duration::from_secs(30);
/// Tentativas de `get_record` quando nenhum par responde (modo Client do par
/// recém-conectado — o identify pode ainda estar em andamento).
const GET_ATTEMPTS: u32 = 5;
/// Commit de 512 KB + margem (padrão do libp2p é 16 KB, insuficiente).
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
/// TTL dos registros (padrão do libp2p é 36 h — curto demais para commits).
const RECORD_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

#[derive(Debug)]
struct BehaviourError(String);

impl fmt::Display for BehaviourError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BehaviourError {}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    /// Troca de endereços observados: sem ele o kad nunca confirma um
    /// endereço externo e fica em modo Client (ignora requests inbound).
    identify: identify::Behaviour,
}

type SwarmEventOut = SwarmEvent<BehaviourEvent>;

/// Comandos enviados à task que detém o `Swarm`.
enum NodeCommand {
    Dial(Multiaddr, oneshot::Sender<Result<PeerId, String>>),
    StartPutRecord(
        String,
        Vec<u8>,
        oneshot::Sender<Result<kad::QueryId, String>>,
    ),
    StartGetRecord(String, oneshot::Sender<kad::QueryId>),
    StartBootstrap(oneshot::Sender<Result<(), String>>),
    Subscribe(String, oneshot::Sender<Result<(), String>>),
    Publish(String, Vec<u8>, oneshot::Sender<Result<(), String>>),
}

/// Loop de eventos do swarm: consome eventos do swarm e comandos do nó.
async fn run_event_loop(
    mut swarm: Swarm<Behaviour>,
    listen_addrs: Arc<Mutex<Vec<Multiaddr>>>,
    mut cmds: mpsc::UnboundedReceiver<NodeCommand>,
    events: mpsc::UnboundedSender<SwarmEventOut>,
) {
    let label = *swarm.local_peer_id();
    loop {
        tokio::select! {
            ev = swarm.next() => match ev {
                Some(ev) => {
                    // Depuração da rede: `P2PGIT_DEBUG_EVENTS=1 <cmd>` imprime
                    // todos os eventos do swarm rotulados pelo PeerId local.
                    if std::env::var("P2PGIT_DEBUG_EVENTS").is_ok() {
                        eprintln!("[{}]: {:?}", label, ev);
                    }
                    // Identify: o endereço que o par observou para nós é um
                    // endereço externo confirmado — é o que tira o kad do modo
                    // Client (senão ele ignora todos os requests inbound).
                    if let SwarmEvent::Behaviour(BehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) = &ev
                    {
                        swarm.add_external_address(info.observed_addr.clone());
                        for addr in &info.listen_addrs {
                            swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(peer_id, addr.clone());
                        }
                    }
                    if let SwarmEvent::NewListenAddr { address, .. } = &ev {
                        if let Ok(mut addrs) = listen_addrs.lock() {
                            addrs.push(address.clone());
                        }
                    }
                    if events.send(ev).is_err() {
                        break; // sem consumidores; encerra
                    }
                }
                None => break,
            },
            cmd = cmds.recv() => match cmd {
                Some(cmd) => handle_cmd(&mut swarm, cmd),
                None => break,
            },
        }
    }
}

fn handle_cmd(swarm: &mut Swarm<Behaviour>, cmd: NodeCommand) {
    match cmd {
        NodeCommand::Dial(addr, tx) => {
            let result = match extract_peer_id(&addr) {
                Some(peer_id) => {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, strip_p2p(&addr));
                    swarm.dial(addr).map(|_| peer_id).map_err(|e| e.to_string())
                }
                None => Err(format!("endereço sem /p2p/<peer_id>: {}", addr)),
            };
            let _ = tx.send(result);
        }
        NodeCommand::StartPutRecord(key, value, tx) => {
            let key_bytes = key.as_bytes().to_vec();
            let result = swarm
                .behaviour_mut()
                .kademlia
                .put_record(
                    kad::Record::new(kad::RecordKey::new(&key_bytes), value),
                    kad::Quorum::One,
                )
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        }
        NodeCommand::StartGetRecord(key, tx) => {
            let key_bytes = key.as_bytes().to_vec();
            let qid = swarm
                .behaviour_mut()
                .kademlia
                .get_record(kad::RecordKey::new(&key_bytes));
            let _ = tx.send(qid);
        }
        NodeCommand::StartBootstrap(tx) => {
            let result = swarm
                .behaviour_mut()
                .kademlia
                .bootstrap()
                .map(|_| ())
                .map_err(|e| format!("{:?}", e));
            let _ = tx.send(result);
        }
        NodeCommand::Subscribe(topic, tx) => {
            let result = swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new(topic))
                .map(|_| ())
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        }
        NodeCommand::Publish(topic, data, tx) => {
            let result = swarm
                .behaviour_mut()
                .gossipsub
                .publish(gossipsub::IdentTopic::new(topic), data)
                .map(|_| ())
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        }
    }
}

/// Resultado de um `fetch_commit` bem-sucedido.
pub struct FetchedRepo {
    pub address: String,
    pub head: Commit,
    /// Ancestrais do HEAD (mais recentes primeiro), quando presentes na rede.
    pub chain: Vec<Commit>,
}

/// Nó libp2p reutilizável: sobe em background, conecta, publica/busca registros.
pub struct P2pNode {
    peer_id: PeerId,
    listen_addrs: Arc<Mutex<Vec<Multiaddr>>>,
    cmds: mpsc::UnboundedSender<NodeCommand>,
    events: mpsc::UnboundedReceiver<SwarmEventOut>,
}

impl P2pNode {
    pub async fn new(bootstrap: Vec<Multiaddr>) -> anyhow::Result<Self> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let peer_id = PeerId::from(key.public());

                let store_cfg = kad::store::MemoryStoreConfig {
                    max_value_bytes: MAX_RECORD_BYTES,
                    max_records: 100_000,
                    ..Default::default()
                };
                let store = kad::store::MemoryStore::with_config(peer_id, store_cfg);

                let mut cfg = kad::Config::default();
                cfg.set_max_packet_size(MAX_RECORD_BYTES);
                cfg.set_record_ttl(Some(RECORD_TTL));
                cfg.set_query_timeout(Duration::from_secs(60));
                let kademlia = kad::Behaviour::with_config(peer_id, store, cfg);

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::Config::default(),
                )
                .map_err(|e| BehaviourError(format!("gossipsub: {}", e)))?;

                let identify = identify::Behaviour::new(identify::Config::new(
                    "p2pgit/1.0".into(),
                    key.public(),
                ));

                Ok(Behaviour {
                    kademlia,
                    gossipsub,
                    identify,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let peer_id = *swarm.local_peer_id();
        let listen_addrs = Arc::new(Mutex::new(Vec::new()));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();

        tokio::spawn(run_event_loop(swarm, listen_addrs.clone(), cmd_rx, ev_tx));

        let mut node = Self {
            peer_id,
            listen_addrs,
            cmds: cmd_tx,
            events: ev_rx,
        };
        node.wait_for_listen(LISTEN_TIMEOUT).await?;

        for addr in bootstrap {
            node.connect_bootstrap(addr).await?;
        }
        // Entra na tabela de roteamento o quanto antes (ignora "sem peers").
        let _ = node.start_kademlia_bootstrap().await;

        Ok(node)
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    /// Endereços de escuta completos com /p2p/<peer_id> (prontos para bootstrap).
    pub fn dialable_addrs(&self) -> Vec<Multiaddr> {
        let mut addrs = self.listen_addrs();
        for a in &mut addrs {
            a.push(libp2p::multiaddr::Protocol::P2p(self.peer_id));
        }
        addrs
    }

    /// Consome o próximo evento do swarm encaminhado pela task de fundo.
    pub async fn next_event(&mut self) -> Option<SwarmEventOut> {
        self.events.recv().await
    }

    async fn wait_for_listen(&mut self, timeout: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.listen_addrs().is_empty() {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("timeout aguardando endereço de escuta");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn send_command<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<T>) -> NodeCommand,
    ) -> anyhow::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.cmds
            .send(build(tx))
            .map_err(|_| anyhow::anyhow!("task de rede encerrada"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("task de rede não respondeu"))
    }

    /// Conecta a um bootstrap node: extrai o PeerId, adiciona na tabela do
    /// kad e aguarda a conexão + a troca de `identify`.
    ///
    /// O `identify` é obrigatório aqui: sem ele o par não confirma nosso
    /// endereço externo e continua em modo Client (ignora requests kad).
    pub async fn connect_bootstrap(&mut self, full_addr: Multiaddr) -> anyhow::Result<PeerId> {
        let peer_id = extract_peer_id(&full_addr)
            .ok_or_else(|| anyhow!("endereço de bootstrap sem /p2p/<peer_id>: {}", full_addr))?;

        let dialed = self
            .send_command(|tx| NodeCommand::Dial(full_addr.clone(), tx))
            .await?;
        dialed.map_err(|e| anyhow!("discando bootstrap {}: {}", full_addr, e))?;

        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut connected_at: Option<Instant> = None;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return match connected_at {
                    Some(_) => Ok(peer_id), // conectou; identify pode estar atrasado
                    None => bail!("timeout conectando ao bootstrap {}", full_addr),
                };
            }
            match tokio::time::timeout(remaining, self.events.recv()).await {
                Err(_) => {
                    return match connected_at {
                        Some(_) => Ok(peer_id),
                        None => bail!("timeout conectando ao bootstrap {}", full_addr),
                    }
                }
                Ok(None) => bail!("swarm encerrado"),
                Ok(Some(SwarmEvent::ConnectionEstablished { peer_id: p, .. })) if p == peer_id => {
                    connected_at.get_or_insert_with(Instant::now);
                }
                // Identify recebido do par: ambos os lados já trocaram chaves
                // e endereços observados — seguro para consultar a DHT.
                Ok(Some(SwarmEvent::Behaviour(BehaviourEvent::Identify(
                    identify::Event::Received { peer_id: p, .. },
                )))) if p == peer_id && connected_at.is_some() => {
                    return Ok(peer_id);
                }
                Ok(Some(_)) => continue,
            }
        }
    }

    async fn start_kademlia_bootstrap(&self) -> anyhow::Result<()> {
        self.send_command(NodeCommand::StartBootstrap)
            .await?
            .map_err(|e| anyhow::anyhow!("bootstrap: {}", e))
    }

    /// Grava o registro no store local e replica para os peers mais próximos.
    ///
    /// O `put_record` do kad grava no store local ANTES de iniciar a query,
    /// então mesmo sem peers o registro fica servível localmente.
    pub async fn put_record(&mut self, key: &str, value: Vec<u8>) -> anyhow::Result<()> {
        anyhow::ensure!(
            value.len() <= MAX_RECORD_BYTES,
            "registro '{}' tem {} bytes (máx {})",
            key,
            value.len(),
            MAX_RECORD_BYTES
        );

        let qid = self
            .send_command(|tx| NodeCommand::StartPutRecord(key.to_string(), value, tx))
            .await?
            .map_err(|e| anyhow!("falha ao gravar registro '{}': {}", key, e))?;

        let deadline = Instant::now() + PUT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, self.events.recv()).await {
                Err(_) => {
                    eprintln!(
                        "[DHT] registro '{}' gravado no store local; sem resposta de peers para propagar",
                        key
                    );
                    return Ok(());
                }
                Ok(None) => bail!("swarm encerrado"),
                Ok(Some(SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                    kad::Event::OutboundQueryProgressed { id, result, .. },
                )))) if id == qid => match result {
                    kad::QueryResult::PutRecord(Ok(_)) => return Ok(()),
                    kad::QueryResult::PutRecord(Err(e)) => {
                        eprintln!(
                            "[DHT] registro '{}' no store local; propagação falhou: {}",
                            key, e
                        );
                        return Ok(());
                    }
                    _ => continue,
                },
                Ok(Some(_)) => continue,
            }
        }
    }

    /// Busca um registro na DHT (store local primeiro, depois os peers).
    /// `Ok(None)` = registro inexistente; `Err` = timeout/erro de rede.
    ///
    /// Distingue "ninguém respondeu" de "registro ausente": se toda request
    /// falhou (par recém-conectado ainda em modo Client, por exemplo),
    /// refaz a query algumas vezes antes de desistir.
    pub async fn get_record(&mut self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let qid = self
                .send_command(|tx| NodeCommand::StartGetRecord(key.to_string(), tx))
                .await?;

            let deadline = Instant::now() + GET_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(remaining, self.events.recv()).await {
                    Err(_) => bail!("timeout buscando registro '{}' na DHT", key),
                    Ok(None) => bail!("swarm encerrado"),
                    Ok(Some(SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryProgressed {
                            id, result, stats, ..
                        },
                    )))) if id == qid => match result {
                        kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(r))) => {
                            return Ok(Some(r.record.value));
                        }
                        kad::QueryResult::GetRecord(Ok(
                            kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                        )) => return Ok(None),
                        kad::QueryResult::GetRecord(Err(_)) => {
                            // Nenhuma resposta dos pares → tentar de novo.
                            if stats.num_successes() == 0 && attempts < GET_ATTEMPTS {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                                break;
                            }
                            return Ok(None);
                        }
                        _ => continue,
                    },
                    Ok(Some(_)) => continue,
                }
            }
        }
    }

    pub async fn gossip_subscribe(&mut self, topic: &str) -> anyhow::Result<()> {
        self.send_command(|tx| NodeCommand::Subscribe(topic.to_string(), tx))
            .await?
            .map_err(|e| anyhow::anyhow!("subscribe '{}': {}", topic, e))
    }

    pub async fn gossip_publish(&mut self, topic: &str, data: Vec<u8>) -> anyhow::Result<()> {
        self.send_command(|tx| NodeCommand::Publish(topic.to_string(), data, tx))
            .await?
            .map_err(|e| anyhow::anyhow!("publish '{}': {}", topic, e))
    }
}

fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

fn strip_p2p(addr: &Multiaddr) -> Multiaddr {
    let mut out = Multiaddr::empty();
    for proto in addr.iter() {
        if matches!(proto, libp2p::multiaddr::Protocol::P2p(_)) {
            break;
        }
        out.push(proto);
    }
    out
}

/// Bootstrap da CLI → Multiaddrs validados.
pub fn parse_bootstrap(list: &[String]) -> anyhow::Result<Vec<Multiaddr>> {
    list.iter()
        .map(|s| {
            s.parse::<Multiaddr>()
                .with_context(|| format!("endereço inválido: {}", s))
        })
        .collect()
}

/// Bootstrap padrão: `~/.p2pgit/bootstrap.txt` (um multiaddr por linha).
pub fn default_bootstrap() -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = std::path::Path::new(&home)
        .join(".p2pgit")
        .join("bootstrap.txt");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// "meu-projeto.open.p2pgit" → ("meu-projeto", "open.p2pgit");
/// "meu-projeto" → ("meu-projeto", namespace padrão).
fn split_alias(target: &str) -> (String, String) {
    match target.split_once('.') {
        Some((name, ns)) => (name.to_string(), ns.to_string()),
        None => (target.to_string(), DEFAULT_NAMESPACE.to_string()),
    }
}

/// `true` se o alvo tem a forma de um endereço real (BASE32 de 35 bytes).
/// Alias também podem terminar em `.p2pgit`, então só o corpo de 56 chars
/// (35 bytes codificados em base32 sem padding) identifica um endereço.
fn looks_like_address(target: &str) -> bool {
    target
        .strip_suffix(".p2pgit")
        .is_some_and(|body| body.len() == 56 && body.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Resolve endereço/alias na DHT e baixa o HEAD + histórico disponível.
///
/// Cada registro passa por `validate_commit_record` (assinatura, sanitização,
/// ligação chave↔autor). O guard interativo pode abortar com `policy`.
pub async fn fetch_commit(
    target: &str,
    bootstrap: &[String],
    policy: GuardPolicy,
) -> anyhow::Result<FetchedRepo> {
    let mut node = P2pNode::new(parse_bootstrap(bootstrap)?).await?;

    // 1. Resolve o endereço final (direto ou via registro de alias).
    //    Um endereço real é BASE32 de 35 bytes = 56 chars + ".p2pgit";
    //    alias como "meu-projeto.open.p2pgit" também terminam em .p2pgit,
    //    então o tamanho do corpo é o que os distingue.
    let address = if looks_like_address(target) {
        RepoIdentity::verify_address(target)?; // checksum e versão
        target.to_string()
    } else {
        let (alias, namespace) = split_alias(target);
        let key = alias_record_key(&namespace, &alias);
        let bytes = node
            .get_record(&key)
            .await?
            .ok_or_else(|| anyhow!("nenhum registro de alias '{}' na DHT", key))?;
        let envelope: AliasEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow!("registro de alias '{}' corrompido: {}", key, e))?;
        anyhow::ensure!(
            envelope.is_valid(),
            "registro de alias '{}' com assinatura inválida",
            key
        );
        println!("Alias '{}' -> {}", key, envelope.record.target_address);
        envelope.record.target_address
    };

    // 2. HEAD sob `<endereço>`.
    let head_bytes = node
        .get_record(&address)
        .await?
        .ok_or_else(|| anyhow!("nenhum commit publicado sob {}", address))?;
    let head = validate_commit_record(&address, &head_bytes, policy)?;

    // 3. Histórico: `<endereço>#<parent_hash>` até a raiz ou ausência.
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut parent = head.parent_hash.clone();
    while let Some(hash) = parent {
        if !visited.insert(hash.clone()) {
            break;
        }
        let key = commit_record_key(&address, Some(&hash));
        match node.get_record(&key).await {
            Ok(Some(bytes)) => match validate_commit_record(&key, &bytes, policy) {
                Ok(c) => {
                    parent = c.parent_hash.clone();
                    chain.push(c);
                }
                Err(e) => {
                    eprintln!("[DHT] registro '{}' rejeitado: {}", key, e);
                    break;
                }
            },
            _ => {
                eprintln!(
                    "[DHT] '{}' ausente — histórico incompleto (commit de fork não semeado?)",
                    key
                );
                break;
            }
        }
    }

    Ok(FetchedRepo {
        address,
        head,
        chain,
    })
}

/// Sequência monotônica para registros mutáveis (BEP-44 style), persistida em `.p2pgit/seq`.
pub fn next_seq() -> anyhow::Result<u64> {
    let path = std::path::Path::new(".p2pgit/seq");
    let current: u64 = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let next = current + 1;
    std::fs::write(path, next.to_string())?;
    Ok(next)
}

/// Publica um alias deste repositório na DHT como registro mutável assinado.
pub async fn publish_alias(
    id: &RepoIdentity,
    alias: &str,
    namespace: &str,
    bootstrap: &[String],
) -> anyhow::Result<()> {
    let mut node = P2pNode::new(parse_bootstrap(bootstrap)?).await?;
    let seq = next_seq()?;
    let envelope = AliasEnvelope::create(id, seq, alias, namespace)?;
    let key = alias_record_key(namespace, alias);
    node.put_record(&key, serde_json::to_vec(&envelope)?)
        .await?;
    println!("Alias '{}' (seq={}) publicado na DHT.", key, seq);
    Ok(())
}

/// Semeia o repositório local na DHT: HEAD, histórico completo e aliases.
/// Retorna o número de registros gravados.
pub async fn seed_local_repo(node: &mut P2pNode) -> anyhow::Result<usize> {
    let id: RepoIdentity =
        serde_json::from_str(&std::fs::read_to_string(".p2pgit/identity.json")?)?;
    let head = std::fs::read_to_string(".p2pgit/HEAD")?.trim().to_string();
    let mut seeded = 0;

    // Commits: cada arquivo é conferido contra o próprio hash antes de sair daqui.
    for entry in std::fs::read_dir(".p2pgit")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(hash) = name
            .strip_prefix("commit_")
            .and_then(|s| s.strip_suffix(".json"))
        else {
            continue;
        };
        let bytes = std::fs::read(entry.path())?;
        let commit: Commit = serde_json::from_slice(&bytes)?;
        if commit.compute_hash() != hash {
            eprintln!(
                "[seed] '{}' não corresponde ao hash do arquivo — ignorado",
                name
            );
            continue;
        }
        let key = if hash == head {
            commit_record_key(&id.onion_like_address, None)
        } else {
            commit_record_key(&id.onion_like_address, Some(hash))
        };
        node.put_record(&key, bytes).await?;
        seeded += 1;
    }

    // Aliases deste repositório, como registros mutáveis assinados.
    if let Ok(registry) = AliasRegistry::load(std::path::Path::new(".p2pgit/aliases.json")) {
        for record in registry.records.values() {
            if !record.pubkey_hex.eq_ignore_ascii_case(&id.public_key_hex) {
                continue;
            }
            let seq = next_seq()?;
            let envelope = AliasEnvelope::create(&id, seq, &record.alias, &record.namespace)?;
            let key = alias_record_key(&record.namespace, &record.alias);
            node.put_record(&key, serde_json::to_vec(&envelope)?)
                .await?;
            seeded += 1;
        }
    }

    Ok(seeded)
}

/// Daemon: inicia o nó, semeia o repositório local e reage a eventos de rede.
pub async fn run_dht(bootstrap: Vec<String>) -> anyhow::Result<()> {
    let mut node = P2pNode::new(parse_bootstrap(&bootstrap)?).await?;
    println!("PeerId: {}", node.peer_id());
    for addr in node.dialable_addrs() {
        println!("Ouvindo em: {}", addr);
    }

    node.gossip_subscribe(ANNOUNCE_TOPIC).await?;

    match seed_local_repo(&mut node).await {
        Ok(n) if n > 0 => println!("{} registro(s) semeado(s) na DHT.", n),
        Ok(_) => println!("Nada para semear (repo não inicializado ou sem commits/aliases)."),
        Err(e) => eprintln!("[seed] {}", e),
    }

    // Anuncia o HEAD local (falha silenciosamente sem peers conectados).
    if let (Ok(id_json), Ok(head)) = (
        std::fs::read_to_string(".p2pgit/identity.json"),
        std::fs::read_to_string(".p2pgit/HEAD"),
    ) {
        if let Ok(id) = serde_json::from_str::<RepoIdentity>(&id_json) {
            let ann = HeadAnnouncement::new(&id, head.trim())?;
            match node
                .gossip_publish(ANNOUNCE_TOPIC, serde_json::to_vec(&ann)?)
                .await
            {
                Ok(()) => println!("Anúncio de HEAD publicado: {}", &ann.head_hash[..12]),
                Err(e) => eprintln!("[announce] {}", e),
            }
        }
    }

    println!("Nó DHT iniciado. Aguardando conexões...");
    while let Some(event) = node.next_event().await {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed { result, .. },
            )) => match result {
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(r))) => {
                    println!("Registro encontrado: {:?}", r.record.key);
                }
                kad::QueryResult::Bootstrap(Ok(b)) => {
                    println!("Bootstrap: peer={}, restantes={}", b.peer, b.num_remaining);
                }
                kad::QueryResult::Bootstrap(Err(e)) => {
                    eprintln!("Bootstrap erro: {:?}", e);
                }
                _ => {}
            },
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("Peer conectado: {}", peer_id);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                let data = message.data;
                match serde_json::from_slice::<HeadAnnouncement>(&data) {
                    Ok(ann) if ann.is_valid() => {
                        println!(
                            "Anúncio válido: {} -> HEAD {}",
                            ann.address,
                            &ann.head_hash[..12.min(ann.head_hash.len())]
                        );
                    }
                    Ok(_) => eprintln!(
                        "Anúncio INVÁLIDO descartado (assinatura/frescor/endereço inconsistentes)."
                    ),
                    Err(_) => {} // mensagem que não é anúncio; ignorar
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dois nós em loopback: B publica um registro, A o encontra
    /// (via replicação ou query na rede).
    #[tokio::test]
    async fn two_nodes_put_and_get_record() {
        let mut a = P2pNode::new(vec![]).await.unwrap();
        let addr_a = a.dialable_addrs()[0].clone();

        let mut b = P2pNode::new(vec![addr_a]).await.unwrap();
        b.put_record("chave-teste", b"valor-p2pgit".to_vec())
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        let mut found = None;
        while Instant::now() < deadline {
            match a.get_record("chave-teste").await {
                Ok(Some(v)) => {
                    found = Some(v);
                    break;
                }
                Ok(None) | Err(_) => continue,
            }
        }
        assert_eq!(found.as_deref(), Some(b"valor-p2pgit".as_ref()));
    }

    #[test]
    fn split_alias_variants() {
        assert_eq!(
            split_alias("meu-projeto.open.p2pgit"),
            ("meu-projeto".into(), "open.p2pgit".into())
        );
        assert_eq!(
            split_alias("meu-projeto"),
            ("meu-projeto".into(), DEFAULT_NAMESPACE.into())
        );
    }
}
