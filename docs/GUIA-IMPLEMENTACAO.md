# Guia de Implementação — p2pgit funcional de ponta a ponta

> Análise feita em 2026-11-16 sobre o README (spec), `Cargo.toml` e o código-fonte
> (`identity.rs`, `sanitizer.rs`, `repo.rs`, `network.rs`, `p2p.rs`, `main.rs`).
> Estado atual: 12 testes passando, MVP local funcional, **rede real e vários
> recursos prometidos na spec ainda não implementados**.

## Status das fases

| Fase | Estado | Evidência |
|---|---|---|
| **0 — Consolidação do MVP local** | ✅ Concluída | Hash canônico (BTreeMap + vetores ordenados), varredura recursiva com `.p2pgitignore`, PR assinado anti-reencaminhamento, `log`/`show`/`checkout`, `GuardPolicy` + `--yes`/`--strict`, commits indexados por hash completo. 20 testes + clippy limpo. |
| **1 — Rede real (DHT)** | ✅ Concluída | `P2pNode` com event-loop em background, `identify` (sem ele o kad fica em modo Client e ignora requests inbound), validação na borda via `validate_commit_record`, histórico completo `endereço#hash`, alias BEP-44 com `seq`, gossipsub `p2pgit/announce/v1`, bootstrap padrão em `~/.p2pgit/bootstrap.txt`. 22 testes com `--features network`. E2E: 2 daemons em loopback, clone por endereço e por alias, histórico de 2 commits, clone via 3º nó que só conhece um bootstrap. |
| **2 — Binários via BitTorrent** | ✅ Concluída | `add-binary` (MD5 + SHA-256 + infohash opcional, grava em `.binary`), `fetch-binaries` (magnet → `aria2c` → valida MD5/SHA-256 → grava `.p2pgit/binaries.lock`), varredura do commit ignora binários do manifesto, guard no clone verifica `binaries/<file_path>` (ausente → aviso com instrução; divergente → bloqueio). 26 testes. E2E: binário ausente/correto/corrompido validados no clone. |
| **3 — Dependências `.p2pdeps`** | ✅ Concluída | `add-dep` (resolve HEAD na DHT ou fixa com `--pin`, grava em `.p2pdeps`), montagem no clone em `<out>/<mount_path>` com recursão (`--depth`, padrão 1) e detecção de ciclo por (alvo, hash fixado), `.p2pgit/deps.lock` com o resultado por dependência. HEAD do repo semeado sob a chave plana **e** `#hash`. 29 testes. E2E: clone pela DHT traz `deps/crypto/`; pin adulterado → falha; ciclo → ignorado com aviso. |
| **4 — PRs pela rede** | ✅ Concluída | `create-pr --bootstrap` publica o PR como registro `pr:<alvo>#<pr_id>` **e** no índice `<alvo>#prs` (Kademlia não faz busca por prefixo — sem índice ninguém descobre os PRs) + gossip no tópico `p2pgit/pr/<alvo>/v1`. `list-prs` lê o índice pela DHT e mescla com o inbox do daemon, revalidando tudo. `approve-pr` endurecido: detecta fork desatualizado (base ≠ HEAD), recusa **conflitos** de arquivos e faz merge 3-way trivial (não reverte mudanças do autor). 36 testes. |
| **3 — Dependências `.p2pdeps`** | ⬜ Pendente | |
| **4 — PRs pela rede** | ⬜ Pendente | |
| **5 — Endurecimento** | ⬜ Pendente | |

### Armadilhas reais encontradas na Fase 1 (evitar recair)

1. **`libp2p-kad` nasce em `Mode::Client`** e só vira `Server` quando há um
   endereço externo **confirmado**. Sem `identify`, os nós nunca confirmam
   endereço → **ignoram todo request inbound** (`DeniedUpgrade` no handler),
   e todo `put`/`get` falha com "quorum failed"/`NotFound` mesmo com TCP
   conectado. Correção: comportamento `identify` + `swarm.add_external_address
   (info.observed_addr)` no evento `identify::Event::Received`.
2. **O swarm precisa ser polulado continuamente** — um `Swarm` parado não
   aceita conexões. Comandos efêmeros (`clone`, `register-alias`) exigem uma
   task de eventos em background (`NodeCommand` via mpsc), senão o nó ocioso
   nunca responde ao dial do par.
3. **Corrida identificação × primeira query**: o par pode ainda estar em modo
   Client quando o `get` sai. `connect_bootstrap` espera o `identify::Received`
   e `get_record` refaz a query (5×) quando `num_successes() == 0`.
4. **Alias podem terminar em `.p2pgit`** (`meu-projeto.open.p2pgit`): distinguir
   endereço real por `looks_like_address` (corpo BASE32 de 56 chars), não pelo
   sufixo.
5. **Limites do kad são baixos por padrão** (65 KB de registro, 16 KB de
   pacote, TTL de 36 h) — incompatíveis com commits de 512 KB. Elevar
   `max_value_bytes`/`max_packet_size` (2 MB) e `record_ttl` (30 dias).

## 1. Diagnóstico: o que existe × o que a spec promete

| Recurso da spec | Estado | Evidência no código |
|---|---|---|
| Endereço Tor-style (Base32 + checksum + versão) | ✅ Feito | `identity.rs::derive_tor_address` / `verify_address` (35 bytes, v3, roundtrip testado) |
| Assinatura Ed25519 do commit | ✅ Feito | `repo.rs::create_signed` + `is_signature_valid` |
| Sanitizador (anti-binário, anti-Base64, limite 512 KB) | ✅ Feito | `sanitizer.rs`, `repo.rs` |
| `.binary` / `.p2pdeps` / MD5 | ⚠️ Parcial | Manifestos criados e hashados, mas **nunca consumidos**: `mount_path` não é montado no clone; binários não são baixados |
| PR "assinado pela chave do fork" | ❌ **Não implementado** | `PullRequest` (`repo.rs:44-50`) **não tem campo `signature`** — `create_pr` grava JSON cru; `approve-pr` nunca valida o autor do fork |
| Clone via endereço/alias na rede | ❌ Stub | `resolve_target` (`main.rs:110-152`) só acha commits **locais**; endereço válido → erro "aguardando peers" |
| Alias propagado na DHT (BEP-44) | ❌ Stub | `register-alias` só grava em `aliases.json` local; nada de `kad::put_record` |
| Daemon semeia o commit | ⚠️ Parcial | `p2p.rs::run_dht` semeia apenas o **HEAD**; sem `get_record`, sem servir registros de outros peers, gossipsub criado mas **nunca usado** |
| Histórico / DAG | ❌ Ausente | `clone` copia 1 commit; não segue `parent_hash`; sem `log`, `show`, `checkout` |
| Binários via BitTorrent (infohash) | ❌ Ausente | Nenhum cliente torrent; usuário valida na mão com `check-binary` |
| Transporte Tor real | ❌ Ausente | "Tor" é só o **formato do endereço**; sem SOCKS5/hidden service |

### Bugs/dívidas encontrados no código atual (corrigir antes de crescer)

1. **PR não assinado** — a spec diz "assinado pela chave do fork"; o `main.rs:273-294` não assina nada e `approve-pr` (`main.rs:296-318`) aceita PR de **qualquer um** sem verificar autor.
2. **`compute_hash` não cobre o commit inteiro** (`repo.rs:115-139`): ignora `mount_path` dos deps, `description`/`torrent_infohash` dos binários, e depende da ordem dos campos. Duas serializações do mesmo conteúdo lógico podem divergir. Risco de hash-division e de colliders.
3. **Commit só varre o diretório raiz** (`main.rs:209-225`): `read_dir(".")` ignora subpastas inteiras — o comando "empacota os arquivos de texto" prometido não funciona em projeto real.
4. **`resolve_target` por alias pega QUALQUER commit do autor** (`main.rs:122-133`), não o commit apontado pelo alias/HEAD do repo alvo; variável `candidate` é código morto.
5. **`save_commit` trunca o hash em 12 hex** (`main.rs:103`): risco de colisão em ~2⁴⁸ commits; usar hash completo ou prefixo ≥ 16.
6. **`client_download_guard` é interativo** (`network.rs:123-130`): trava scripts/daemon; falta flag `--yes`/`--no-interactive` e é executado inclusive em `verify`.
7. **Timestamp entra no hash sem limite**: permite minerar timestamps para colisões de hash (não crítico hoje, mas anote para a fase de endurecimento).

---

## Fase 0 — Consolidação do MVP local (pré-requisito)

**Objetivo:** tornar o fluxo local correto e completo antes de tocar em rede.

### Passo 0.1 — Corrigir o hash canônico do commit
- Substituir o `compute_hash` manual por serialização canônica:
  ```rust
  pub fn compute_hash(&self) -> String {
      // serializa sem o campo signature, com chaves ordenadas
      let mut c = self.clone();
      c.signature = String::new();
      let json = serde_json::to_vec(&c).unwrap(); // serde_json já ordena? não: use `serde_json::Map` ordenado ou BTreeMap em `files`
      hex::encode(Sha256::digest(&json))
  }
  ```
- Trocar `HashMap<String, String>` em `Commit.files` por `BTreeMap` (ordenação determinística de graça) e as listas de binários/deps por ordenação por `file_path`/`name` antes do hash.
- **Cuidado de migração:** isso muda todos os hashes; é o momento certo (0.1.0, sem dados reais).
- Testes: mesmo commit criado duas vezes com maps em ordem diferente → mesmo hash.

### Passo 0.2 — Varredura recursiva do diretório
- Criar `repo::collect_files(root: &Path) -> Result<BTreeMap<String, String>>`:
  - caminha recursivamente (`walkdir` crate ou recursão manual),
  - ignora `.p2pgit/`, `.git/`, `target/`, `node_modules/` e tudo em um novo `.p2pgitignore` (sintaxe gitignore simples: linhas de glob),
  - respeita o limite de 512 KB somando progressivamente.
- Mover a lógica de `Commands::Commit` para dentro de `repo.rs` e deixar o `main.rs` fino.

### Passo 0.3 — Assinar e verificar PullRequests
- Adicionar campo ao struct (`repo.rs`):
  ```rust
  pub struct PullRequest {
      pub pr_id: String,
      pub target_repo_address: String,
      pub fork_author_pubkey: String,
      pub proposed_commit: Commit,
      pub fork_head_hash: String,   // para detectar PRs desatualizados
      pub signature: String,        // Ed25519(fork_priv, payload)
  }
  ```
- Payload assinado = `pr_id|target_repo_address|fork_author_pubkey|fork_head_hash|proposed_commit.compute_hash()`.
- `CreatePr`: assinar com a identidade local; `ApprovePr`: **validar** `is_valid()` (novo método) antes do `client_download_guard`, e checar `fork_author_pubkey == proposed_commit.author_pubkey`.
- Novos testes: PR válido é aceito; PR com assinatura forjada é recusado; PR cujo commit interno foi trocado é recusado.

### Passo 0.4 — Histórico local (DAG mínima)
- Novos subcomandos:
  - `log` — caminha `HEAD → parent_hash` lendo `commit_*.json`, imprime `hash12 msg autor data`;
  - `show [hash]` — imprime arquivos/mensagem do commit;
  - `checkout <hash12|full>` — restaura os arquivos do commit no diretório e atualiza um `HEAD_detached` (ou desanexa o HEAD).
- Renomear `save_commit` para salvar com **hash completo** (ou 16+ hex) e indexar por hash em um único `commits.json` (map hash → caminho) para busca O(1).

### Passo 0.5 — Guard não-interativo e flags
- `client_download_guard(commit, Policy)` com `Policy::Interactive | Policy::DenyAll | Policy::AllowAllAfterWarning`.
- Flags globais no CLI: `--yes` (aceita avisos), `--strict` (rejeita qualquer suspeito). Padrão = Interactive no TTY, `DenyAll` quando não-TTY.
- Critério de aceite da Fase 0: `cargo test` com ≥ 20 testes, e o fluxo abaixo funciona:
  ```bash
  p2pgit init --alias demo && p2pgit commit -m a && p2pgit commit -m b
  p2pgit log                       # mostra os 2 commits ligados por parent_hash
  p2pgit checkout <hash_a>         # restaura estado antigo
  p2pgit create-pr <endereço> && p2pgit approve-pr pr_*.json
  ```

---

## Fase 1 — Rede real: publicar e buscar commits (coração do sistema)

> **✅ Concluída** (2026-11-16). Implementada em `src/p2p.rs` (`P2pNode` +
> event-loop em background), `src/network.rs` (`validate_commit_record`,
> `AliasEnvelope`, `HeadAnnouncement`) e `src/main.rs` (clone com fallback
> DHT → local). Critério de aceite validado em E2E com dois daemons.
> Ver "Armadihas reais encontradas na Fase 1" no topo deste guia.

**Objetivo:** `clone <endereço>.p2pgit` funcionar **de verdade** entre duas máquinas.

### Passo 1.1 — Separar o nó de rede em biblioteca
- Extrair o código de `p2p.rs` para uma API reutilizável:
  ```rust
  pub struct P2pNode { swarm: Swarm<Behaviour>, }
  impl P2pNode {
      pub async fn new(bootstrap: Vec<Multiaddr>, listen: Vec<Multiaddr>) -> Result<Self>;
      pub async fn put_record(&mut self, key: &str, value: Vec<u8>) -> Result<()>;
      pub async fn get_record(&mut self, key: &str, timeout: Duration) -> Result<Option<Vec<u8>>>;
      pub fn local_peer_id(&self) -> PeerId;      // necessário para bootstrap de outros
      pub fn listen_addrs(&self) -> Vec<Multiaddr>; // imprime "/ip4/x.x.x.x/tcp/port/p2p/<peer_id>"
  }
  ```
- `run_dht` (daemon) passa a ser um consumidor dessa API; os comandos `clone`/`register-alias` criam um nó **efêmero** (sobe, faz a operação, desce) — sem exigir daemon rodando.

### Passo 1.2 — Validar registros Kademlia na borda
- Toda gravação/leitura passa por uma função única `validate_record(key, value)`:
  - o `value` é um `Commit` JSON válido;
  - `commit.compute_hash()` confere com o hash esperado (quando conhecido);
  - `client_download_guard(commit, policy)` roda;
  - a chave do registro **deve** derivar da `author_pubkey` (impede alguém publicar commit falso sob endereço alheio).
- **Regra da rede:** nunca escrever um registro obtido de peer sem validar; nunca servir registro não validado.

### Passo 1.3 — `clone <endereço>` real
1. Extrai a pubkey do endereço (`verify_address`).
2. `P2pNode::get_record(endereço)` com timeout de ~30 s.
3. Valida (Passo 1.2) e escreve os arquivos em `--out`.
4. Persiste o commit localmente em `<out>/.p2pgit/` junto com uma `identity.json` **sem chave privada** (`private_key_hex: None` — o campo já existe para isso!) para que o clone possa criar PRs depois.
- Bootstrap por padrão: lista de nós fixos em `~/.p2pgit/bootstrap.toml` + flag `--bootstrap`.
- Teste de integração: iniciar 2 nós em loopback na mesma suite (`tokio::test`), um publica, outro busca.

### Passo 1.4 — Semear o histórico completo
- No `daemon` e no `clone` do servidor: publicar cada commit da cadeia sob a chave `endereço#hash` ( além do HEAD em `endereço`).
- `clone` busca o HEAD e depois repete `get_record(endereço#parent)` até a raiz (limite: 1000 saltos) → history real.
- Comando `p2pgit fetch` (atualiza repo clonado até o novo HEAD) reusa a mesma lógica.

### Passo 1.5 — Aliases na DHT (BEP-44 style)
- Registro mutável assinado:
  ```rust
  pub struct MutableAliasRecord {
      pub alias_record: AliasRecord, // já assinado pelo dono
      pub seq: u64,                  // monotônico; peer rejeita seq menor
      pub v_signature: Vec<u8>,      // sig sobre (seq || alias_record)
  }
  ```
- `register-alias`: além de salvar local, faz `put_record` na chave `alias:<namespace>:<alias>`.
- `resolve`: 1º registro local, 2º `get_record` na DHT, validando `seq` e a assinatura interna (o `AliasRegistry::insert` já valida assinatura e correspondência pubkey↔endereço — reusar).
- Persistir registros de aliases recebidos em `~/.p2pgit/alias-cache.json` (o `MemoryStore` do kad perde tudo ao reiniciar).

### Passo 1.6 — Gossipsub: anúncios
- Tópicos:
  - `p2pgit/announce/<endereço>/v1` — autor anuncia novo HEAD (mensagem = hash + assinatura);
  - `p2pgit/pr/<endereço>/v1` — forks anunciam PRs (o JSON assinado da Fase 0).
- Daemon subscreve os tópicos dos aliases que ele segue e reage: novo anúncio → `fetch` automático (opcional, flag `--auto-fetch`).
- Critério de aceite da Fase 1: em duas pastas/máquinas, `daemon` na A + `clone <endereço-de-A> --out repo-b` na B funciona sem nenhum arquivo copiado à mão; `log` em B mostra a cadeia.

---

## Fase 2 — Binários via BitTorrent

> **✅ Concluída** (2026-11-17). Comandos `add-binary` e `fetch-binaries`
> implementados em `main.rs`; `BinaryManifestEntry` ganhou `sha256_hash`
> (opcional, com compatibilidade retroativa de JSON legado); a varredura do
> commit ignora binários listados no `.binary`; o guard do clone valida
> `binaries/<file_path>` quando presentes e avisa quando ausentes. Download via
> magnet usa `aria2c` externo (mensagem de instalação quando ausente).

**Objetivo:** consumir e produzir o manifesto `.binary` de ponta a ponta.

### Passo 2.1 — Comandos de manifesto
- `p2pgit add-binary <arquivo> [--description ...] [--torrent-infohash <40hex>]`:
  - calcula MD5, insere/atualiza entrada em `.binary`, imprime aviso de que o binário sairá do commit;
  - se `--torrent-infohash` não for dado e `--seed` for passado, cria o torrent localmente (Passo 2.2) e preenche o infohash.
- `p2pgit fetch-binaries`: para cada entrada com `torrent_infohash`, baixa e valida MD5.

### Passo 2.2 — Integração torrent
- Opção recomendada: crate **`librqbit`** (client BitTorrent v2/1 em Rust, API embutível) ou shelling out para `transmission-cli`/`aria2c` no MVP.
- Fluxo: obter `.torrent`/magnet a partir do infohash via DHT pública do BitTorrent → baixar para `binaries/<file_path>` → `verify_md5` **antes** de qualquer execução → registrar sucesso/falha em `.p2pgit/binaries.lock`.
- Segurança: MD5 é fraco (colisões conhecidas). Adicionar campo `sha256_hash` opcional no `BinaryManifestEntry` e preferir SHA-256 quando presente (o `md-5`/`sha2` já estão nas deps).

### Passo 2.3 — Guard de binários no clone
- No `client_download_guard`, além de listar, verificar se os binários já estão em `binaries/` e validar MD5 na hora; entradas faltantes viram aviso com instrução `fetch-binaries`.
- Critério de aceite: repo com `textura.png` listada; `clone` + `fetch-binaries` no peer B produz o arquivo com MD5 conferindo.

---

## Fase 3 — Dependências `.p2pdeps` (submódulos P2P)

> **✅ Concluída** (2026-11-17). Comando `add-dep` e montagem no clone
> implementados em `main.rs`; busca do commit fixado em
> `p2p::fetch_pinned_commit` (valida assinatura + hash da chave);
> `network::dep_identity_key` para detecção de ciclo; `.p2pgit/deps.lock`.
> Descoberta importante: o HEAD precisa ser semeado **também** sob
> `<endereço>#<hash>`, senão a dependência fixada no HEAD atual não é
> encontrada na DHT.

**Objetivo:** `mount_path` deixar de ser decorativo.

### Passo 3.1 — Resolver e montar no clone
- Após clonar o repo principal, para cada `LinkedRepository`:
  1. resolver `target_address_or_alias` (endereço → DHT; alias → registro BEP-44);
  2. `get_record(endereço#pinned_commit_hash)`;
  3. validar (`client_download_guard` + hash bate com `pinned_commit_hash`);
  4. clonar em `mount_path/` (recursivamente, com `--depth` padrão 1 e detecção de ciclo por `pinned_commit_hash` já visitado).
- Gravar `.p2pgit/deps.lock` com o que foi resolvido (endereço + hash + caminho).

### Passo 3.2 — Comando `p2pgit add-dep`
- `p2pgit add-dep <endereço-ou-alias> [--pin <hash>] --mount deps/crypto` — resolve o HEAD atual do alvo se `--pin` não for dado, grava em `.p2pdeps`.
- Critério de aceite: repo A depende de `crypto-lib` → clone de A traz `deps/crypto/` com os arquivos do commit fixado.

---

## Fase 4 — PRs pela rede + colaboração

> **✅ Concluída** (2026-11-17). `create-pr --bootstrap` publica o PR como
> registro `pr:<alvo>#<pr_id>` **e** no índice `<alvo>#prs` (Kademlia não tem
> busca por prefixo — sem um índice, ninguém descobre quais PRs existem) e
> anuncia no gossip `p2pgit/pr/<alvo>/v1`. O daemon assina esse tópico e
> salva os PRs recebidos em `.p2pgit/inbox-prs.json`. `list-prs` une índice
> da DHT + inbox, revalidando cada assinatura. `approve-pr` endurecido:
> fork desatualizado (base ≠ HEAD) vira aviso, conflito de arquivos é
> recusado, e o merge é 3-way trivial por arquivo.
>
> **Bugs encontrados e corrigidos no caminho:**
> 1. o clone não gravava o arquivo do commit HEAD em `.p2pgit/` — `log` e o
>    cálculo do fork point quebravam no fork;
> 2. o merge sobrescrevia a árvore do HEAD com a do fork, **revertendo**
>    mudanças do autor em arquivos que o fork nem tocou (corrigido com
>    `merge_trees`);
> 3. gossipsub tem corrida em nós efêmeros: o publish saía antes da malha
>    se formar (daí o índice determinístico como caminho principal).

- `create-pr` além do arquivo: publicar o PR (JSON assinado da Fase 0) no tópico gossipsub `p2pgit/pr/<alvo>/v1` **e** como `kad::Record` sob a chave `pr:<alvo>#<pr_id>`.
- Novos comandos no repo original:
  - `p2pgit list-prs` — busca registros `pr:<meu-endereço>#*` (via gossipsub recebido no daemon + DHT), valida cada assinatura;
  - `p2pgit approve-pr <pr.json>` — passa a checar: assinatura do fork, `fork_head_hash` ainda é ancestral do HEAD atual (evita merges de forks desatualizados sem aviso), e conflito de arquivos (mesmo caminho alterado no HEAD e no PR → pedir resolução manual).
- Opcional (merge real): implementar merge 3-way trivial por arquivo (se só um lado mudou, usa ele; se ambos, recusa pedindo rebase no fork). Nada de fusão textual automática no MVP.

---

## Fase 5 — Endurecimento e produção

1. **Cripto**
   - Checar timestamps/limites no `client_download_guard` (commit com data futura → aviso).
   - SHA-256 em `.binary`; degradar MD5 para "legado".
2. **Rede**
   - `autonat` + `relay` + `dcutr` do libp2p (NAT traversal) e opcionalmente `quic`.
   - Persistência de registros DHT (`FileStore` ou `SQLiteStore` em vez de `MemoryStore`).
   - Rate-limit e tamanho máximo de registro (512 KB + margem) na validação de entrada.
3. **Tor real (opcional)**
   - Transporte por SOCKS5/hidden service: endereços `.p2pgit` continuam sendo identidade; o "Tor" de verdade entra como transporte opcional (`--tor` no daemon usando `arti` ou Tor SOCKS do sistema).
4. **Qualidade**
   - Testes de integração de rede automatizados (2 nós em loopback), fuzz do `sanitizer` (`cargo fuzz`), CI (fmt + clippy + test + test --features network).
   - `cargo audit` no CI (dependências com `unsafe`/CVE).
5. **UX final**
   - `p2pgit doctor` — diagnóstico (bootstrap acessível? portas? chaves ok?).
   - Tabela `status --network` mostrando peers conectados e registros semeados.

---

## Ordem sugerida e dependências

```
Fase 0 (correções) ──► Fase 1 (DHT real) ──► Fase 3 (deps)
        │                    │
        │                    └──► Fase 2 (torrent)
        └──► Assinatura de PR ──► Fase 4 (PRs na rede)
                     Fase 5 (transversal, contínuo)
```

- **Fase 0**: ~1-2 dias — nada de rede, só correção e comandos locais.
- **Fase 1**: ~3-5 dias — o maior risco técnico; comece pelo teste de 2 nós em loopback.
- **Fases 2-4**: 1-2 dias cada, após a Fase 1 funcionar.
- **Fase 5**: contínua.

## Definição de "programa funcional"

O sistema estará funcional de ponta a ponta quando:

1. Duas pessoas, sem servidor central, conseguirem: `init` → `commit` → `daemon` (A) e `clone <endereço>` → editar → `commit` → `create-pr` (B) → `approve-pr` (A), tudo trafegando pela DHT/gossipsub.
2. O histórico completo (cadeia de `parent_hash`) for replicável e navegável (`log`/`checkout`).
3. Aliases resolvidos pela DHT com registros mutáveis assinados (seq monotônico).
4. Binários e deps externos baixados e **validados** automaticamente.
5. Nenhum caminho no código aceitar registro de rede sem passar por `validate_record` (assinatura + sanitização + limite).
