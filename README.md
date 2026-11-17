# p2pgit — Git descentralizado sobre Torrent/DHT em Rust

MVP de um sistema de controle de versão P2P que combina:

- **Git**: DAG de commits (cada commit aponta para o `parent_hash`).
- **BitTorrent/DHT**: distribuição sem servidor central (Kademlia via libp2p).
- **Tor**: endereço derivado da chave pública (Base32 + checksum + versão, sufixo `.p2pgit`).
- **Bitcoin**: cada commit é assinado com Ed25519 pela chave privada do dono.

## Requisitos

- Rust 1.75+ (testado com 1.95)
- O transporte DHT real é opcional (feature `network`)

## Build

```bash
cargo build                     # MVP local (rápido)
cargo build --features network  # inclui nó Kademlia/Gossipsub/Identify real
cargo test                      # 24 testes unitários
cargo test --features network   # 26 testes (inclui 2 nós em loopback)
```

O binário fica em `target/debug/git_torrent`.

## Comandos

| Comando | Descrição |
|---|---|
| `p2pgit init --alias <nome>` | Cria o repositório, gera chave pública/privada, endereço `.p2pgit`, os manifests `.binary` e `.p2pdeps`, e registra o alias. |
| `p2pgit register-alias <alias> [--namespace open.p2pgit] [--bootstrap <addr>...]` | Cria e assina um registro de alias (BEP-44 style); com a feature `network`, publica na DHT. |
| `p2pgit commit -m "msg" [--force-text]` | Empacota **recursivamente** os arquivos de texto do diretório atual (respeita `.p2pgitignore`) em um commit assinado (limite rígido de 512 KB), com `parent_hash` = HEAD. |
| `p2pgit log` | Lista o histórico seguindo a cadeia `parent_hash` (HEAD → raiz). |
| `p2pgit show [hash]` | Mostra detalhes e arquivos de um commit (padrão: HEAD). |
| `p2pgit checkout <hash>` | Restaura o diretório de trabalho em um commit antigo (HEAD detached), com todas as validações de segurança. |
| `p2pgit clone <alvo> [--out clone] [--bootstrap <addr>...]` | Valida e clona um commit (arquivo `.json`, endereço `.p2pgit` ou alias). Com a feature `network`, busca o HEAD **e o histórico** na DHT antes de recorrer aos arquivos locais. Aplica todos os bloqueios de segurança. |
| `p2pgit create-pr <endereço> [--out pr.json]` | Gera um Pull Request **assinado pela chave do fork** (o alvo é validado como endereço ou alias). Se recusado, o fork permanece válido. |
| `p2pgit approve-pr <pr.json>` | Verifica assinatura do PR, destinatário e autor do commit antes de re-assinar o merge com a chave privada do repositório original. |
| `p2pgit status` | Mostra endereço, chave pública, HEAD e aliases. |
| `p2pgit verify <endereço\|commit.json>` | Valida a checksum do endereço ou a assinatura do commit. |
| `p2pgit check-binary <arquivo> <md5>` | Valida o MD5 de um binário baixado contra o manifesto `.binary`. |
| `p2pgit add-binary <arquivo> [--description ...] [--torrent-infohash <40hex>]` | Registra o binário no manifesto `.binary` com MD5 **e SHA-256** calculados (o binário sai do commit de código puro). |
| `p2pgit fetch-binaries [--out-dir binaries]` | Baixa via magnet (`aria2c`) os binários com `torrent_infohash` e valida MD5/SHA-256; grava o resultado em `.p2pgit/binaries.lock`. |
| `p2pgit daemon [--bootstrap <peer/multiaddr>...]` | **(feature `network`)** Inicia o nó DHT, semeia o repositório local (HEAD + histórico + aliases) e anuncia novos HEADs via gossipsub. Bootstrap padrão: `~/.p2pgit/bootstrap.txt`. |

Flags globais de segurança (aplicam-se a `clone`, `checkout`, `approve-pr` e `verify`):

| Flag | Comportamento |
|---|---|
| *(padrão em TTY)* | Alerta e pergunta `[s/N]` ao detectar conteúdo suspeito. |
| `--strict` | Rejeita qualquer conteúdo suspeito, sem perguntar. |
| `--yes` | Alerta e prossegue (modo não-interativo). |

Em TTY não-interativo (scripts/daemon) o padrão é negar tudo automaticamente.

## Fluxo básico

```bash
git_torrent init --alias meu-projeto
echo 'fn main() { println!("olá"); }' > main.rs
git_torrent commit -m "commit inicial"
git_torrent status
git_torrent verify .p2pgit/commit_<hash>.json
git_torrent clone .p2pgit/commit_<hash>.json --out meu-clone
```

## `.p2pgitignore` — exclusão da varredura

O `commit` varre o diretório recursivamente. Por padrão ele ignora `.p2pgit/`,
`.git/`, `target/`, `node_modules/`, diretórios e arquivos ocultos (exceto o
próprio `.p2pgitignore`). Padrões adicionais podem ser declarados:

```text
# comentário
rascunho.txt     # nome de arquivo em qualquer profundidade
build/           # diretório inteiro
docs/*.md        # glob com caminho relativo
```

## Segurança (bloqueios do cliente)

Ao fazer `clone`, `checkout` ou `approve-pr`, o cliente executa `client_download_guard`:

1. **Assinatura Ed25519** — rejeita commits adulterados na rede.
2. **Limite de 512 KB** — rejeita commits maiores que o permitido.
3. **Anti-binário** — detecta bytes nulos, UTF-8 inválido e alta densidade de caracteres de controle.
4. **Anti-Base64** — detecta payloads longos contínuos (≥120 chars) ofuscados em código. Nesses casos, pede confirmação explícita ao usuário com alerta de risco.
5. **Avisos** — lista binários externos do `.binary` e repositórios linkados do `.p2pdeps`.

## `.binary` — binários fora do commit

O código puro nunca contém binários. Eles são referenciados por **MD5** (legado) e **SHA-256** (preferido), e opcionalmente por `infohash` de torrent:

```json
[
  {
    "file_path": "assets/textura.png",
    "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256_hash": "d32b202dbebe7daadc26783c1e279fc535b2e83beceb22993703f9a67012b7d4",
    "torrent_infohash": "8a9b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    "description": "Textura principal do jogo"
  }
]
```

Registre e baixe com:

```bash
git_torrent add-binary assets/textura.png --description "Textura principal" \
  --torrent-infohash 8a9b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
git_torrent fetch-binaries          # usa magnet + aria2c; valida MD5/SHA-256
git_torrent check-binary assets/textura.png d41d8cd98f00b204e9800998ecf8427e
```

No clone, binários ausentes viram aviso com a instrução `fetch-binaries`;
binários presentes são **validados na hora** (divergência de hash bloqueia o
clone). O resultado do download fica em `.p2pgit/binaries.lock`.

## `.p2pdeps` — repositórios essenciais linkados

Evita inflar o repositório com dependências. Cada entrada aponta para outro endereço `.p2pgit`/alias em um commit fixado:

```json
[
  {
    "name": "crypto-utils",
    "target_address_or_alias": "crypto-lib.open.p2pgit",
    "pinned_commit_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "mount_path": "deps/crypto"
  }
]
```

## Estrutura do código

```
src/
├── identity.rs   # Ed25519, endereço estilo Tor, assinatura/verificação
├── sanitizer.rs  # filtro anti-binário e anti-Base64
├── repo.rs       # Commit (512 KB), .binary, .p2pdeps, PullRequest, MD5
├── network.rs    # AliasRecord, AliasRegistry local, client_download_guard
├── p2p.rs        # transporte libp2p (Kademlia + Gossipsub) — feature "network"
└── main.rs       # CLI (clap) e fluxo completo
```

## Estado do MVP / próximos passos

- A resolução de aliases e commits no MVP local usa um registro em `.p2pgit/aliases.json` e arquivos de commit locais (indexados pelo hash SHA-256 completo).
- **Rede real (feature `network`) — Fase 1 concluída:** o `daemon` publica o repositório local na DHT Kademlia (`kad::Record`), o `clone` busca o HEAD e o histórico completo (`endereço` + `endereço#hash`) com validação em `validate_commit_record`, e o `register-alias` publica um registro mutável assinado (BEP-44, com `seq`). Aliases também são resolvidos na DHT.
- O transporte usa libp2p com `identify`: sem ele o kad fica em modo *Client* e ignora os requests dos pares (veja `docs/GUIA-IMPLEMENTACAO.md`, "Armadilhas reais encontradas na Fase 1").
- Bootstrap padrão lido de `~/.p2pgit/bootstrap.txt` (um multiaddr por linha) ou da flag `--bootstrap`.
- PRs são assinados pela chave do fork (`PullRequest::create`) e `approve-pr` valida assinatura, destinatário e correspondência autor-do-PR ↔ autor-do-commit antes de aceitar.
- O hash do commit é canônico (JSON serializado com vetores ordenados, sem assinatura) e cobre todos os campos, inclusive `mount_path` e `torrent_infohash`.
- A busca de binários por `infohash` em trackers/DHT BitTorrent e a verificação automática pós-download ainda são responsabilidade do cliente/usuário (use `check-binary`).
- O merge de PRs re-assina a árvore proposta como um novo commit filho do commit do fork, preservando o DAG.
- **Binários via BitTorrent — Fase 2 concluída:** `add-binary` grava MD5 + SHA-256 + infohash no `.binary`; `fetch-binaries` baixa via magnet (`aria2c`) e valida a integridade; o guard do clone verifica `binaries/<file_path>` (ausente → aviso, divergente → bloqueio).
- Próximos passos planejados: ver `docs/GUIA-IMPLEMENTACAO.md` (Fase 3 — dependências `.p2pdeps`).

### Testando a rede localmente (2 daemons)

```bash
cargo build --features network

# Máquina/terminal A: publica o repositório atual
cd /caminho/do/repo-a && git_torrent daemon

# Terminal B: busca (o daemon de A precisa estar no ar)
git_torrent clone <endereço>.p2pgit --out repo-b \
  --bootstrap /ip4/127.0.0.1/tcp/<porta>/p2p/<peer_id-de-A>
```

Os comandos `clone` e `register-alias` criam um nó **efêmero** (sobe, faz a
operação, desce) — não exigem daemon rodando no lado do cliente.
