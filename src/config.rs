//! Limites do protocolo, num único lugar para o CLI, o sanitizer e a rede.

/// Tamanho máximo do conteúdo textual de um commit (soma dos arquivos).
pub const MAX_COMMIT_SIZE_BYTES: usize = 512 * 1024;

/// Trecho contínuo sem espaço, a partir deste tamanho, vira candidato a Base64.
pub const BASE64_MIN_LEN: usize = 120;

/// Fração máxima de caracteres de controle (exceto `\n`, `\r` e `\t`).
pub const CONTROL_CHAR_THRESHOLD: f64 = 0.02;

/// Janela anti-replay dos anúncios de HEAD no gossipsub.
pub const ANNOUNCE_MAX_AGE_SECS: u64 = 24 * 3600;
