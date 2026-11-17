use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum ContentStatus {
    CleanText,
    BinaryDetected(String),
    Base64PayloadDetected(String),
}

/// Analisa bytes antes de aceitar no commit ou ao baixar de um peer.
pub fn inspect_file_content(path: &Path, content: &[u8]) -> ContentStatus {
    // 1. Detecção de Null Bytes (indicador clássico de arquivo binário).
    if content.contains(&0x00) {
        return ContentStatus::BinaryDetected(format!("Byte nulo (0x00) detectado em {:?}", path));
    }

    // 2. Validação estrita UTF-8 (código puro deve ser texto válido).
    let text = match std::str::from_utf8(content) {
        Ok(t) => t,
        Err(_) => {
            return ContentStatus::BinaryDetected(format!(
                "Codificação não-UTF8 detectada em {:?}",
                path
            ));
        }
    };

    // 3. Proporção de caracteres de controle não-imprimíveis.
    let control_chars = text
        .chars()
        .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
        .count();

    if !text.is_empty() && (control_chars as f64 / text.len() as f64) > 0.02 {
        return ContentStatus::BinaryDetected(format!(
            "Alta densidade de caracteres de controle em {:?}",
            path
        ));
    }

    // 4. Heurística Anti-Base64 (detecta blocos longos contínuos sem espaços).
    if detect_embedded_base64(text) {
        return ContentStatus::Base64PayloadDetected(format!(
            "Possível payload Base64 embutido detectado em {:?}",
            path
        ));
    }

    ContentStatus::CleanText
}

fn detect_embedded_base64(text: &str) -> bool {
    for line in text.lines() {
        let trimmed = line.trim();

        // Ignora linhas curtas (variáveis normais ou hashes curtos).
        if trimmed.len() < 120 {
            continue;
        }

        // Remove prefixos comuns de atribuição (ex: `const img = "..."`).
        let candidate = trimmed
            .split(&['"', '\'', '='][..])
            .max_by_key(|s| s.len())
            .unwrap_or("");

        if candidate.len() >= 120 && !candidate.contains(' ') {
            let is_b64_charset = candidate.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == '+'
                    || c == '/'
                    || c == '='
                    || c == '-'
                    || c == '_'
            });

            // Verifica entropia básica (Base64 real mistura maiúsculas, minúsculas e números).
            let has_upper = candidate.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = candidate.chars().any(|c| c.is_ascii_lowercase());
            let has_digit = candidate.chars().any(|c| c.is_ascii_digit());

            if is_b64_charset && has_upper && has_lower && has_digit {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn clean_source_is_accepted() {
        let src = "fn main() {\n    println!(\"olá\");\n}\n";
        assert_eq!(
            inspect_file_content(Path::new("main.rs"), src.as_bytes()),
            ContentStatus::CleanText
        );
    }

    #[test]
    fn null_byte_is_binary() {
        let data = [b'a', 0x00, b'b'];
        assert!(matches!(
            inspect_file_content(Path::new("x"), &data),
            ContentStatus::BinaryDetected(_)
        ));
    }

    #[test]
    fn long_base64_is_detected() {
        // Base64 sem padding: bloco contínuo de 210 chars com maiúsculas,
        // minúsculas e dígitos (o padding '=' quebraria o bloco em pedaços).
        let payload = "Ab3".repeat(70);
        let line = format!("const img = \"{}\";", payload);
        assert!(matches!(
            inspect_file_content(Path::new("x.js"), line.as_bytes()),
            ContentStatus::Base64PayloadDetected(_)
        ));
    }
}
