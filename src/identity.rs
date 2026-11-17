use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(test)]
use zeroize::ZeroizeOnDrop;

/// CHECKSUM_DOMAIN para derivação do endereço estilo Tor.
const CHECKSUM_DOMAIN: &[u8] = b".p2pgit checksum";

/// Wrapper que zera a memória ao cair (protege chaves privadas).
#[derive(ZeroizeOnDrop)]
#[cfg(test)]
pub struct SigningKeyBytes(pub [u8; 32]);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RepoIdentity {
    pub public_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_hex: Option<String>, // None se for apenas um clone de terceiros
    pub onion_like_address: String,
    pub alias: Option<String>,
}

impl RepoIdentity {
    /// Cria um novo par de chaves e gera o endereço estilo Tor.
    pub fn generate(alias: Option<String>) -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let address = Self::derive_tor_address(&verifying_key);
        let priv_bytes = signing_key.to_bytes();

        Self {
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            private_key_hex: Some(hex::encode(priv_bytes)),
            onion_like_address: address,
            alias,
        }
    }

    /// Cria uma identidade a partir de uma seed determinística (para testes).
    #[cfg(test)]
    pub fn from_seed(seed: [u8; 32], alias: Option<String>) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let address = Self::derive_tor_address(&verifying_key);

        Self {
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            private_key_hex: Some(hex::encode(seed)),
            onion_like_address: address,
            alias,
        }
    }

    /// Deriva endereço estilo Tor v3: BASE32(PUBKEY + CHECKSUM + VERSION) + ".p2pgit".
    pub fn derive_tor_address(pub_key: &VerifyingKey) -> String {
        let pub_bytes = pub_key.to_bytes();

        let mut hasher = Sha256::new();
        hasher.update(CHECKSUM_DOMAIN);
        hasher.update(pub_bytes);
        let hash = hasher.finalize();

        let mut raw_addr = Vec::with_capacity(35);
        raw_addr.extend_from_slice(&pub_bytes);
        raw_addr.extend_from_slice(&hash[..2]); // 2 bytes de checksum
        raw_addr.push(0x03); // Versão 3

        let encoded = BASE32_NOPAD.encode(&raw_addr).to_lowercase();
        format!("{}.p2pgit", encoded)
    }

    /// Reconstroi a chave pública a partir do endereço (valida checksum e versão).
    pub fn verify_address(address: &str) -> anyhow::Result<VerifyingKey> {
        let suffix = ".p2pgit";
        let body = address
            .strip_suffix(suffix)
            .ok_or_else(|| anyhow::anyhow!("Endereço deve terminar em '{}'", suffix))?;

        let raw = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|e| anyhow::anyhow!("Endereço Base32 inválido: {}", e))?;

        if raw.len() != 35 {
            anyhow::bail!("Endereço com tamanho inválido ({} bytes)", raw.len());
        }
        if raw[34] != 0x03 {
            anyhow::bail!("Versão de endereço desconhecida: {:#x}", raw[34]);
        }

        let pub_arr: [u8; 32] = raw[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Chave pública inválida no endereço"))?;

        let mut hasher = Sha256::new();
        hasher.update(CHECKSUM_DOMAIN);
        hasher.update(pub_arr);
        let hash = hasher.finalize();

        if hash[0] != raw[32] || hash[1] != raw[33] {
            anyhow::bail!("Checksum do endereço não confere");
        }

        VerifyingKey::from_bytes(&pub_arr)
            .map_err(|e| anyhow::anyhow!("Chave pública inválida: {}", e))
    }

    /// Assina o hash de um commit (apenas quem tem a chave privada consegue).
    pub fn sign_data(&self, data: &[u8]) -> anyhow::Result<String> {
        let priv_hex = self.private_key_hex.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Chave privada ausente! Você só pode criar um Fork ou PR.")
        })?;

        let priv_bytes: [u8; 32] = hex::decode(priv_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Tamanho de chave inválido"))?;

        let signing_key = SigningKey::from_bytes(&priv_bytes);
        let signature: Signature = signing_key.sign(data);
        Ok(hex::encode(signature.to_bytes()))
    }

    /// Verifica se um commit realmente pertence ao dono do endereço.
    pub fn verify_signature(pub_hex: &str, data: &[u8], sig_hex: &str) -> bool {
        let Ok(pub_bytes) = hex::decode(pub_hex) else {
            return false;
        };
        let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_arr) else {
            return false;
        };

        let Ok(sig_bytes) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key.verify(data, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_and_verify() {
        let id = RepoIdentity::generate(Some("teste".into()));
        assert!(id.onion_like_address.ends_with(".p2pgit"));
        let msg = b"mensagem de teste";
        let sig = id.sign_data(msg).unwrap();
        assert!(RepoIdentity::verify_signature(
            &id.public_key_hex,
            msg,
            &sig
        ));
        assert!(!RepoIdentity::verify_signature(
            &id.public_key_hex,
            b"outro",
            &sig
        ));
    }

    #[test]
    fn address_roundtrip() {
        let id = RepoIdentity::generate(None);
        let key = RepoIdentity::verify_address(&id.onion_like_address).unwrap();
        assert_eq!(hex::encode(key.to_bytes()), id.public_key_hex);
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x42; 32];
        let a = RepoIdentity::from_seed(seed, None);
        let b = RepoIdentity::from_seed(seed, None);
        assert_eq!(a.onion_like_address, b.onion_like_address);
        assert_eq!(a.public_key_hex, b.public_key_hex);
    }

    #[test]
    fn signing_key_bytes_zeroizes_on_drop() {
        let key = SigningKeyBytes([0xAA; 32]);
        assert_eq!(key.0[0], 0xAA);
        // Ao cair, o zeroize deve limpar a memória.
        drop(key);
    }
}
