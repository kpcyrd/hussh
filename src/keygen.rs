use crate::errors::*;
use russh::keys::{Algorithm, HashAlg, PrivateKey, ssh_key::LineEnding};
use std::io::ErrorKind;
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

pub fn keygen() -> Result<PrivateKey> {
    let privkey = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    let pubkey = privkey.public_key();

    let fp = pubkey.fingerprint(HashAlg::Sha256);
    info!("Generated ssh key: {fp}");

    Ok(privkey)
}

/*
pub fn keygen_str() -> Result<Zeroizing<String>> {
    let privkey = keygen()?;
    let privkey = privkey.to_openssh(LineEnding::LF)?;
    Ok(privkey)
}
*/

fn privkey_str(privkey: &PrivateKey) -> Result<Zeroizing<String>> {
    let privkey = privkey.to_openssh(LineEnding::LF)?;
    Ok(privkey)
}

pub async fn init_from_path(path: &Path) -> Result<PrivateKey> {
    debug!("Loading ssh private key from: {path:?}");
    match fs::read_to_string(path).await {
        Ok(buf) => {
            let key = PrivateKey::from_openssh(buf)?;
            let fp = key.public_key().fingerprint(HashAlg::Sha256);
            info!("Loaded ssh key: {fp}");
            Ok(key)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            debug!("No existing ssh key, generating one");
            let key = keygen()?;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .await
                .with_context(|| format!("Failed to create ssh private key file: {path:?}"))?;
            file.write_all(privkey_str(&key)?.as_bytes())
                .await
                .context("Failed to write ssh private key file")?;
            Ok(key)
        }
        Err(err) => Err(err).with_context(|| format!("Failed to load ssh private key: {path:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {
        keygen().unwrap();
    }
}
