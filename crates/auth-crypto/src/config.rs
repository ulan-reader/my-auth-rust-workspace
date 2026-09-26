use secrecy::SecretString;
use serde::Deserialize;

/// Параметры Argon2id. Дефолты — минимум по рекомендациям OWASP на 2024 год
/// (19 MiB памяти, 2 итерации, 1 поток параллелизма).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Argon2Config {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// HMAC-секрет. Раздельные ключи для access и на будущее — под ротацию.
    pub secret: SecretString,
    pub issuer: String,
    pub audience: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    #[serde(default)]
    pub argon2: Argon2Config,
    pub jwt: JwtConfig,
}
