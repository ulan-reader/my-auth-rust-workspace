use secrecy::SecretString;
use serde::Deserialize;

fn default_max_concurrent() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// Параметры Argon2id. Дефолты — минимум по рекомендациям OWASP на 2024 год
/// (19 MiB памяти, 2 итерации, 1 поток параллелизма).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Argon2Config {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// Сколько хешей считается одновременно; остальные ждут в очереди.
    /// Пик памяти ≈ max_concurrent × m_cost_kib.
    pub max_concurrent: usize,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            max_concurrent: default_max_concurrent(),
        }
    }
}

/// Публичный ключ, который ещё принимается при проверке, но не используется
/// для подписи — нужен на время ротации: старый `kid` выдал токены с TTL
/// до `access_ttl`, их нужно продолжать принимать, пока они не протухнут,
/// уже подписывая новые текущим ключом.
#[derive(Debug, Clone, Deserialize)]
pub struct JwtVerificationKey {
    pub kid: String,
    /// base64url (без паддинга) сырых 32 байт публичного ключа Ed25519.
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// base64url (без паддинга) 32-байтного seed приватного ключа Ed25519.
    /// Сгенерировать: `cargo run -p auth-server -- jwt-keygen`.
    pub signing_key: SecretString,
    /// Идентификатор текущего ключа подписи — попадает в заголовок `kid`
    /// каждого выданного токена и в JWKS.
    pub kid: String,
    pub issuer: String,
    pub audience: String,
    /// Ключи предыдущих поколений — всё ещё принимаются при проверке
    /// (см. `JwtVerificationKey`), но ими никогда не подписывают.
    #[serde(default)]
    pub extra_verification_keys: Vec<JwtVerificationKey>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    #[serde(default)]
    pub argon2: Argon2Config,
    pub jwt: JwtConfig,
}
