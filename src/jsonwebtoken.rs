use derive_builder::Builder;
pub use fred::prelude::Config as RedisConfig;
use fred::prelude::*;
pub use jsonwebtoken::Validation as JWTValidation;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// A type alias for results with the custom `Error` type.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Builder, Clone)]
pub struct IDPConfig {
    pub redis_config: RedisConfig,
    pub validation: JWTValidation,
}

/// Represents a JWT-based identity provider.
#[derive(Clone)]
pub struct IdentityProviderJWT {
    secret: SecretBox<[u8]>,
    redis: Client,
    validation: JWTValidation,
}

impl IdentityProviderJWT {
    /// Creates a new `IdentityProviderJWT` instance.
    pub async fn new<T: AsRef<[u8]>>(config: IDPConfig, secret: T) -> Result<Self> {
        let secret = SecretBox::new(Box::from(secret.as_ref()));
        let client = Client::new(config.redis_config, None, None, None);
        client.init().await?;
        Ok(Self {
            secret,
            redis: client,
            validation: config.validation,
        })
    }

    /// Rotates the secret at runtime.
    pub fn rotate_secret<T: AsRef<[u8]>>(&mut self, new_secret: T) {
        self.secret = SecretBox::new(Box::from(new_secret.as_ref()));
    }

    /// Generates a new token with the provided claims.
    pub fn generate_token<T: serde::Serialize + serde::de::DeserializeOwned>(
        &self,
        claims: token::TokenClaims<T>,
    ) -> Result<token::Token> {
        let token = token::Token::generate(claims, self.secret.expose_secret())?;
        Ok(token)
    }

    /// Validates a token and returns its claims.
    pub fn validate_token<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        token: &token::Token,
    ) -> Result<token::TokenClaims<T>> {
        let claims: token::TokenClaims<T> =
            token.to_claims(self.secret.expose_secret(), self.validation.clone())?;
        if claims.exp().is_expired() {
            return Err(Error::TokenExpired);
        }
        Ok(claims)
    }

    /// Revokes a token by storing its JTI in Redis.
    pub async fn revoke_token<T: Serialize + DeserializeOwned>(
        &self,
        key: &str,
        claims: &token::TokenClaims<T>,
    ) -> Result<()> {
        let key = self.create_key(key, claims.jti.to_string().as_str());
        let _: () = self
            .redis
            .set(
                key,
                "",
                Some(Expiration::EX(claims.exp.left_till())),
                None,
                false,
            )
            .await?;
        Ok(())
    }

    /// Checks if a token has been revoked.
    pub async fn is_token_revoked<T: Serialize + DeserializeOwned>(
        &self,
        key: &str,
        token: &token::TokenClaims<T>,
    ) -> Result<bool> {
        let key = self.create_key(key, token.jti.to_string().as_str());
        let result = self.redis.exists(key).await?;
        Ok(result)
    }

    /// Namespaced Redis key construction.
    fn create_key(&self, key: &str, token_id: &str) -> String {
        format!("idp:jwt:{}:{}", key, token_id)
    }
}

/// Custom error type for the identity provider.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Token error: {0}")]
    TokenError(#[from] token::TokenError),
    #[error("Redis error: {0}")]
    RedisError(#[from] fred::error::Error),
    #[error("Token expired")]
    TokenExpired,
}

pub mod token {
    use derive_builder::Builder;
    use jsonwebtoken;
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use thiserror::Error;
    use uuid::Uuid;

    /// Represents the claims in a JWT token.
    #[derive(Debug, Serialize, Deserialize, Clone, Builder)]
    #[builder(pattern = "owned", setter(into), build_fn(error = "TokenError"))]
    pub struct TokenClaims<T>
    where
        T: Serialize + DeserializeOwned,
    {
        #[serde(
            serialize_with = "serde_helpers::serialize_json",
            deserialize_with = "serde_helpers::deserialize_json"
        )]
        pub sub: Subject<T>, // Subject
        pub exp: TimeStamp, // Expiration time (Unix timestamp)
        pub iat: TimeStamp, // Issued at (Unix timestamp)
        pub typ: String,    // Type
        pub iss: String,    // Issuer
        pub aud: String,    // Audience
        pub jti: JWTID,     // JWT ID
    }

    impl<T> TokenClaims<T>
    where
        T: Serialize + DeserializeOwned,
    {
        /// Returns the subject of the token.
        pub fn sub(&self) -> &Subject<T> {
            &self.sub
        }
        /// Returns the expiration time of the token.
        pub fn exp(&self) -> TimeStamp {
            self.exp
        }
        /// Returns the issued-at time of the token.
        pub fn iat(&self) -> TimeStamp {
            self.iat
        }
        /// Returns the issuer of the token.
        pub fn iss(&self) -> &str {
            &self.iss
        }
        /// Returns the type of the token.
        pub fn typ(&self) -> &str {
            &self.typ
        }
        /// Returns the audience of the token.
        pub fn aud(&self) -> &str {
            &self.aud
        }
        /// Returns the JWT ID of the token.
        pub fn jti(&self) -> &JWTID {
            &self.jti
        }
    }

    /// Represents a JWT token.
    #[derive(Clone, Debug)]
    pub struct Token {
        token: String,
    }

    impl Token {
        /// Creates a new `Token` instance from a raw token string.
        pub fn with_token(token: &str) -> Self {
            Self {
                token: token.to_string(),
            }
        }

        /// Generates a new JWT token from the given claims and secret.
        pub fn generate<T>(claims: TokenClaims<T>, secret: &[u8]) -> Result<Self, TokenError>
        where
            T: Serialize + for<'de> Deserialize<'de>,
        {
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(secret),
            )?;
            Ok(Self { token })
        }

        /// Decodes the token into `TokenClaims` using the provided secret and validation.
        pub fn to_claims<T: for<'de> Deserialize<'de> + Serialize>(
            &self,
            secret: &[u8],
            validation: jsonwebtoken::Validation,
        ) -> Result<TokenClaims<T>, TokenError> {
            let claims = jsonwebtoken::decode::<TokenClaims<T>>(
                &self.token,
                &jsonwebtoken::DecodingKey::from_secret(secret),
                &validation,
            )?
            .claims;
            Ok(claims)
        }

        /// Returns the raw token string.
        pub fn to_string(&self) -> String {
            self.token.clone()
        }

        /// Secure constant-time comparison.
        pub fn secure_eq(&self, other: &Self) -> bool {
            use subtle::ConstantTimeEq;

            self.token.as_bytes().ct_eq(other.token.as_bytes()).into()
        }
    }

    impl std::fmt::Display for Token {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.token)
        }
    }

    impl std::str::FromStr for Token {
        type Err = TokenError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(Self::with_token(s))
        }
    }

    /// Generates a unique JWT ID (JTI).
    pub fn generate_jti() -> String {
        Uuid::new_v4().to_string()
    }

    /// Represents the subject of a JWT token.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Subject<T>(pub T);

    impl<T> Subject<T> {
        pub fn new(sub: T) -> Self {
            Self(sub)
        }
        pub fn value(&self) -> &T {
            &self.0
        }
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    impl<T> std::ops::Deref for Subject<T> {
        type Target = T;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<T> std::ops::DerefMut for Subject<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    /// Represents a timestamp in a JWT token.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct TimeStamp(i64);

    impl TimeStamp {
        /// Returns the current timestamp.
        pub fn now() -> i64 {
            chrono::Utc::now().timestamp()
        }
        pub fn from_now(seconds: i64) -> Self {
            TimeStamp(Self::now() + seconds)
        }
        /// Creates a `TimeStamp` from a raw Unix timestamp.
        pub fn from_i64(timestamp: i64) -> Self {
            TimeStamp(timestamp)
        }
        /// Checks if the timestamp is expired.
        pub fn is_expired(&self) -> bool {
            self.0 < TimeStamp::now()
        }
        pub fn left_till(&self) -> i64 {
            self.0 - TimeStamp::now()
        }
        pub fn extend(&mut self, seconds: i64) {
            self.0 += seconds;
        }
        pub fn to_i64(&self) -> i64 {
            self.0
        }
    }

    impl From<i64> for TimeStamp {
        fn from(value: i64) -> Self {
            TimeStamp(value)
        }
    }

    impl<T> From<T> for Subject<T>
    where
        T: Serialize + DeserializeOwned,
    {
        fn from(value: T) -> Self {
            Subject::new(value)
        }
    }

    /// Custom error type for token-related operations.
    #[derive(Error, Debug)]
    pub enum TokenError {
        #[error("JWT error: {0}")]
        JwtError(#[from] jsonwebtoken::errors::Error),
        #[error("Invalid token format")]
        InvalidTokenFormat,
    }

    impl From<derive_builder::UninitializedFieldError> for TokenError {
        fn from(_: derive_builder::UninitializedFieldError) -> Self {
            TokenError::InvalidTokenFormat
        }
    }

    /// Represents a unique JWT ID (JTI).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct JWTID(String);

    impl JWTID {
        /// Creates a new unique JWT ID.
        pub fn new() -> Self {
            JWTID(uuid::Uuid::new_v4().to_string())
        }
        /// Creates a `JWTID` from a string.
        pub fn from_string(id: &str) -> Self {
            JWTID(id.to_string())
        }
        /// Converts the `JWTID` to a string.
        pub fn to_string(&self) -> String {
            self.0.clone()
        }
    }
    impl std::fmt::Display for JWTID {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    mod serde_helpers {
        use base64::{Engine as _, engine::general_purpose};
        use rmp_serde::{from_slice, to_vec};
        use serde::Deserialize;
        use serde::{Serialize, de::DeserializeOwned};

        pub fn serialize_msgpack<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: Serialize,
            S: serde::Serializer,
        {
            let bytes = to_vec(value).map_err(serde::ser::Error::custom)?;
            let b64 = general_purpose::STANDARD.encode(bytes);
            serializer.serialize_str(&b64)
        }

        pub fn deserialize_msgpack<'de, T, D>(deserializer: D) -> Result<T, D::Error>
        where
            T: DeserializeOwned,
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let bytes = general_purpose::STANDARD
                .decode(&s)
                .map_err(serde::de::Error::custom)?;
            from_slice(&bytes).map_err(serde::de::Error::custom)
        }

        pub fn serialize_json<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: Serialize,
            S: serde::Serializer,
        {
            let json_str = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
            serializer.serialize_str(&json_str)
        }

        pub fn deserialize_json<'de, T, D>(deserializer: D) -> Result<T, D::Error>
        where
            T: DeserializeOwned,
            D: serde::Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            serde_json::from_str(&s).map_err(serde::de::Error::custom)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use serde::{Deserialize, Serialize};
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        struct CustomClaims {
            username: String,
            admin: bool,
        }

        #[test]
        fn test_token_encode_decode_custom_claims() {
            let claims = TokenClaimsBuilder::<CustomClaims>::default()
                .sub(Subject::new(CustomClaims {
                    username: "alice".to_string(),
                    admin: true,
                }))
                .exp(TimeStamp::from_now(3600))
                .iat(TimeStamp::from_now(0))
                .typ("access".to_string())
                .iss("issuer".to_string())
                .aud("audience".to_string())
                .jti(JWTID::new())
                .build()
                .unwrap();

            let secret = b"supersecretkey";
            let token = Token::generate(claims.clone(), secret).unwrap();

            let mut validation = jsonwebtoken::Validation::default();
            validation.set_audience(&["audience"]);
            let decoded_claims: TokenClaims<CustomClaims> =
                token.to_claims(secret, validation).unwrap();

            assert_eq!(decoded_claims.sub().value(), claims.sub().value());
            assert_eq!(decoded_claims.typ(), claims.typ());
            assert_eq!(decoded_claims.iss(), claims.iss());
            assert_eq!(decoded_claims.aud(), claims.aud());
            assert_eq!(decoded_claims.jti().to_string(), claims.jti().to_string());
        }

        #[test]
        fn test_token_encode_decode_primitive_claims() {
            let claims = TokenClaimsBuilder::<u32>::default()
                .sub(Subject::new(42u32))
                .exp(TimeStamp::from_now(3600))
                .iat(TimeStamp::from_now(0))
                .typ("number".to_string())
                .iss("issuer".to_string())
                .aud("audience".to_string())
                .jti(JWTID::new())
                .build()
                .unwrap();

            let secret = b"anothersecret";
            let token = Token::generate(claims.clone(), secret).unwrap();

            let mut validation = jsonwebtoken::Validation::default();
            validation.set_audience(&["audience"]);
            let decoded_claims: TokenClaims<u32> = token.to_claims(secret, validation).unwrap();

            assert_eq!(decoded_claims.sub().value(), claims.sub().value());
            assert_eq!(decoded_claims.typ(), claims.typ());
            assert_eq!(decoded_claims.iss(), claims.iss());
            assert_eq!(decoded_claims.aud(), claims.aud());
            assert_eq!(decoded_claims.jti().to_string(), claims.jti().to_string());
        }
    }
}
