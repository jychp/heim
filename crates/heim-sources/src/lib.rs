//! Secret sources for Heim.
//!
//! This crate resolves already-configured secret references into typed secret
//! material. It does not call providers or inject credentials into child
//! processes.

use std::fmt;
use std::path::Path;

use heim_config::{LocalAuthFile, LocalAuthRef, LocalAuthSecret, ProviderConfig};

/// Expected secret type for a local auth reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    GithubAppPrivateKey,
    GithubPat,
    SlackBotToken,
    SlackAppToken,
}

impl fmt::Display for SecretKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubAppPrivateKey => formatter.write_str("github_app_private_key"),
            Self::GithubPat => formatter.write_str("github_pat"),
            Self::SlackBotToken => formatter.write_str("slack_bot_token"),
            Self::SlackAppToken => formatter.write_str("slack_app_token"),
        }
    }
}

/// Secret material resolved from a source.
#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedSecret {
    GithubAppPrivateKey { pem: String },
    GithubPat { token: String },
    SlackBotToken { token: String },
    SlackAppToken { token: String },
}

impl ResolvedSecret {
    pub fn kind(&self) -> SecretKind {
        match self {
            Self::GithubAppPrivateKey { .. } => SecretKind::GithubAppPrivateKey,
            Self::GithubPat { .. } => SecretKind::GithubPat,
            Self::SlackBotToken { .. } => SecretKind::SlackBotToken,
            Self::SlackAppToken { .. } => SecretKind::SlackAppToken,
        }
    }

    pub fn slack_bot_token(token: impl Into<String>) -> Self {
        Self::SlackBotToken {
            token: token.into(),
        }
    }

    pub fn slack_app_token(token: impl Into<String>) -> Self {
        Self::SlackAppToken {
            token: token.into(),
        }
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubAppPrivateKey { .. } => formatter
                .debug_struct("GithubAppPrivateKey")
                .field("pem", &"<redacted>")
                .finish(),
            Self::GithubPat { .. } => formatter
                .debug_struct("GithubPat")
                .field("token", &"<redacted>")
                .finish(),
            Self::SlackBotToken { .. } => formatter
                .debug_struct("SlackBotToken")
                .field("token", &"<redacted>")
                .finish(),
            Self::SlackAppToken { .. } => formatter
                .debug_struct("SlackAppToken")
                .field("token", &"<redacted>")
                .finish(),
        }
    }
}

/// Local secrets required by one configured provider.
#[derive(Clone, PartialEq, Eq)]
pub enum ProviderLocalSecrets {
    AwsSts,
    GithubApp { private_key: ResolvedSecret },
    GithubPat { token: ResolvedSecret },
}

impl fmt::Debug for ProviderLocalSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwsSts => formatter.debug_struct("AwsSts").finish(),
            Self::GithubApp { private_key } => formatter
                .debug_struct("GithubApp")
                .field("private_key", private_key)
                .finish(),
            Self::GithubPat { token } => formatter
                .debug_struct("GithubPat")
                .field("token", token)
                .finish(),
        }
    }
}

/// Common behavior for secret sources.
pub trait SecretSource {
    fn resolve(
        &self,
        auth_ref: &LocalAuthRef,
        expected: SecretKind,
    ) -> Result<ResolvedSecret, SecretSourceError>;

    fn resolve_provider(
        &self,
        provider: &ProviderConfig,
    ) -> Result<ProviderLocalSecrets, SecretSourceError> {
        match provider {
            ProviderConfig::AwsSts(_) => Ok(ProviderLocalSecrets::AwsSts),
            ProviderConfig::GithubApp(provider) => Ok(ProviderLocalSecrets::GithubApp {
                private_key: self
                    .resolve(&provider.private_key, SecretKind::GithubAppPrivateKey)?,
            }),
            ProviderConfig::GithubPat(provider) => Ok(ProviderLocalSecrets::GithubPat {
                token: self.resolve(&provider.token, SecretKind::GithubPat)?,
            }),
        }
    }
}

/// Secret source backed by Heim's unsafe local `.auth.json` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafeLocalAuthSource {
    auth: LocalAuthFile,
}

impl UnsafeLocalAuthSource {
    pub fn load_default() -> Result<Self, SecretSourceError> {
        let auth = heim_config::load_default_auth_file().map_err(SecretSourceError::LoadAuth)?;
        Ok(Self::new(auth))
    }

    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, SecretSourceError> {
        let auth = heim_config::load_auth_file(path).map_err(SecretSourceError::LoadAuth)?;
        Ok(Self::new(auth))
    }

    pub fn new(auth: LocalAuthFile) -> Self {
        Self { auth }
    }
}

impl SecretSource for UnsafeLocalAuthSource {
    fn resolve(
        &self,
        auth_ref: &LocalAuthRef,
        expected: SecretKind,
    ) -> Result<ResolvedSecret, SecretSourceError> {
        let secret =
            self.auth
                .get(auth_ref.as_str())
                .ok_or_else(|| SecretSourceError::MissingSecret {
                    auth_ref: auth_ref.to_string(),
                })?;
        let resolved = match secret {
            LocalAuthSecret::GithubAppPrivateKey { pem } => {
                ResolvedSecret::GithubAppPrivateKey { pem: pem.clone() }
            }
            LocalAuthSecret::GithubPat { token } => ResolvedSecret::GithubPat {
                token: token.clone(),
            },
            LocalAuthSecret::SlackBotToken { token } => ResolvedSecret::SlackBotToken {
                token: token.clone(),
            },
            LocalAuthSecret::SlackAppToken { token } => ResolvedSecret::SlackAppToken {
                token: token.clone(),
            },
        };

        if resolved.kind() != expected {
            return Err(SecretSourceError::SecretKindMismatch {
                auth_ref: auth_ref.to_string(),
                expected,
                actual: resolved.kind(),
            });
        }

        Ok(resolved)
    }
}

/// Error returned while loading or resolving secrets from a source.
#[derive(Debug)]
pub enum SecretSourceError {
    LoadAuth(heim_config::ConfigError),
    MissingSecret {
        auth_ref: String,
    },
    SecretKindMismatch {
        auth_ref: String,
        expected: SecretKind,
        actual: SecretKind,
    },
}

impl fmt::Display for SecretSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadAuth(source) => {
                write!(formatter, "failed to load unsafe local auth: {source}")
            }
            Self::MissingSecret { auth_ref } => {
                write!(
                    formatter,
                    "unsafe local auth entry {auth_ref} was not found"
                )
            }
            Self::SecretKindMismatch {
                auth_ref,
                expected,
                actual,
            } => write!(
                formatter,
                "unsafe local auth entry {auth_ref} has type {actual}, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for SecretSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LoadAuth(source) => Some(source),
            Self::MissingSecret { .. } | Self::SecretKindMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use heim_config::{LocalAuthRef, parse_auth_json_str};

    use super::{
        ProviderLocalSecrets, ResolvedSecret, SecretKind, SecretSource, UnsafeLocalAuthSource,
    };

    #[test]
    fn resolves_github_pat_from_unsafe_local_auth() {
        let source = source_from_json(
            r#"{
                "github_personal_pat": {
                    "type": "github_pat",
                    "token": "ghp_secret"
                }
            }"#,
        );
        let auth_ref = LocalAuthRef::new("github_personal_pat").expect("valid auth ref");

        let secret = source
            .resolve(&auth_ref, SecretKind::GithubPat)
            .expect("resolved secret");

        assert_eq!(
            secret,
            ResolvedSecret::GithubPat {
                token: "ghp_secret".to_owned()
            }
        );
    }

    #[test]
    fn resolves_github_app_private_key_from_unsafe_local_auth() {
        let source = source_from_json(
            r#"{
                "github_drymn_app_private_key": {
                    "type": "github_app_private_key",
                    "pem": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
                }
            }"#,
        );
        let auth_ref = LocalAuthRef::new("github_drymn_app_private_key").expect("valid auth ref");

        let secret = source
            .resolve(&auth_ref, SecretKind::GithubAppPrivateKey)
            .expect("resolved secret");

        assert_eq!(secret.kind(), SecretKind::GithubAppPrivateKey);
    }

    #[test]
    fn resolves_slack_bot_token_from_unsafe_local_auth() {
        let source = source_from_json(
            r#"{
                "slack_bot_token": {
                    "type": "slack_bot_token",
                    "token": "xoxb-secret"
                }
            }"#,
        );
        let auth_ref = LocalAuthRef::new("slack_bot_token").expect("valid auth ref");

        let secret = source
            .resolve(&auth_ref, SecretKind::SlackBotToken)
            .expect("resolved secret");

        assert_eq!(secret.kind(), SecretKind::SlackBotToken);
        assert!(!format!("{secret:?}").contains("xoxb-secret"));
    }

    #[test]
    fn resolves_slack_app_token_from_unsafe_local_auth() {
        let source = source_from_json(
            r#"{
                "slack_app_token": {
                    "type": "slack_app_token",
                    "token": "xapp-secret"
                }
            }"#,
        );
        let auth_ref = LocalAuthRef::new("slack_app_token").expect("valid auth ref");

        let secret = source
            .resolve(&auth_ref, SecretKind::SlackAppToken)
            .expect("resolved secret");

        assert_eq!(secret.kind(), SecretKind::SlackAppToken);
        assert!(!format!("{secret:?}").contains("xapp-secret"));
    }

    #[test]
    fn rejects_slack_secret_when_github_pat_expected() {
        let source = source_from_json(
            r#"{
                "slack_bot_token": {
                    "type": "slack_bot_token",
                    "token": "xoxb-secret"
                }
            }"#,
        );
        let auth_ref = LocalAuthRef::new("slack_bot_token").expect("valid auth ref");

        let error = source
            .resolve(&auth_ref, SecretKind::GithubPat)
            .expect_err("wrong secret kind");

        assert!(error.to_string().contains("expected github_pat"));
        assert!(!error.to_string().contains("xoxb-secret"));
    }

    #[test]
    fn rejects_missing_auth_ref() {
        let source = source_from_json("{}");
        let auth_ref = LocalAuthRef::new("missing").expect("valid auth ref");

        let error = source
            .resolve(&auth_ref, SecretKind::GithubPat)
            .expect_err("missing secret");

        assert_eq!(
            error.to_string(),
            "unsafe local auth entry missing was not found"
        );
    }

    #[test]
    fn rejects_wrong_secret_kind_without_printing_secret_value() {
        let source = source_from_json(
            r#"{
                "github_personal_pat": {
                    "type": "github_pat",
                    "token": "ghp_secret"
                }
            }"#,
        );
        let auth_ref = LocalAuthRef::new("github_personal_pat").expect("valid auth ref");

        let error = source
            .resolve(&auth_ref, SecretKind::GithubAppPrivateKey)
            .expect_err("wrong secret kind");

        assert_eq!(
            error.to_string(),
            "unsafe local auth entry github_personal_pat has type github_pat, expected github_app_private_key"
        );
        assert!(!error.to_string().contains("ghp_secret"));
    }

    #[test]
    fn debug_output_redacts_secret_values() {
        let secret = ResolvedSecret::GithubPat {
            token: "ghp_secret".to_owned(),
        };

        let debug = format!("{secret:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("ghp_secret"));
    }

    #[test]
    fn resolves_provider_local_secrets_for_github_app() {
        let source = source_from_json(
            r#"{
                "github_drymn_app_private_key": {
                    "type": "github_app_private_key",
                    "pem": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
                }
            }"#,
        );
        let config = heim_config::parse_config_str(
            r#"
            [providers.github_drymn]
            type = "github_app"
            app_id = 123456
            installation_id = 987654
            private_key = { auth = "github_drymn_app_private_key" }
            "#,
        )
        .expect("valid config");
        let provider = config.provider("github_drymn").expect("provider");

        let secrets = source
            .resolve_provider(provider)
            .expect("resolved provider secrets");

        assert!(matches!(
            secrets,
            ProviderLocalSecrets::GithubApp {
                private_key: ResolvedSecret::GithubAppPrivateKey { .. }
            }
        ));
    }

    #[test]
    fn resolves_provider_local_secrets_for_github_pat() {
        let source = source_from_json(
            r#"{
                "github_personal_pat": {
                    "type": "github_pat",
                    "token": "ghp_secret"
                }
            }"#,
        );
        let config = heim_config::parse_config_str(
            r#"
            [providers.github_personal]
            type = "github_pat"
            token = { auth = "github_personal_pat" }
            "#,
        )
        .expect("valid config");
        let provider = config.provider("github_personal").expect("provider");

        let secrets = source
            .resolve_provider(provider)
            .expect("resolved provider secrets");

        assert_eq!(
            secrets,
            ProviderLocalSecrets::GithubPat {
                token: ResolvedSecret::GithubPat {
                    token: "ghp_secret".to_owned()
                }
            }
        );
    }

    #[test]
    fn aws_sts_provider_does_not_require_local_secrets() {
        let source = source_from_json("{}");
        let config = heim_config::parse_config_str(
            r#"
            [providers.aws_prod]
            type = "aws_sts"
            role_arn = "arn:aws:iam::123456789012:role/ProdReadonly"
            "#,
        )
        .expect("valid config");
        let provider = config.provider("aws_prod").expect("provider");

        let secrets = source
            .resolve_provider(provider)
            .expect("resolved provider secrets");

        assert_eq!(secrets, ProviderLocalSecrets::AwsSts);
    }

    fn source_from_json(json: &str) -> UnsafeLocalAuthSource {
        UnsafeLocalAuthSource::new(parse_auth_json_str(json).expect("valid auth file"))
    }
}
