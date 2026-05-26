//! Credential providers for Heim.
//!
//! This crate converts resolved secret material into process-scoped credential
//! carriers. It does not call AWS APIs yet.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use heim_sources::ResolvedSecret;
use serde::{Deserialize, Serialize};

/// Request context passed to a credential provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    pub grant: String,
    pub provider: String,
    pub requester: String,
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub git: Option<ProviderGitContext>,
}

impl CredentialRequest {
    pub fn new(
        grant: impl Into<String>,
        provider: impl Into<String>,
        requester: impl Into<String>,
        command: impl IntoIterator<Item = impl Into<String>>,
        cwd: PathBuf,
    ) -> Self {
        Self {
            grant: grant.into(),
            provider: provider.into(),
            requester: requester.into(),
            command: command.into_iter().map(Into::into).collect(),
            cwd,
            git: None,
        }
    }

    pub fn with_git(mut self, git: ProviderGitContext) -> Self {
        self.git = Some(git);
        self
    }
}

/// Git metadata available to providers when detected locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGitContext {
    pub remote: Option<String>,
    pub branch: Option<String>,
}

impl ProviderGitContext {
    pub fn new(remote: Option<String>, branch: Option<String>) -> Self {
        Self { remote, branch }
    }
}

/// Environment variable carrying credential material.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialEnvVar {
    name: String,
    value: String,
}

impl CredentialEnvVar {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for CredentialEnvVar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialEnvVar")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Credential material ready to inject into a child process.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedCredential {
    kind: String,
    env_vars: Vec<CredentialEnvVar>,
    temp_files: Vec<String>,
}

impl IssuedCredential {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            env_vars: Vec::new(),
            temp_files: Vec::new(),
        }
    }

    pub fn with_env_var(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push(CredentialEnvVar::new(name, value));
        self
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn env_vars(&self) -> &[CredentialEnvVar] {
        &self.env_vars
    }

    pub fn temp_files(&self) -> &[String] {
        &self.temp_files
    }

    pub fn metadata(&self) -> CredentialMetadata {
        CredentialMetadata {
            kind: self.kind.clone(),
            env_vars: self.env_vars.iter().map(|env| env.name.clone()).collect(),
            temp_files: self.temp_files.clone(),
        }
    }
}

impl fmt::Debug for IssuedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedCredential")
            .field("kind", &self.kind)
            .field("env_vars", &self.env_vars)
            .field("temp_files", &self.temp_files)
            .finish()
    }
}

/// Redacted credential metadata suitable for audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMetadata {
    pub kind: String,
    pub env_vars: Vec<String>,
    pub temp_files: Vec<String>,
}

/// Common behavior for credential providers.
pub trait CredentialProvider {
    fn issue(&self, request: &CredentialRequest) -> Result<IssuedCredential, ProviderError>;
}

/// GitHub PAT pass-through provider.
///
/// PAT support is an unsafe compatibility provider. GitHub App installation
/// tokens remain the preferred GitHub provider once implemented.
#[derive(Clone, PartialEq, Eq)]
pub struct GithubPatProvider {
    token: String,
}

impl GithubPatProvider {
    pub fn from_secret(secret: ResolvedSecret) -> Result<Self, ProviderError> {
        match secret {
            ResolvedSecret::GithubPat { token } => Ok(Self { token }),
            other => Err(ProviderError::SecretKindMismatch {
                provider: "github_pat".to_owned(),
                actual: other.kind().to_string(),
                expected: "github_pat",
            }),
        }
    }
}

impl fmt::Debug for GithubPatProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubPatProvider")
            .field("token", &"<redacted>")
            .finish()
    }
}

impl CredentialProvider for GithubPatProvider {
    fn issue(&self, _request: &CredentialRequest) -> Result<IssuedCredential, ProviderError> {
        Ok(IssuedCredential::new("github_pat")
            .with_env_var("GH_TOKEN", self.token.clone())
            .with_env_var("GITHUB_TOKEN", self.token.clone()))
    }
}

/// GitHub App installation token provider.
#[derive(Clone, PartialEq, Eq)]
pub struct GithubAppProvider<C = ReqwestGithubAppClient> {
    app_id: u64,
    installation_id: u64,
    private_key_pem: String,
    repositories: Vec<String>,
    client: C,
    jwt_override: Option<String>,
}

impl<C> GithubAppProvider<C> {
    pub fn from_secret(
        app_id: u64,
        installation_id: u64,
        repositories: Vec<String>,
        secret: ResolvedSecret,
        client: C,
    ) -> Result<Self, ProviderError> {
        match secret {
            ResolvedSecret::GithubAppPrivateKey { pem } => Ok(Self {
                app_id,
                installation_id,
                private_key_pem: pem,
                repositories,
                client,
                jwt_override: None,
            }),
            other => Err(ProviderError::SecretKindMismatch {
                provider: "github_app".to_owned(),
                actual: other.kind().to_string(),
                expected: "github_app_private_key",
            }),
        }
    }
}

impl GithubAppProvider {
    pub fn from_secret_with_default_client(
        app_id: u64,
        installation_id: u64,
        repositories: Vec<String>,
        secret: ResolvedSecret,
    ) -> Result<Self, ProviderError> {
        Self::from_secret(
            app_id,
            installation_id,
            repositories,
            secret,
            ReqwestGithubAppClient,
        )
    }
}

#[cfg(test)]
impl<C> GithubAppProvider<C> {
    fn from_secret_with_jwt_for_tests(
        app_id: u64,
        installation_id: u64,
        repositories: Vec<String>,
        secret: ResolvedSecret,
        client: C,
        jwt: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let mut provider =
            Self::from_secret(app_id, installation_id, repositories, secret, client)?;
        provider.jwt_override = Some(jwt.into());
        Ok(provider)
    }
}

impl<C> fmt::Debug for GithubAppProvider<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppProvider")
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("private_key_pem", &"<redacted>")
            .field("repositories", &self.repositories)
            .finish_non_exhaustive()
    }
}

impl<C> CredentialProvider for GithubAppProvider<C>
where
    C: GithubAppClient,
{
    fn issue(&self, _request: &CredentialRequest) -> Result<IssuedCredential, ProviderError> {
        let jwt = match &self.jwt_override {
            Some(jwt) => jwt.clone(),
            None => github_app_jwt(self.app_id, &self.private_key_pem)?,
        };
        let token = self.client.create_installation_token(
            &jwt,
            self.installation_id,
            &self.repositories,
        )?;

        Ok(IssuedCredential::new("github_app")
            .with_env_var("GH_TOKEN", token.token.clone())
            .with_env_var("GITHUB_TOKEN", token.token))
    }
}

/// HTTP boundary used by the GitHub App provider.
pub trait GithubAppClient {
    fn create_installation_token(
        &self,
        jwt: &str,
        installation_id: u64,
        repositories: &[String],
    ) -> Result<GithubAppInstallationToken, ProviderError>;
}

/// GitHub App installation token returned by the GitHub API.
#[derive(Clone, PartialEq, Eq)]
pub struct GithubAppInstallationToken {
    pub token: String,
}

impl fmt::Debug for GithubAppInstallationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubAppInstallationToken")
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReqwestGithubAppClient;

impl GithubAppClient for ReqwestGithubAppClient {
    fn create_installation_token(
        &self,
        jwt: &str,
        installation_id: u64,
        repositories: &[String],
    ) -> Result<GithubAppInstallationToken, ProviderError> {
        let url =
            format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
        let response = reqwest::blocking::Client::new()
            .post(url)
            .timeout(Duration::from_secs(30))
            .header("Accept", "application/vnd.github+json")
            .header("Authorization", format!("Bearer {jwt}"))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "heim")
            .json(&GithubAppTokenRequest::new(repositories))
            .send()
            .map_err(|source| ProviderError::Http {
                provider: "github_app",
                message: source.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(ProviderError::Http {
                provider: "github_app",
                message: format!("GitHub API returned status {status}"),
            });
        }

        let body = response
            .json::<GithubAppTokenResponse>()
            .map_err(|source| ProviderError::Http {
                provider: "github_app",
                message: source.to_string(),
            })?;

        if body.token.trim().is_empty() {
            return Err(ProviderError::Http {
                provider: "github_app",
                message: "GitHub API returned an empty installation token".to_owned(),
            });
        }

        Ok(GithubAppInstallationToken { token: body.token })
    }
}

#[derive(Debug, Serialize)]
struct GithubAppTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    repositories: Option<Vec<String>>,
}

impl GithubAppTokenRequest {
    fn new(repositories: &[String]) -> Self {
        if repositories.is_empty() {
            Self { repositories: None }
        } else {
            Self {
                repositories: Some(
                    repositories
                        .iter()
                        .map(|repository| github_repository_name(repository))
                        .collect(),
                ),
            }
        }
    }
}

fn github_repository_name(repository: &str) -> String {
    repository
        .rsplit('/')
        .next()
        .unwrap_or(repository)
        .to_owned()
}

#[derive(Debug, Deserialize)]
struct GithubAppTokenResponse {
    token: String,
}

#[derive(Debug, Serialize)]
struct GithubAppJwtClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

fn github_app_jwt(app_id: u64, private_key_pem: &str) -> Result<String, ProviderError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| ProviderError::Clock {
            provider: "github_app",
            message: source.to_string(),
        })?
        .as_secs();
    let claims = GithubAppJwtClaims {
        iat: now.saturating_sub(60),
        exp: now + 540,
        iss: app_id.to_string(),
    };
    let key =
        jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|source| {
            ProviderError::Jwt {
                provider: "github_app",
                message: source.to_string(),
            }
        })?;

    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|source| ProviderError::Jwt {
        provider: "github_app",
        message: source.to_string(),
    })
}

/// Provider error without credential secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    UnsupportedProvider {
        provider: String,
        provider_type: &'static str,
    },
    SecretKindMismatch {
        provider: String,
        actual: String,
        expected: &'static str,
    },
    Jwt {
        provider: &'static str,
        message: String,
    },
    Http {
        provider: &'static str,
        message: String,
    },
    Clock {
        provider: &'static str,
        message: String,
    },
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProvider {
                provider,
                provider_type,
            } => write!(
                formatter,
                "provider {provider} has type {provider_type}, which cannot issue credentials yet"
            ),
            Self::SecretKindMismatch {
                provider,
                actual,
                expected,
            } => write!(
                formatter,
                "provider {provider} received secret type {actual}, but expected {expected}"
            ),
            Self::Jwt { provider, message } => {
                write!(
                    formatter,
                    "provider {provider} failed to sign JWT: {message}"
                )
            }
            Self::Http { provider, message } => {
                write!(formatter, "provider {provider} request failed: {message}")
            }
            Self::Clock { provider, message } => {
                write!(
                    formatter,
                    "provider {provider} failed to read clock: {message}"
                )
            }
        }
    }
}

impl std::error::Error for ProviderError {}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;

    use heim_sources::ResolvedSecret;

    use super::{
        CredentialProvider, CredentialRequest, GithubAppClient, GithubAppInstallationToken,
        GithubAppProvider, GithubPatProvider, ProviderError,
    };

    #[test]
    fn github_pat_provider_issues_gh_environment_variables() {
        let provider = GithubPatProvider::from_secret(ResolvedSecret::GithubPat {
            token: "ghp_secret".to_owned(),
        })
        .expect("provider");
        let request = CredentialRequest::new(
            "github.personal-readonly",
            "github_personal",
            "gh",
            ["gh", "pr", "view", "42"],
            PathBuf::from("/workspace"),
        );

        let credential = provider.issue(&request).expect("credential");

        assert_eq!(credential.kind(), "github_pat");
        assert_eq!(credential.env_vars()[0].name(), "GH_TOKEN");
        assert_eq!(credential.env_vars()[0].value(), "ghp_secret");
        assert_eq!(credential.env_vars()[1].name(), "GITHUB_TOKEN");
        assert_eq!(credential.env_vars()[1].value(), "ghp_secret");
    }

    #[test]
    fn issued_credential_metadata_excludes_secret_values() {
        let provider = GithubPatProvider::from_secret(ResolvedSecret::GithubPat {
            token: "ghp_secret".to_owned(),
        })
        .expect("provider");
        let request = CredentialRequest::new(
            "github.personal-readonly",
            "github_personal",
            "gh",
            ["gh", "pr", "view", "42"],
            PathBuf::from("/workspace"),
        );

        let credential = provider.issue(&request).expect("credential");
        let metadata = credential.metadata();
        let debug = format!("{credential:?}");

        assert_eq!(metadata.kind, "github_pat");
        assert_eq!(metadata.env_vars, ["GH_TOKEN", "GITHUB_TOKEN"]);
        assert_eq!(metadata.temp_files, Vec::<String>::new());
        assert!(!debug.contains("ghp_secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn github_pat_provider_rejects_wrong_secret_kind_without_printing_secret() {
        let error = GithubPatProvider::from_secret(ResolvedSecret::GithubAppPrivateKey {
            pem: "secret-pem".to_owned(),
        })
        .expect_err("wrong secret kind");

        assert_eq!(
            error.to_string(),
            "provider github_pat received secret type github_app_private_key, but expected github_pat"
        );
        assert!(!format!("{error:?}").contains("secret-pem"));
    }

    #[test]
    fn github_app_provider_requests_installation_token_and_exports_env_vars() {
        let client = RecordingGithubAppClient::new("ghs_installation_secret");
        let provider = GithubAppProvider::from_secret_with_jwt_for_tests(
            123456,
            987654,
            vec!["drymn/backend".to_owned()],
            ResolvedSecret::GithubAppPrivateKey {
                pem: "secret-pem".to_owned(),
            },
            client,
            "signed-jwt",
        )
        .expect("provider");
        let request = CredentialRequest::new(
            "github.drymn-pr-write",
            "github_drymn",
            "gh",
            ["gh", "pr", "view", "42"],
            PathBuf::from("/workspace"),
        );

        let credential = provider.issue(&request).expect("credential");

        assert_eq!(credential.kind(), "github_app");
        assert_eq!(credential.env_vars()[0].name(), "GH_TOKEN");
        assert_eq!(credential.env_vars()[0].value(), "ghs_installation_secret");
        assert_eq!(credential.env_vars()[1].name(), "GITHUB_TOKEN");
        assert_eq!(credential.env_vars()[1].value(), "ghs_installation_secret");
        assert_eq!(
            provider.client.calls.borrow().as_slice(),
            [(
                "signed-jwt".to_owned(),
                987654,
                vec!["drymn/backend".to_owned()]
            )]
        );
        assert!(!format!("{credential:?}").contains("ghs_installation_secret"));
    }

    #[test]
    fn github_app_provider_rejects_wrong_secret_kind_without_printing_secret() {
        let error = GithubAppProvider::from_secret_with_jwt_for_tests(
            123456,
            987654,
            Vec::new(),
            ResolvedSecret::GithubPat {
                token: "ghp_secret".to_owned(),
            },
            RecordingGithubAppClient::new("ghs_installation_secret"),
            "signed-jwt",
        )
        .expect_err("wrong secret kind");

        assert_eq!(
            error.to_string(),
            "provider github_app received secret type github_pat, but expected github_app_private_key"
        );
        assert!(!format!("{error:?}").contains("ghp_secret"));
    }

    #[test]
    fn github_app_provider_redacts_private_key_in_debug() {
        let provider = GithubAppProvider::from_secret_with_jwt_for_tests(
            123456,
            987654,
            Vec::new(),
            ResolvedSecret::GithubAppPrivateKey {
                pem: "secret-pem".to_owned(),
            },
            RecordingGithubAppClient::new("ghs_installation_secret"),
            "signed-jwt",
        )
        .expect("provider");

        let debug = format!("{provider:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-pem"));
    }

    #[test]
    fn github_app_installation_token_debug_redacts_secret() {
        let token = GithubAppInstallationToken {
            token: "ghs_installation_secret".to_owned(),
        };

        let debug = format!("{token:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("ghs_installation_secret"));
    }

    #[test]
    fn github_app_provider_propagates_client_error_without_printing_secret() {
        let provider = GithubAppProvider::from_secret_with_jwt_for_tests(
            123456,
            987654,
            Vec::new(),
            ResolvedSecret::GithubAppPrivateKey {
                pem: "secret-pem".to_owned(),
            },
            FailingGithubAppClient,
            "signed-jwt",
        )
        .expect("provider");
        let request = CredentialRequest::new(
            "github.drymn-pr-write",
            "github_drymn",
            "gh",
            ["gh", "pr", "view", "42"],
            PathBuf::from("/workspace"),
        );

        let error = provider.issue(&request).expect_err("client error");

        assert_eq!(
            error.to_string(),
            "provider github_app request failed: GitHub API returned status 403 Forbidden"
        );
        assert!(!format!("{error:?}").contains("secret-pem"));
        assert!(!format!("{error:?}").contains("signed-jwt"));
    }

    #[test]
    fn github_app_token_request_uses_repository_names() {
        let request =
            super::GithubAppTokenRequest::new(&["drymn/backend".to_owned(), "worker".to_owned()]);

        assert_eq!(
            request.repositories,
            Some(vec!["backend".to_owned(), "worker".to_owned()])
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordingGithubAppClient {
        token: String,
        calls: RefCell<Vec<(String, u64, Vec<String>)>>,
    }

    impl RecordingGithubAppClient {
        fn new(token: impl Into<String>) -> Self {
            Self {
                token: token.into(),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl GithubAppClient for RecordingGithubAppClient {
        fn create_installation_token(
            &self,
            jwt: &str,
            installation_id: u64,
            repositories: &[String],
        ) -> Result<GithubAppInstallationToken, ProviderError> {
            self.calls
                .borrow_mut()
                .push((jwt.to_owned(), installation_id, repositories.to_vec()));
            Ok(GithubAppInstallationToken {
                token: self.token.clone(),
            })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FailingGithubAppClient;

    impl GithubAppClient for FailingGithubAppClient {
        fn create_installation_token(
            &self,
            _jwt: &str,
            _installation_id: u64,
            _repositories: &[String],
        ) -> Result<GithubAppInstallationToken, ProviderError> {
            Err(ProviderError::Http {
                provider: "github_app",
                message: "GitHub API returned status 403 Forbidden".to_owned(),
            })
        }
    }
}
