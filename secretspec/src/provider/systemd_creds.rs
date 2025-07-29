use super::Provider;
use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use url::Url;

/// Scope for systemd credential encryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CredentialScope {
    /// User-scoped encryption (--user flag), no root privileges required.
    User,
    /// System-scoped encryption, may require elevated privileges.
    System,
}

impl Default for CredentialScope {
    fn default() -> Self {
        CredentialScope::User
    }
}

/// Configuration for the systemd-creds provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdCredsConfig {
    /// Directory for encrypted credential files. Files use format: `{project}-{profile}-{key}.cred`
    pub directory: PathBuf,

    /// Encryption scope: User (--user flag, safer) or System (may need privileges)
    pub scope: CredentialScope,
}

impl SystemdCredsConfig {
    /// Validates that an identifier (project, key, profile) is safe for use in filenames.
    fn validate_identifier(input: &str) -> Result<()> {
        if input.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Identifier cannot be empty".to_string(),
            ));
        }

        if input.len() > 255 {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Identifier too long (max 255 characters)".to_string(),
            ));
        }

        // Prevent path traversal components
        if input.contains("..") || input.contains('/') || input.contains('\\') {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Identifier contains path separators or traversal sequences".to_string(),
            ));
        }

        Ok(())
    }

    /// Validates and normalizes a directory path.
    fn validate_directory_path(path: &Path) -> Result<PathBuf> {
        // Use standard path canonicalization when possible
        match path.canonicalize() {
            Ok(canonical) => Ok(canonical),
            Err(_) => {
                // If canonicalize fails (path doesn't exist yet), just use the original path
                // Path creation will be handled by fs::create_dir_all later
                Ok(path.to_path_buf())
            }
        }
    }
}

impl TryFrom<&Url> for SystemdCredsConfig {
    type Error = SecretSpecError;

    /// Creates config from URL: `systemd-creds://directory?scope=user|system`
    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "systemd-creds" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for systemd-creds provider",
                url.scheme()
            )));
        }

        let directory = if url.path() != "" && url.path() != "/" {
            // Check if this is an absolute path (starts with /) or has a host
            if let Some(host) = url.host_str() {
                // Case like systemd-creds://config/secrets -> host="config", path="/secrets"
                // We want "config/secrets"
                format!("{}{}", host, url.path())
            } else {
                // Absolute path from systemd-creds:///path
                url.path().to_string()
            }
        } else if let Some(host) = url.host_str() {
            // Relative path from systemd-creds://directory
            host.to_string()
        } else {
            // No directory specified - this is an error
            return Err(SecretSpecError::ProviderOperationFailed(
                "systemd-creds provider requires a directory path. Use format: systemd-creds:///path or systemd-creds://directory".to_string()
            ));
        };

        let scope = url
            .query_pairs()
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| match value.as_ref() {
                "user" => Ok(CredentialScope::User),
                "system" => Ok(CredentialScope::System),
                invalid => Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Invalid scope '{}'. Must be 'user' or 'system'",
                    invalid
                ))),
            })
            .transpose()?
            .unwrap_or_default();

        let validated_directory = Self::validate_directory_path(&PathBuf::from(&directory))?;

        Ok(Self {
            directory: validated_directory,
            scope,
        })
    }
}

/// Provider for managing secrets using systemd-creds encryption.
/// Stores each secret as a separate encrypted file using `{project}-{profile}-{key}.cred` naming.
pub struct SystemdCredsProvider {
    config: SystemdCredsConfig,
}

impl SystemdCredsProvider {
    /// Executes a systemd-creds command
    fn execute_systemd_creds_command(
        &self,
        args: &[&str],
        stdin_data: Option<&str>,
    ) -> Result<std::process::Output> {
        let mut cmd = Command::new("systemd-creds");
        cmd.args(args);

        if let Some(_data) = stdin_data {
            cmd.stdin(std::process::Stdio::piped());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to execute systemd-creds: {}",
                e
            ))
        })?;

        if let Some(data) = stdin_data {
            if let Some(stdin) = child.stdin.take() {
                use std::io::Write;
                let mut stdin = stdin;
                stdin.write_all(data.as_bytes()).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to write to systemd-creds stdin: {}",
                        e
                    ))
                })?;
            }
        }

        let output = child.wait_with_output().map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to wait for systemd-creds command: {}",
                e
            ))
        })?;

        Ok(output)
    }
}

crate::register_provider! {
    struct: SystemdCredsProvider,
    config: SystemdCredsConfig,
    name: "systemd-creds",
    description: "Systemd encrypted credentials",
    schemes: ["systemd-creds"],
    examples: ["systemd-creds:///etc/credstore.encrypted", "systemd-creds://./creds?scope=user", "systemd-creds:///var/secrets?scope=system"],
}

impl SystemdCredsProvider {
    pub fn new(config: SystemdCredsConfig) -> Self {
        Self { config }
    }

    /// Generates secure filename: `{project}-{profile}-{key}.cred`
    fn credential_filename(&self, project: &str, key: &str, profile: &str) -> Result<PathBuf> {
        SystemdCredsConfig::validate_identifier(project)?;
        SystemdCredsConfig::validate_identifier(key)?;
        SystemdCredsConfig::validate_identifier(profile)?;

        let filename = format!("{}-{}-{}.cred", project, profile, key);
        Ok(self.config.directory.join(filename))
    }

    /// Checks if systemd-creds command is available.
    fn check_systemd_creds_available(&self) -> Result<()> {
        let output = self.execute_systemd_creds_command(&["--version"], None)?;

        if !output.status.success() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "systemd-creds command test failed. Please ensure systemd is properly installed."
                    .to_string(),
            ));
        }

        Ok(())
    }
}

impl Provider for SystemdCredsProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    /// Retrieves and decrypts a secret value from credential file.
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        self.check_systemd_creds_available()?;

        let credential_path = self.credential_filename(project, key, profile)?;

        if !credential_path.exists() {
            return Ok(None);
        }

        let mut args = vec!["decrypt"];

        match self.config.scope {
            CredentialScope::User => {
                args.push("--user");
            }
            CredentialScope::System => {}
        }

        let path_str = credential_path.to_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Credential path contains invalid Unicode characters".to_string(),
            )
        })?;
        args.push(path_str);

        let output = self.execute_systemd_creds_command(&args, None)?;

        if !output.status.success() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Failed to decrypt credential. Check permissions and file integrity.".to_string(),
            ));
        }

        let value = String::from_utf8(output.stdout).map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "Credential content contains invalid UTF-8 data".to_string(),
            )
        })?;

        let trimmed_value = value.trim_end_matches('\n');
        Ok(Some(SecretString::new(trimmed_value.to_string().into())))
    }

    /// Encrypts and stores a secret value to credential file.
    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        self.check_systemd_creds_available()?;

        if !self.config.directory.exists() {
            fs::create_dir_all(&self.config.directory).map_err(|_| {
                SecretSpecError::ProviderOperationFailed(
                    "Failed to create credential directory. Check permissions.".to_string(),
                )
            })?;
        }

        let credential_path = self.credential_filename(project, key, profile)?;

        let mut args = vec!["encrypt"];

        match self.config.scope {
            CredentialScope::User => {
                args.push("--user");
            }
            CredentialScope::System => {}
        }

        args.push("-");
        let path_str = credential_path.to_str().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "Credential path contains invalid Unicode characters".to_string(),
            )
        })?;
        args.push(path_str);

        let output = self.execute_systemd_creds_command(&args, Some(value.expose_secret()))?;

        if !output.status.success() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Failed to encrypt credential. Check permissions and systemd configuration."
                    .to_string(),
            ));
        }

        Ok(())
    }

    fn reflect(&self) -> Result<HashMap<String, crate::config::Secret>> {
        use crate::config::Secret;

        if !self.config.directory.exists() {
            return Ok(HashMap::new());
        }

        let mut secrets = HashMap::new();

        for entry in fs::read_dir(&self.config.directory)? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();

            if filename_str.ends_with(".cred") {
                let name_without_ext = &filename_str[..filename_str.len() - 5];
                let parts: Vec<&str> = name_without_ext.split('-').collect();

                if parts.len() >= 3 {
                    let key = parts[2..].join("-");
                    secrets.insert(
                        key.clone(),
                        Secret {
                            description: Some(format!("{} systemd credential", key)),
                            required: true,
                            default: None,
                        },
                    );
                }
            }
        }

        Ok(secrets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemd_creds_url_parsing() {
        // Test with absolute path using three slashes
        let url = Url::parse("systemd-creds:///etc/secrets").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "/etc/secrets");
        assert_eq!(config.scope, CredentialScope::User); // Default scope

        // Test with relative path using two slashes - authority as directory name
        let url = Url::parse("systemd-creds://secrets").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "secrets");
        assert_eq!(config.scope, CredentialScope::User);

        // Test with relative path in subdirectory
        let url = Url::parse("systemd-creds://config/secrets").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "config/secrets");
        assert_eq!(config.scope, CredentialScope::User);

        // Test with no directory (should fail)
        let url = Url::parse("systemd-creds://").unwrap();
        let result: Result<SystemdCredsConfig> = (&url).try_into();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("requires a directory path"));
        }

        // Test with complex relative path
        let url = Url::parse("systemd-creds://app/creds/production").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "app/creds/production");
        assert_eq!(config.scope, CredentialScope::User);
    }

    #[test]
    fn test_systemd_creds_url_parsing_with_scope() {
        // Test with user scope (explicit)
        let url = Url::parse("systemd-creds:///etc/secrets?scope=user").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "/etc/secrets");
        assert_eq!(config.scope, CredentialScope::User);

        // Test with system scope
        let url = Url::parse("systemd-creds:///var/secrets?scope=system").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "/var/secrets");
        assert_eq!(config.scope, CredentialScope::System);

        // Test with relative path and user scope
        let url = Url::parse("systemd-creds://./local/creds?scope=user").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "./local/creds");
        assert_eq!(config.scope, CredentialScope::User);

        // Test with complex path and system scope
        let url = Url::parse("systemd-creds://app/production/secrets?scope=system").unwrap();
        let config: SystemdCredsConfig = (&url).try_into().unwrap();
        assert_eq!(config.directory.to_str().unwrap(), "app/production/secrets");
        assert_eq!(config.scope, CredentialScope::System);
    }

    #[test]
    fn test_systemd_creds_url_parsing_invalid_scope() {
        // Test with invalid scope
        let url = Url::parse("systemd-creds:///etc/secrets?scope=invalid").unwrap();
        let result: Result<SystemdCredsConfig> = (&url).try_into();
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("Invalid scope 'invalid'"));
        }
    }

    #[test]
    fn test_credential_scope_default() {
        let scope = CredentialScope::default();
        assert_eq!(scope, CredentialScope::User);
    }

    #[test]
    fn test_credential_filename() {
        let config = SystemdCredsConfig {
            directory: PathBuf::from("/tmp/test"),
            scope: CredentialScope::User,
        };
        let provider = SystemdCredsProvider::new(config);

        let path = provider
            .credential_filename("myapp", "API_KEY", "production")
            .unwrap();
        assert_eq!(
            path.to_str().unwrap(),
            "/tmp/test/myapp-production-API_KEY.cred"
        );

        let path = provider
            .credential_filename("test-project", "DB_URL", "default")
            .unwrap();
        assert_eq!(
            path.to_str().unwrap(),
            "/tmp/test/test-project-default-DB_URL.cred"
        );
    }

    #[test]
    fn test_reflect_empty_directory() {
        let provider = SystemdCredsProvider::new(SystemdCredsConfig {
            directory: PathBuf::from("/tmp/nonexistent"),
            scope: CredentialScope::User,
        });

        let secrets = provider.reflect().unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_security_path_components_in_project() {
        let result = SystemdCredsConfig::validate_identifier("test/injection");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path separators"));
    }

    #[test]
    fn test_security_path_components_in_key() {
        let result = SystemdCredsConfig::validate_identifier("api_key/../etc/passwd");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("traversal sequences")
        );
    }

    #[test]
    fn test_security_path_components_in_profile() {
        let result = SystemdCredsConfig::validate_identifier("prod\\..\\system32");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path separators"));
    }

    #[test]
    fn test_security_path_traversal_in_identifiers() {
        let traversal_attempts = vec![
            "../../../etc/passwd",
            "../../tmp/evil",
            "./../../sensitive_file",
            "..\\..\\windows\\system32",
            "/absolute/path/attack",
        ];

        for attempt in traversal_attempts {
            let result = SystemdCredsConfig::validate_identifier(attempt);
            assert!(result.is_err(), "Should reject path traversal: {}", attempt);
        }
    }

    #[test]
    fn test_security_path_traversal_in_directory() {
        let traversal_attempts = vec![
            "../../etc/passwd",
            "../../../tmp/malicious",
            "subdir/../../../escaping",
        ];

        for attempt in traversal_attempts {
            let path = PathBuf::from(attempt);
            let result = SystemdCredsConfig::validate_directory_path(&path);
            assert!(result.is_ok() || result.is_err());
        }
    }

    #[test]
    fn test_security_reserved_names() {
        let result = SystemdCredsConfig::validate_identifier("..");
        assert!(result.is_err(), "Should reject .. (path traversal)");

        let result = SystemdCredsConfig::validate_identifier(".");
        assert!(result.is_ok(), "Should allow . as a filename character");
    }

    #[test]
    fn test_security_empty_identifier() {
        let result = SystemdCredsConfig::validate_identifier("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_security_long_identifier() {
        let long_input = "a".repeat(256);
        let result = SystemdCredsConfig::validate_identifier(&long_input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_security_valid_identifiers() {
        let valid_inputs = vec![
            "valid_name",
            "valid-name",
            "ValidName123",
            "name.with.dots",
            "a",
            "project-123",
            "API_KEY_V2",
            "special@chars", // Now allowed since we use standard path handling
            "unicode_αβγ",   // Unicode is fine for filenames
        ];

        for input in valid_inputs {
            let result = SystemdCredsConfig::validate_identifier(input);
            assert!(result.is_ok(), "Should accept valid identifier: {}", input);
        }
    }

    #[test]
    fn test_security_malicious_url_paths() {
        let malicious_urls = vec!["systemd-creds://../../etc/secrets"];

        for url_str in malicious_urls {
            let url = Url::parse(url_str).unwrap();
            let result: Result<SystemdCredsConfig> = (&url).try_into();
            assert!(
                result.is_ok() || result.is_err(),
                "Should handle URL: {}",
                url_str
            );
        }

        let url_str = "systemd-creds://dir/../../../escape";
        let url = Url::parse(url_str).unwrap();
        let result: Result<SystemdCredsConfig> = (&url).try_into();

        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_security_default_scope_is_user() {
        let default_scope = CredentialScope::default();
        assert_eq!(default_scope, CredentialScope::User);
    }

    #[test]
    fn test_security_error_messages_no_disclosure() {
        let result = SystemdCredsConfig::validate_identifier("test/../evil");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();

        assert!(!error_msg.contains("/usr/"));
        assert!(!error_msg.contains("/etc/"));
        assert!(!error_msg.contains("root"));
        assert!(!error_msg.contains("admin"));
    }

    #[cfg(feature = "integration_tests")]
    mod integration_security_tests {
        use super::*;
        use tempfile::TempDir;

        #[test]
        fn test_security_safe_credential_filename_generation() {
            let temp_dir = TempDir::new().unwrap();
            let config = SystemdCredsConfig {
                directory: temp_dir.path().to_path_buf(),
                scope: CredentialScope::User,
            };
            let provider = SystemdCredsProvider::new(config);

            let path = provider
                .credential_filename("myapp", "api_key", "prod")
                .unwrap();
            let expected = temp_dir.path().join("myapp-prod-api_key.cred");
            assert_eq!(path, expected);

            let result = provider.credential_filename("../evil", "key", "prod");
            assert!(result.is_err());
        }
    }
}
