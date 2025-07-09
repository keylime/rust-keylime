use crate::config::*;
use config::{Config, File, FileFormat};
use glob::glob;
use log::*;
use serde::{Deserialize, Serialize};
use std::{
    env,
    path::{Path, PathBuf},
};

pub static GLOBAL_CONFIG_OVERRIDE_ENV_VAR: &str = "KEYLIME_AGENT_CONFIG";

// This enum represents the different kinds of sources for our configuration.
// By wrapping the PathBuf, we preserve the context of whether the user
// specified a single file or a whole directory.
#[derive(Debug)]
pub enum ConfigSource {
    File(PathBuf),
    Directory(PathBuf),
}

#[derive(Debug, Default)]
pub struct FileConfigBuilder {
    sources: Vec<ConfigSource>,
}

impl FileConfigBuilder {
    /// Creates a new, empty ConfigBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a single file as a configuration source.
    ///
    /// # Arguments
    ///
    /// * `path` - A path to the configuration file.
    pub fn file(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.sources.push(ConfigSource::File(path.into()));
        self
    }

    /// Adds a directory as a configuration source.
    /// All files within this directory will be loaded through globbing.
    ///
    /// # Arguments
    ///
    /// * `path` - A path to the directory.
    pub fn directory(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.sources.push(ConfigSource::Directory(path.into()));
        self
    }

    /// Load the configuration files from the default locations
    pub fn load_default_locations(&mut self) -> &mut Self {
        self.file(DEFAULT_SYS_CONFIG)
            .directory(DEFAULT_SYS_CONFIG_SNIPPETS_DIR)
            .file(DEFAULT_CONFIG)
            .directory(DEFAULT_CONFIG_SNIPPETS_DIR)
    }

    /// Consumes the builder and attempts to load the configuration.
    pub fn build(&mut self) -> Result<AgentConfig, KeylimeConfigError> {
        // wrapper struct just to deserialize
        #[derive(Debug, Deserialize, Serialize)]
        struct FileConfig {
            agent: AgentConfig,
        }

        // Use the default config as the base and override with the options from the sources
        let default_config = AgentConfig::default();
        let mut builder = Config::builder().add_source(default_config);

        // If the 'KEYLIME_AGENT_CONFIG' environment variable is set, load the configuration file set
        // and ignore system configurations
        if let Ok(env_cfg) = env::var(GLOBAL_CONFIG_OVERRIDE_ENV_VAR) {
            if !env_cfg.is_empty() {
                let path = Path::new(&env_cfg);
                if path.exists() {
                    warn!(
                        "Configuration replaced by {}: {}",
                        GLOBAL_CONFIG_OVERRIDE_ENV_VAR,
                        path.display()
                    );
                    builder = builder.add_source(
                        File::new(&env_cfg, FileFormat::Toml).required(true),
                    );
                    let f: FileConfig = builder.build()?.try_deserialize()?;
                    return Ok(f.agent);
                } else {
                    warn!("Configuration set in {GLOBAL_CONFIG_OVERRIDE_ENV_VAR} environment variable not found");
                    return Err(KeylimeConfigError::MissingEnvConfigFile {
                        file: path.display().to_string(),
                    });
                }
            }
        }

        // Apply the sources in order
        for (index, source) in self.sources.iter().enumerate() {
            match source {
                ConfigSource::File(path) => {
                    debug!(
                        "Loading configuration from FILE (#{}): {}",
                        index,
                        path.display()
                    );
                    builder = builder.add_source(
                        File::new(
                            &path.display().to_string(),
                            FileFormat::Toml,
                        )
                        .required(false),
                    );
                }
                ConfigSource::Directory(path) => {
                    debug!(
                        "Loading configuration from DIRECTORY (#{}): {}",
                        index,
                        path.display()
                    );

                    builder = builder.add_source(
                        glob(&path.join("*").display().to_string())
                            .map_err(KeylimeConfigError::GlobPattern)?
                            .filter_map(|entry| entry.ok())
                            .map(|path| {
                                File::new(
                                    &path.display().to_string(),
                                    FileFormat::Toml,
                                )
                                .required(false)
                            })
                            .collect::<Vec<_>>(),
                    );
                }
            }
        }

        let f: FileConfig = builder.build()?.try_deserialize()?;
        debug!("File configuration build process finished.");
        Ok(f.agent)
    }
}

pub fn load_default_files() -> Result<AgentConfig, KeylimeConfigError> {
    FileConfigBuilder::new().load_default_locations().build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_default_files() {
        let r = load_default_files();
        assert!(r.is_ok(), "failed to load default: {r:?}")
    }

    #[test]
    fn test_load_from_single_file() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let file_path = dir.path().join("config.toml");
        let mut file = std::fs::File::create(&file_path)
            .expect("failed to create config file");
        // Use the new option name `ip`
        writeln!(file, "[agent]\nip = \"192.168.1.10\"")
            .expect("failed to write on config file");

        let config = FileConfigBuilder::new()
            .file(&file_path)
            .build()
            .expect("failed to build configuration");

        // Assert against the new field name `ip`
        assert_eq!(config.ip, "192.168.1.10");
    }

    #[test]
    fn test_load_from_directory() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let file_path1 = dir.path().join("a.toml");
        let mut file1 = std::fs::File::create(&file_path1)
            .expect("failed to create config file");
        // Use `ip`
        writeln!(file1, "[agent]\nip = \"127.0.0.1\"")
            .expect("failed to write on config file");

        let file_path2 = dir.path().join("b.toml");
        let mut file2 = std::fs::File::create(&file_path2)
            .expect("failed to create config file");
        // Use `port`
        writeln!(file2, "[agent]\nport = 8888")
            .expect("failed to write on config file");

        let config = FileConfigBuilder::new()
            .directory(dir.path())
            .build()
            .expect("failed to build config");

        // Assert against the new field names
        assert_eq!(config.ip, "127.0.0.1");
        assert_eq!(config.port, 8888);
    }
}
