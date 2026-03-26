use crate::provider::{ModelProvider, ModelRequest, ModelResponse};
use async_trait::async_trait;
use libloading::{Library, Symbol};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub supported_models: Vec<String>,
}

pub type PluginCreate = unsafe fn() -> *mut dyn ModelProvider;
pub type PluginMetadataFn = unsafe fn() -> PluginMetadata;

pub struct Plugin {
    pub metadata: PluginMetadata,
    provider: Box<dyn ModelProvider>,
    _lib: Arc<Library>,
}

impl Plugin {
    pub fn provider(&self) -> &dyn ModelProvider {
        &*self.provider
    }
}

pub struct PluginManager {
    plugins: HashMap<String, Plugin>,
    plugin_dir: PathBuf,
}

impl PluginManager {
    pub fn new(plugin_dir: PathBuf) -> Self {
        Self {
            plugins: HashMap::new(),
            plugin_dir,
        }
    }

    pub fn load_plugin(&mut self, name: &str) -> Result<()> {
        let library_path = self.plugin_dir.join(format!(
            "{}{}",
            name,
            std::env::consts::DLL_EXTENSION
        ));

        unsafe {
            let lib = Arc::new(Library::new(library_path)?);

            // Get metadata first
            let metadata_fn: Symbol<PluginMetadataFn> = lib.get(b"plugin_metadata")?;
            let metadata = metadata_fn();

            // Create provider instance
            let create_fn: Symbol<PluginCreate> = lib.get(b"create_provider")?;
            let provider_ptr = create_fn();
            let provider = Box::from_raw(provider_ptr);

            self.plugins.insert(
                name.to_string(),
                Plugin {
                    metadata,
                    provider,
                    _lib: lib,
                },
            );
        }

        Ok(())
    }

    pub fn unload_plugin(&mut self, name: &str) -> Result<()> {
        self.plugins.remove(name);
        Ok(())
    }

    pub fn get_provider(&self, name: &str) -> Option<&dyn ModelProvider> {
        self.plugins.get(name).map(|p| p.provider())
    }

    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins.values().map(|p| p.metadata.clone()).collect()
    }
}

#[macro_export]
macro_rules! declare_plugin {
    ($provider_type:ty, $metadata:expr) => {
        #[no_mangle]
        pub extern "C" fn create_provider() -> *mut dyn $crate::provider::ModelProvider {
            let provider = <$provider_type>::new();
            Box::into_raw(Box::new(provider))
        }

        #[no_mangle]
        pub extern "C" fn plugin_metadata() -> $crate::plugin::PluginMetadata {
            $metadata
        }
    };
}

// Example plugin implementation module
pub mod example {
    use super::*;
    use crate::provider::{ModelProvider, ModelRequest, ModelResponse};

    pub struct ExampleProvider;

    impl ExampleProvider {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl ModelProvider for ExampleProvider {
        async fn process_request(&self, request: ModelRequest) -> Result<ModelResponse> {
            // Example implementation
            Ok(ModelResponse {
                content: "Example response".to_string(),
                model: request.model,
                usage: None,
            })
        }

        fn get_credentials(&self) -> HashMap<String, String> {
            HashMap::new()
        }

        fn supports_model(&self, _model: &str) -> bool {
            true
        }
    }

    declare_plugin!(
        ExampleProvider,
        PluginMetadata {
            name: "example".to_string(),
            version: "0.1.0".to_string(),
            description: "An example provider plugin".to_string(),
            author: "Example Author".to_string(),
            supported_models: vec!["example-model".to_string()],
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_plugin_loading() {
        let temp_dir = tempdir().unwrap();
        let mut manager = PluginManager::new(temp_dir.path().to_path_buf());

        // Note: This test requires actual plugin compilation.
        // In practice, we'd have a test plugin compiled and placed in the temp directory.
        // For now, we'll just test the manager's API.

        assert!(manager.list_plugins().is_empty());
        assert!(manager.get_provider("non-existent").is_none());
    }
}