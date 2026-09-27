use std::sync::Arc;

use crate::{
    Result,
    domain::RuntimeSettings,
    ports::SettingsRepository,
    service::{AccessService, AuthContext, Ports, admin_permissions as perm},
};

#[derive(Clone)]
pub struct SettingsService {
    settings: Arc<dyn SettingsRepository>,
    access: AccessService,
}

impl SettingsService {
    pub fn new(settings: Arc<dyn SettingsRepository>, access: AccessService) -> Self {
        Self { settings, access }
    }

    pub fn from_ports(ports: &Ports) -> Self {
        Self::new(ports.settings.clone(), AccessService::from_ports(ports))
    }

    pub async fn get(&self, actor: &AuthContext) -> Result<RuntimeSettings> {
        self.access
            .require_permission(actor, perm::SETTINGS_MANAGE, None)
            .await?;
        self.settings.get().await
    }

    pub async fn set_allow_self_registration(
        &self,
        actor: &AuthContext,
        allowed: bool,
    ) -> Result<RuntimeSettings> {
        self.access
            .require_permission(actor, perm::SETTINGS_MANAGE, None)
            .await?;
        self.settings.set_allow_self_registration(allowed).await?;
        self.settings.get().await
    }
}
