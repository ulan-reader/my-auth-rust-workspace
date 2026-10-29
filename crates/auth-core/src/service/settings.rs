use std::sync::Arc;

use crate::{
    Result,
    domain::RuntimeSettings,
    ports::{AuditEvent, AuditRepository, SettingsRepository, UnitOfWork},
    service::{
        AccessService, AuthContext, Ports, admin_permissions as perm,
        audit::{audit_actions, audit_targets},
    },
};

#[derive(Clone)]
pub struct SettingsService {
    settings: Arc<dyn SettingsRepository>,
    access: AccessService,
    uow: Arc<dyn UnitOfWork>,
    audit: Arc<dyn AuditRepository>,
}

impl SettingsService {
    pub fn new(
        settings: Arc<dyn SettingsRepository>,
        access: AccessService,
        uow: Arc<dyn UnitOfWork>,
        audit: Arc<dyn AuditRepository>,
    ) -> Self {
        Self {
            settings,
            access,
            uow,
            audit,
        }
    }

    pub fn from_ports(ports: &Ports) -> Self {
        Self::new(
            ports.settings.clone(),
            AccessService::from_ports(ports),
            ports.uow.clone(),
            ports.audit.clone(),
        )
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

        let mut tx = self.uow.begin().await?;
        self.settings
            .set_allow_self_registration(&mut *tx, allowed)
            .await?;
        let event = AuditEvent::new(
            Some(actor.user_id()),
            audit_actions::SETTINGS_UPDATE,
            audit_targets::SETTINGS,
            None,
        )
        .detail("allow_self_registration", allowed.to_string());
        self.audit.record(&mut *tx, &event).await?;
        tx.commit().await?;

        self.settings.get().await
    }
}
