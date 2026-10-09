use leptos::prelude::*;

const TOKEN_KEY: &str = "auth_token";

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

pub fn load_token() -> Option<String> {
    storage()?.get_item(TOKEN_KEY).ok()?
}

pub fn save_token(token: &str) {
    if let Some(s) = storage() {
        let _ = s.set_item(TOKEN_KEY, token);
    }
}

pub fn clear_token() {
    if let Some(s) = storage() {
        let _ = s.remove_item(TOKEN_KEY);
    }
}

/// Реактивное состояние логина, доступное всему дереву через `use_context`.
#[derive(Clone, Copy)]
pub struct AuthState(pub RwSignal<Option<String>>);

pub fn provide_auth_state() {
    provide_context(AuthState(RwSignal::new(load_token())));
}

pub fn use_auth() -> AuthState {
    use_context::<AuthState>().expect("AuthState не предоставлен — забыли provide_auth_state()?")
}
