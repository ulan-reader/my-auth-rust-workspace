use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::{api, auth};

#[component]
pub fn SettingsPage() -> impl IntoView {
    let auth_state = auth::use_auth();

    let Some(token) = auth_state.0.get_untracked() else {
        return view! {
            <p>"Не авторизован."</p>
        }
        .into_any();
    };

    let settings = RwSignal::new(Option::<api::SettingsDto>::None);
    let error = RwSignal::new(Option::<String>::None);
    let saving = RwSignal::new(false);

    {
        let token = token.clone();

        spawn_local(async move {
            match api::get_settings(&token).await {
                Ok(s) => settings.set(Some(s)),
                Err(e) => error.set(Some(e.to_string())),
            }
        });
    }

    let toggle = move |_| {
        let Some(current) = settings.get() else {
            return;
        };

        if saving.get() {
            return;
        }

        saving.set(true);
        error.set(None);

        let token = token.clone();
        let next = !current.allow_self_registration;

        spawn_local(async move {
            match api::update_settings(&token, next).await {
                Ok(s) => settings.set(Some(s)),
                Err(e) => error.set(Some(e.to_string())),
            }

            saving.set(false);
        });
    };

    let toggle = StoredValue::new(toggle);

    let logout = move |_| {
        auth::clear_token();
        auth_state.0.set(None);
    };

    view! {
        <div class="settings-page">
            <h1>"Настройки"</h1>

            {move || {
                error.get().map(|msg| {
                    view! {
                        <p class="error">{msg}</p>
                    }
                })
            }}

            {move || match settings.get() {
                None => view! {
                    <p>"Загрузка..."</p>
                }
                .into_any(),

                Some(s) => view! {
                    <label class="toggle">
                        <input
                            type="checkbox"
                            prop:checked=s.allow_self_registration
                            disabled=move || saving.get()
                            on:change=move |ev| {
                                toggle.with_value(|handler| handler(ev));
                            }
                        />
                        "Разрешить самостоятельную регистрацию"
                    </label>
                }
                .into_any(),
            }}

            <button on:click=logout>
                "Выйти"
            </button>
        </div>
    }
    .into_any()
}
