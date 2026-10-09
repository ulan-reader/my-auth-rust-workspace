use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

use crate::{api, auth};

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth_state = auth::use_auth();
    let navigate = use_navigate();

    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let pending = RwSignal::new(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if pending.get() {
            return;
        }
        error.set(None);
        pending.set(true);

        let email_v = email.get();
        let password_v = password.get();
        let navigate = navigate.clone();

        spawn_local(async move {
            match api::login(&email_v, &password_v).await {
                Ok(tokens) => {
                    auth::save_token(&tokens.access_token);
                    auth_state.0.set(Some(tokens.access_token));
                    navigate("/", Default::default());
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            pending.set(false);
        });
    };

    view! {
        <div class="login-page">
            <form on:submit=on_submit>
                <h1>"Вход"</h1>
                <label>
                    "Email"
                    <input
                        type="email"
                        required
                        prop:value=move || email.get()
                        on:input:target=move |ev| email.set(ev.target().value())
                    />
                </label>
                <label>
                    "Пароль"
                    <input
                        type="password"
                        required
                        prop:value=move || password.get()
                        on:input:target=move |ev| password.set(ev.target().value())
                    />
                </label>
                {move || error.get().map(|msg| view! { <p class="error">{msg}</p> })}
                <button type="submit" disabled=move || pending.get()>
                    {move || if pending.get() { "Входим..." } else { "Войти" }}
                </button>
            </form>
        </div>
    }
}
