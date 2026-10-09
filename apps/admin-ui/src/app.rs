use leptos::prelude::*;
use leptos_router::{
    components::{Route, Router, Routes},
    hooks::use_navigate,
    path,
};

use crate::{auth, pages::login::LoginPage, pages::settings::SettingsPage};

#[component]
fn ProtectedHome() -> impl IntoView {
    let auth_state = auth::use_auth();
    let navigate = use_navigate();

    // Effect: если токена нет (включая логаут) — уводим на /login.
    Effect::new(move |_| {
        if auth_state.0.get().is_none() {
            navigate("/login", Default::default());
        }
    });

    move || {
        if auth_state.0.get().is_some() {
            view! { <SettingsPage /> }.into_any()
        } else {
            view! { <p>"Перенаправление..."</p> }.into_any()
        }
    }
}

#[component]
pub fn App() -> impl IntoView {
    auth::provide_auth_state();

    view! {
        <Router>
            <Routes fallback=|| view! { <p>"Страница не найдена"</p> }>
                <Route path=path!("/login") view=LoginPage />
                <Route path=path!("/") view=ProtectedHome />
            </Routes>
        </Router>
    }
}
