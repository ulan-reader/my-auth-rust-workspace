//! Инвариант «в системе остаётся хотя бы один активный администратор».
//! Все операции, которые могут его нарушить, берут одну блокировку — строку
//! роли admin, — поэтому параллельные «снятия» выполняются строго по очереди.

use auth_core::{AuthError, Result, domain::ADMIN_ROLE_CODE};
use sqlx::PgConnection;

use crate::error::map_db_error;

/// Берёт блокировку и возвращает число активных админов до операции.
pub(crate) async fn lock(conn: &mut PgConnection) -> Result<i64> {
    sqlx::query("select id from roles where code = $1 for update")
        .bind(ADMIN_ROLE_CODE)
        .execute(&mut *conn)
        .await
        .map_err(map_db_error)?;
    count(conn).await
}

/// Вызывать после изменения, в той же транзакции.
pub(crate) async fn ensure_remains(conn: &mut PgConnection, before: i64) -> Result<()> {
    if before > 0 && count(conn).await? == 0 {
        return Err(AuthError::validation(
            "нельзя оставить систему без администратора",
        ));
    }
    Ok(())
}

async fn count(conn: &mut PgConnection) -> Result<i64> {
    sqlx::query_scalar(
        r#"
        select count(distinct u.id)
        from user_roles ur
        join roles r on r.id = ur.role_id
        join users u on u.id = ur.user_id
        where r.code = $1 and u.is_active
        "#,
    )
    .bind(ADMIN_ROLE_CODE)
    .fetch_one(&mut *conn)
    .await
    .map_err(map_db_error)
}
