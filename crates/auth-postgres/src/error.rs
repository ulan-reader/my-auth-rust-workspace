use auth_core::AuthError;

/// 23505 = unique_violation -> Conflict; 23503 = foreign_key_violation -> Validation
/// (передан несуществующий id). Всё остальное — внутренняя ошибка.
pub(crate) fn map_db_error(e: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(db_err) = &e {
        match db_err.code().as_deref() {
            Some("23505") => return AuthError::Conflict,
            Some("23503") => {
                return AuthError::validation("указан несуществующий id (fk violation)");
            }
            _ => {}
        }
    }
    AuthError::internal(e)
}
