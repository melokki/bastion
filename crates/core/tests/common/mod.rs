use bastion_core::{DatabaseCredentialInput, DatabaseEngine};

pub fn valid_postgres_input() -> DatabaseCredentialInput {
    postgres_input("Production DB", &["production"])
}

pub fn postgres_input(title: &str, tags: &[&str]) -> DatabaseCredentialInput {
    DatabaseCredentialInput {
        title: title.to_owned(),
        engine: DatabaseEngine::PostgreSql,
        hostname: "db.example.com".to_owned(),
        port: 5432,
        database: "app_production".to_owned(),
        username: "app_user".to_owned(),
        password: "correct horse battery staple".to_owned(),
        schema: Some("public".to_owned()),
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
    }
}
