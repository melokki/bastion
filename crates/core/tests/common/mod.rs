use bastion_core::PostgreSqlCredentialInput;

pub fn valid_postgres_input() -> PostgreSqlCredentialInput {
    postgres_input("Production DB", &["production"])
}

pub fn postgres_input(title: &str, tags: &[&str]) -> PostgreSqlCredentialInput {
    PostgreSqlCredentialInput {
        title: title.to_owned(),
        hostname: "db.example.com".to_owned(),
        port: 5432,
        database: "app_production".to_owned(),
        username: "app_user".to_owned(),
        password: "correct horse battery staple".to_owned(),
        schema: Some("public".to_owned()),
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
    }
}
