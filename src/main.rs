use std::sync::{Arc, Mutex};

use axum::{
    routing::{get, post},
    Router,
    Extension,
};
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod middleware;
pub mod models;
pub mod routes;
pub mod utils;

use crate::{
    middleware::auth::auth_middleware,
    routes::{auth, protected},
    utils::load_env,
    models::{User, Role},
};
use bcrypt;

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<utils::Config>,
    pub users: Arc<Mutex<Vec<User>>>,
}

#[tokio::main]
async fn main() {
    #[derive(OpenApi)]
    #[openapi(
        info(title = "Auth API", description = "A simple auth API"),
        paths(auth::login, auth::register, protected::admin_route, protected::admin_dashboard, protected::user_profile),
        components(schemas(
            models::User,
            models::Role,
            models::LoginRequest,
            models::LoginResponse
        ))
    )]
    struct ApiDoc;

    let state = AppState {
        config: Arc::new(load_env()),
        users: Arc::new(Mutex::new(vec![
            User {
                id: 1,
                email: "admin@example.com".to_string(),
                first_name: "Admin".to_string(),
                last_name: "User".to_string(),
                password: bcrypt::hash("adminpassword", bcrypt::DEFAULT_COST).unwrap(),
                role: Role::Admin,
            }
        ])),
    };

    let app = Router::new()
        .route("/admin", get(protected::admin_route))
        .route("/admin/dashboard", get(protected::admin_dashboard))
        .route("/user/profile", get(protected::user_profile))
        .layer(axum::middleware::from_fn_with_state(state.clone(),auth_middleware))
        .layer(Extension(state.users.clone()))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/login", post(auth::login))
        .route("/register", post(auth::register))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
