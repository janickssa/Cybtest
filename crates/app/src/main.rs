mod auth;

use std::net::SocketAddr;

use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use serde_json::{json, Value};

use auth::Auth;

pub fn router(auth: Auth) -> Router {
    let protected = Router::new()
        .route(
            "/api/me",
            get(|| async { Json(json!({ "user": "admin" })) }),
        )
        .route_layer(middleware::from_fn_with_state(
            auth.clone(),
            auth::require_session,
        ));

    Router::new()
        .route("/api/health", get(health))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .merge(protected)
        .with_state(auth)
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("hash-password") {
        let Some(password) = args.get(2) else {
            eprintln!("usage: sectestgen-app hash-password <password>");
            std::process::exit(2);
        };
        println!("{}", auth::hash_password(password));
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let bind: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .expect("BIND_ADDR must be host:port");
    let hash = std::env::var("AUTH_PASSWORD_HASH").unwrap_or_default();
    let cookie_secure = std::env::var("COOKIE_SECURE").map_or(true, |v| v != "false");
    let auth = Auth::new(hash, cookie_secure).unwrap_or_else(|e| {
        eprintln!("{e}\nGenerate one with: sectestgen-app hash-password '<password>'");
        std::process::exit(1);
    });

    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    tracing::info!("listening on http://{bind}");
    axum::serve(listener, router(auth))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use tower::ServiceExt;

    fn app() -> Router {
        router(Auth::new(auth::hash_password("secret"), false).unwrap())
    }

    fn login_req(password: &str) -> Request<Body> {
        Request::post("/api/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "password": password }).to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn health_is_public() {
        let res = app()
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn me_requires_login() {
        let res = app()
            .oneshot(Request::get("/api/me").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        let res = app().oneshot(login_req("nope")).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_then_me_then_logout() {
        let app = app();
        let res = app.clone().oneshot(login_req("secret")).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));
        let cookie = set_cookie.split(';').next().unwrap().to_string();

        let me = |c: String| {
            Request::get("/api/me")
                .header(header::COOKIE, c)
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(me(cookie.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        let logout = Request::post("/api/logout")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(logout).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.oneshot(me(cookie)).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
