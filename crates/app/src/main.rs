mod auth;
mod db;
mod export;
mod history;
mod plan;
mod rules;
mod runner;
mod runs;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, FromRef};
use axum::http::{header, HeaderValue};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use serde_json::{json, Value};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use auth::Auth;
use rules::Knowledge;

#[derive(Clone, FromRef)]
pub struct AppState {
    auth: Auth,
    knowledge: Arc<Knowledge>,
    runner: Option<Arc<runner::RunnerClient>>,
    db: db::Db,
    scope: Arc<common::Scope>,
}

pub fn router(state: AppState, frontend_dir: Option<PathBuf>, max_upload: usize) -> Router {
    let protected = Router::new()
        .route(
            "/api/me",
            get(|| async { Json(json!({ "user": "admin" })) }),
        )
        .route("/api/tags", get(plan::tags))
        .route("/api/analyze", post(plan::analyze))
        .route("/api/plan", post(plan::plan))
        .route("/api/export/markdown", post(plan::export_markdown))
        .route(
            "/api/upload",
            post(runs::upload).layer(DefaultBodyLimit::max(max_upload)),
        )
        .route("/api/runs", post(runs::create_run))
        .route("/api/runs/{id}", get(runs::get_run))
        .route("/api/runs/{id}/stop", post(runs::stop_run))
        .route("/api/runs/{id}/jobs/{job_id}/stop", post(runs::stop_job))
        .route("/api/runs/{id}/export/sarif", get(history::export_sarif))
        .route("/api/projects", get(history::list_projects))
        .route(
            "/api/projects/{id}",
            get(history::get_project).delete(history::delete_project),
        )
        .route("/api/projects/{id}/triage", post(history::set_triage))
        .route_layer(middleware::from_fn_with_state(
            state.auth.clone(),
            auth::require_session,
        ));

    let api = Router::new()
        .route("/api/health", get(health))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .merge(protected)
        .layer(middleware::from_fn(auth::same_origin))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state);

    let app = match frontend_dir {
        Some(dir) => api
            .fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(dir.join("index.html")))),
        None => api,
    };
    security_headers(app)
}

/// Headers for every response, pages and API alike.
fn security_headers(app: Router) -> Router {
    let headers = [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ];
    headers.into_iter().fold(app, |app, (name, value)| {
        app.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ))
    })
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

    let env_path = |name: &str, default: &str| {
        PathBuf::from(std::env::var(name).unwrap_or_else(|_| default.into()))
    };
    let knowledge = Knowledge::load(
        &env_path("RULES_DIR", "rules"),
        &env_path("CATALOG_DIR", "catalog"),
    )
    .unwrap_or_else(|e| {
        eprintln!("failed to load rules: {e}");
        std::process::exit(1);
    });
    tracing::info!(
        "loaded {} rules, {} tags, {} catalog actions",
        knowledge.rules.len(),
        knowledge.tags.len(),
        knowledge.catalog.len()
    );
    let frontend_dir =
        Some(env_path("FRONTEND_DIR", "frontend/dist")).filter(|d| d.join("index.html").exists());
    if frontend_dir.is_none() {
        tracing::warn!("frontend not found (set FRONTEND_DIR); serving the API only");
    }
    let runner = runner::RunnerClient::from_env().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    if runner.is_none() {
        tracing::warn!("RUNNER_URL not set: plans can be exported but not run");
    }
    let max_upload_mb: usize = std::env::var("MAX_UPLOAD_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let scope = common::Scope::parse(&std::env::var("SCOPE_ALLOWLIST").unwrap_or_default())
        .unwrap_or_else(|e| {
            eprintln!("SCOPE_ALLOWLIST: {e}");
            std::process::exit(1);
        });
    if scope.is_empty() {
        tracing::warn!("SCOPE_ALLOWLIST is empty: URL tests can be planned but not run");
    }
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://sectestgen.db".into());
    let database = db::connect(&database_url).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let state = AppState {
        auth,
        knowledge: Arc::new(knowledge),
        runner: runner.map(Arc::new),
        db: database,
        scope: Arc::new(scope),
    };

    let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
    tracing::info!("listening on http://{bind}");
    axum::serve(
        listener,
        router(state, frontend_dir, max_upload_mb * 1024 * 1024),
    )
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

    async fn app() -> Router {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let state = AppState {
            auth: Auth::new(auth::hash_password("secret"), false).unwrap(),
            knowledge: Arc::new(
                Knowledge::load(&root.join("rules"), &root.join("catalog")).unwrap(),
            ),
            runner: None,
            db: db::connect("sqlite::memory:").await.unwrap(),
            scope: Arc::default(),
        };
        router(state, None, 1024 * 1024)
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
            .await
            .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn me_requires_login() {
        let res = app()
            .await
            .oneshot(Request::get("/api/me").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        let res = app().await.oneshot(login_req("nope")).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_is_throttled_after_repeated_failures() {
        let app = app().await;
        for _ in 0..5 {
            let res = app.clone().oneshot(login_req("nope")).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        // Even the right password is refused while throttled.
        let res = app.oneshot(login_req("secret")).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(res.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn cross_site_posts_are_refused_and_headers_set() {
        let mut req = login_req("secret");
        req.headers_mut()
            .insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        req.headers_mut()
            .insert(header::HOST, "sectestgen.lan:8080".parse().unwrap());
        let res = app().await.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let mut req = login_req("secret");
        req.headers_mut().insert(
            header::ORIGIN,
            "http://sectestgen.lan:8080".parse().unwrap(),
        );
        req.headers_mut()
            .insert(header::HOST, "sectestgen.lan:8080".parse().unwrap());
        let res = app().await.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(res.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert!(res.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn login_then_me_then_logout() {
        let app = app().await;
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
