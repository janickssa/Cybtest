//! Single-user login: Argon2 password hash from the environment and
//! in-memory sessions referenced by an `HttpOnly` cookie.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::RngCore;
use serde::Deserialize;

pub const COOKIE_NAME: &str = "sectestgen_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Clone)]
pub struct Auth {
    password_hash: Arc<String>,
    cookie_secure: bool,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
}

impl Auth {
    pub fn new(password_hash: String, cookie_secure: bool) -> Result<Self, String> {
        PasswordHash::new(&password_hash)
            .map_err(|e| format!("invalid AUTH_PASSWORD_HASH: {e}"))?;
        Ok(Self {
            password_hash: Arc::new(password_hash),
            cookie_secure,
            sessions: Arc::default(),
        })
    }

    fn verify(&self, password: &str) -> bool {
        let hash = PasswordHash::new(&self.password_hash).expect("validated in Auth::new");
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    }

    fn create_session(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, expires| *expires > Instant::now());
        sessions.insert(token.clone(), Instant::now() + SESSION_TTL);
        token
    }

    fn is_valid(&self, token: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(token)
            .is_some_and(|expires| *expires > Instant::now())
    }

    fn remove(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    fn cookie(&self, value: &str, max_age: u64) -> HeaderValue {
        let secure = if self.cookie_secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
        ))
        .expect("cookie is ASCII")
    }
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing")
        .to_string()
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE_NAME)
        .map(|(_, value)| value.to_string())
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
}

pub async fn login(State(auth): State<Auth>, Json(req): Json<LoginRequest>) -> Response {
    if !auth.verify(&req.password) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let token = auth.create_session();
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().insert(
        header::SET_COOKIE,
        auth.cookie(&token, SESSION_TTL.as_secs()),
    );
    res
}

pub async fn logout(State(auth): State<Auth>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers) {
        auth.remove(&token);
    }
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut()
        .insert(header::SET_COOKIE, auth.cookie("", 0));
    res
}

/// Rejects requests without a valid session cookie.
pub async fn require_session(State(auth): State<Auth>, req: Request, next: Next) -> Response {
    match session_token(req.headers()) {
        Some(token) if auth.is_valid(&token) => next.run(req).await,
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}
