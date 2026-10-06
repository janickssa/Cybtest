//! Types shared between the app and the runner.

use serde::{Deserialize, Serialize};

/// A normalized technology tag with the evidence it was detected from,
/// e.g. `crate:actix-web` found in `backend/Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub evidence: Option<String>,
}
