use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::crypto::device::{DeviceConflict, DeviceUnchecked};

/// Errors surfaced to the client as Matrix-style JSON errors.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("upstream request failed: {0}")]
    Upstream(reqwest::Error),
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    DeviceConflict(#[from] DeviceConflict),
    #[error("{0}")]
    DeviceUnchecked(#[from] DeviceUnchecked),
}

impl From<reqwest::Error> for ProxyError {
    /// The error names the URL, which may carry the client's query string,
    /// a legacy `access_token=` included; it goes into the log and back to
    /// the client. Keep the path only.
    fn from(mut error: reqwest::Error) -> Self {
        if let Some(url) = error.url_mut() {
            url.set_query(None);
        }
        ProxyError::Upstream(error)
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let status = match &self {
            ProxyError::Upstream(_) => StatusCode::BAD_GATEWAY,
            ProxyError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ProxyError::DeviceConflict(_) => StatusCode::CONFLICT,
            // The homeserver's failure, and ement syncs again after a 502.
            ProxyError::DeviceUnchecked(_) => StatusCode::BAD_GATEWAY,
        };
        tracing::error!(error = ?self, "request failed");
        let body = serde_json::json!({
            "errcode": "M_UNKNOWN",
            "error": format!("ement-e2ee: {self}"),
        });
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upstream_errors_do_not_repeat_the_query() {
        // Nothing listens on port 1 (where WSL2 may leave the connection
        // hanging rather than refuse it: either way, an error).
        let error = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(500))
            .build()
            .unwrap()
            .get("http://127.0.0.1:1/_matrix/client/v3/sync?access_token=syt_secret&since=s1")
            .send()
            .await
            .unwrap_err();
        let error = ProxyError::from(error);
        let text = format!("{error} {error:?}");
        assert!(!text.contains("syt_secret"), "{text}");
        assert!(text.contains("/_matrix/client/v3/sync"), "{text}");
    }
}
