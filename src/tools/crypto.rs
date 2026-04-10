use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512, Digest};
use sha1::Sha1;
use md5::Md5;

#[derive(Deserialize)]
pub struct HashRequest {
    pub input: String,
}

#[derive(Serialize)]
pub struct HashResponse {
    pub hash: String,
    pub hash_uppercase: String,
    pub success: bool,
}

async fn md5_hash(Json(req): Json<HashRequest>) -> Json<HashResponse> {
    let mut hasher = Md5::new();
    hasher.update(req.input.as_bytes());
    let result = hex::encode(hasher.finalize());
    Json(HashResponse {
        hash: result.clone(),
        hash_uppercase: result.to_uppercase(),
        success: true,
    })
}

async fn sha1_hash(Json(req): Json<HashRequest>) -> Json<HashResponse> {
    let mut hasher = Sha1::new();
    hasher.update(req.input.as_bytes());
    let result = hex::encode(hasher.finalize());
    Json(HashResponse {
        hash: result.clone(),
        hash_uppercase: result.to_uppercase(),
        success: true,
    })
}

async fn sha256_hash(Json(req): Json<HashRequest>) -> Json<HashResponse> {
    let mut hasher = Sha256::new();
    hasher.update(req.input.as_bytes());
    let result = hex::encode(hasher.finalize());
    Json(HashResponse {
        hash: result.clone(),
        hash_uppercase: result.to_uppercase(),
        success: true,
    })
}

async fn sha512_hash(Json(req): Json<HashRequest>) -> Json<HashResponse> {
    let mut hasher = Sha512::new();
    hasher.update(req.input.as_bytes());
    let result = hex::encode(hasher.finalize());
    Json(HashResponse {
        hash: result.clone(),
        hash_uppercase: result.to_uppercase(),
        success: true,
    })
}

#[derive(Deserialize)]
pub struct HmacRequest {
    pub key: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct HmacResponse {
    pub hmac: String,
    pub hmac_uppercase: String,
    pub success: bool,
}

async fn hmac_sha256(Json(req): Json<HmacRequest>) -> Json<HmacResponse> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(req.key.as_bytes()).unwrap();
    mac.update(req.message.as_bytes());
    let result = hex::encode(mac.finalize().into_bytes());
    Json(HmacResponse {
        hmac: result.clone(),
        hmac_uppercase: result.to_uppercase(),
        success: true,
    })
}

#[derive(Deserialize)]
pub struct AesRequest {
    pub text: String,
    pub key: String,
}

#[derive(Serialize)]
pub struct AesResponse {
    pub result: String,
    pub success: bool,
    pub error: Option<String>,
}

async fn aes_encrypt(Json(req): Json<AesRequest>) -> Json<AesResponse> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::Nonce;
    use rand::Rng;

    let key_bytes = if req.key.len() < 32 {
        let mut k = req.key.as_bytes().to_vec();
        k.resize(32, 0);
        k
    } else if req.key.len() > 32 {
        req.key.as_bytes()[..32].to_vec()
    } else {
        req.key.as_bytes().to_vec()
    };

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();

    let nonce_bytes: [u8; 12] = rand::thread_rng().r#gen();
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, req.text.as_bytes()) {
        Ok(encrypted) => {
            let combined: Vec<u8> = nonce_bytes.into_iter().chain(encrypted.into_iter()).collect();
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            Json(AesResponse {
                result: STANDARD.encode(&combined),
                success: true,
                error: None,
            })
        },
        Err(e) => Json(AesResponse {
            result: String::new(),
            success: false,
            error: Some(format!("加密失败: {}", e)),
        }),
    }
}

async fn aes_decrypt(Json(req): Json<AesRequest>) -> Json<AesResponse> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::Nonce;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let combined = match STANDARD.decode(&req.text) {
        Ok(c) => c,
        Err(_) => return Json(AesResponse {
            result: String::new(),
            success: false,
            error: Some("Base64 解码失败".to_string()),
        }),
    };

    if combined.len() < 12 {
        return Json(AesResponse {
            result: String::new(),
            success: false,
            error: Some("数据长度不足".to_string()),
        });
    }

    let nonce = Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];

    let key_bytes = if req.key.len() < 32 {
        let mut k = req.key.as_bytes().to_vec();
        k.resize(32, 0);
        k
    } else if req.key.len() > 32 {
        req.key.as_bytes()[..32].to_vec()
    } else {
        req.key.as_bytes().to_vec()
    };

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();

    match cipher.decrypt(nonce, ciphertext) {
        Ok(decrypted) => match String::from_utf8(decrypted) {
            Ok(s) => Json(AesResponse { result: s, success: true, error: None }),
            Err(_) => Json(AesResponse {
                result: String::new(),
                success: false,
                error: Some("UTF-8 解码失败".to_string()),
            }),
        },
        Err(_) => Json(AesResponse {
            result: String::new(),
            success: false,
            error: Some("解密失败，密钥可能错误".to_string()),
        }),
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/md5", post(md5_hash))
        .route("/sha1", post(sha1_hash))
        .route("/sha256", post(sha256_hash))
        .route("/sha512", post(sha512_hash))
        .route("/hmac", post(hmac_sha256))
        .route("/aes/encrypt", post(aes_encrypt))
        .route("/aes/decrypt", post(aes_decrypt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_json(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    #[tokio::test]
    async fn test_md5() {
        let (_, json) = post_json("/md5", serde_json::json!({"input": "hello"})).await;
        assert_eq!(json["hash"], "5d41402abc4b2a76b9719d911017c592");
    }

    #[tokio::test]
    async fn test_sha256() {
        let (_, json) = post_json("/sha256", serde_json::json!({"input": "hello"})).await;
        assert_eq!(json["hash"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[tokio::test]
    async fn test_hmac() {
        let (_, json) = post_json("/hmac", serde_json::json!({"key": "secret", "message": "hello"})).await;
        assert!(json["success"].as_bool().unwrap());
        assert!(!json["hmac"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_aes_roundtrip() {
        let (_, enc) = post_json("/aes/encrypt", serde_json::json!({"text": "hello", "key": "mysecretkey"})).await;
        assert!(enc["success"].as_bool().unwrap());
        let encrypted = enc["result"].as_str().unwrap();

        let (_, dec) = post_json("/aes/decrypt", serde_json::json!({"text": encrypted, "key": "mysecretkey"})).await;
        assert!(dec["success"].as_bool().unwrap());
        assert_eq!(dec["result"], "hello");
    }
}