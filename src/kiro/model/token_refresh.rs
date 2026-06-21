use serde::{Deserialize, Serialize};

/// 刷新 Token 的请求体 (Social 认证)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// 刷新 Token 的响应体 (Social 认证)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub profile_arn: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// IdC Token 刷新请求体 (AWS SSO OIDC)
///
/// `client_secret` 在 builder-id / public IAM Identity Center 注册的客户端可以
/// 不存在；若 `None`，序列化时 `clientSecret` 字段会被省略，避免 OIDC 端因
/// 空 secret 误判为 `invalid_client`。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdcRefreshRequest {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub refresh_token: String,
    pub grant_type: String,
}

/// IdC Token 刷新响应体 (AWS SSO OIDC)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdcRefreshResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub profile_arn: Option<String>,
}

// ============ External IdP (Microsoft Entra / Azure AD 等) 刷新 ============

/// External IdP token 刷新请求体（OAuth2 标准 form-encoded）
///
/// 对应 `provider == "ExternalIdp"` 账号，不走 AWS SSO OIDC，而是直接 POST 到
/// 凭据上的 `tokenEndpoint`，例如：
/// - Microsoft Entra: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
///
/// 序列化为 `application/x-www-form-urlencoded`（用 `serde_urlencoded`）。
///
/// `client_secret` 仅在 confidential client / web app 场景才存在；对公共客户端
/// （PKCE / native app）应保持 `None`，否则 IdP 会以 `invalid_client` 拒绝。
/// 同样 `scope` 在 refresh 时可省略。
#[derive(Debug, Serialize)]
pub struct ExternalIdpRefreshForm<'a> {
    pub grant_type: &'a str,
    pub client_id: &'a str,
    pub refresh_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'a str>,
}

/// External IdP token 刷新响应体
///
/// 兼容 RFC 6749 / Microsoft Entra v2.0：所有可选字段缺失即视为不更新。
/// `expires_in` 是相对秒数；`refresh_token` 在 IdP rotating refresh 时会刷新。
#[derive(Debug, Deserialize)]
pub struct ExternalIdpRefreshResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// External IdP 错误响应（RFC 6749 §5.2 + Microsoft Entra 扩展字段）
#[derive(Debug, Deserialize)]
pub struct ExternalIdpErrorResponse {
    pub error: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub error_description: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub error_codes: Option<Vec<i64>>,
}

// ============ AWS SSO OIDC 设备授权流程 ============

/// 注册 OIDC 客户端请求体
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterClientRequest {
    pub client_name: String,
    pub client_type: String,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub issuer_url: String,
}

/// 注册 OIDC 客户端响应体
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterClientResponse {
    pub client_id: String,
    pub client_secret: String,
    // 上游字段，仅用于完整反序列化记录；当前流程不依赖具体值
    #[allow(dead_code)]
    pub client_id_issued_at: Option<i64>,
    #[allow(dead_code)]
    pub client_secret_expires_at: Option<i64>,
}

/// 发起设备授权请求体
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartDeviceAuthorizationRequest {
    pub client_id: String,
    pub client_secret: String,
    pub start_url: String,
}

/// 发起设备授权响应体
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartDeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    pub interval: i64,
}

/// 轮询 Token 请求体（设备授权）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenRequest {
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: String,
    pub device_code: String,
}

/// 轮询 Token 响应体
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// AWS SSO OIDC 错误响应
#[derive(Debug, Deserialize)]
pub struct OidcErrorResponse {
    pub error: String,
    // 详细描述供日志使用，反序列化时保留以便排错
    #[allow(dead_code)]
    #[serde(default)]
    pub error_description: Option<String>,
}

// ============ Social (Portal) 登录流程 ============

/// Social token 交换请求体（PKCE）
#[derive(Debug, Serialize)]
pub struct SocialCreateTokenRequest {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitation_code: Option<String>,
}

/// Social token 响应体
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocialCreateTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub profile_arn: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idc_refresh_request_omits_client_secret_when_none() {
        let req = IdcRefreshRequest {
            client_id: "client-123".to_string(),
            client_secret: None,
            refresh_token: "rt-xyz".to_string(),
            grant_type: "refresh_token".to_string(),
        };
        let body = serde_json::to_string(&req).unwrap();
        assert!(!body.contains("clientSecret"), "body = {body}");
        assert!(body.contains("\"clientId\":\"client-123\""));
        assert!(body.contains("\"refreshToken\":\"rt-xyz\""));
        assert!(body.contains("\"grantType\":\"refresh_token\""));
    }

    #[test]
    fn idc_refresh_request_keeps_client_secret_when_some() {
        let req = IdcRefreshRequest {
            client_id: "client-123".to_string(),
            client_secret: Some("super-secret".to_string()),
            refresh_token: "rt-xyz".to_string(),
            grant_type: "refresh_token".to_string(),
        };
        let body = serde_json::to_string(&req).unwrap();
        assert!(body.contains("\"clientSecret\":\"super-secret\""));
    }

    /// 用 reqwest 构造请求并提取已编码的 body，等价于真实刷新路径所走的
    /// `client.post(...).form(&form)` 行为。
    fn encode_form(form: &ExternalIdpRefreshForm<'_>) -> String {
        let client = reqwest::Client::new();
        let req = client
            .post("https://example.invalid/token")
            .form(form)
            .build()
            .expect("build form request");
        let body = req.body().expect("form body").as_bytes().expect("inline body");
        String::from_utf8(body.to_vec()).expect("utf8 body")
    }

    #[test]
    fn external_idp_form_omits_optional_when_none() {
        let form = ExternalIdpRefreshForm {
            grant_type: "refresh_token",
            client_id: "abc-app",
            refresh_token: "rt-1",
            client_secret: None,
            scope: None,
        };
        let encoded = encode_form(&form);
        assert!(!encoded.contains("client_secret"), "encoded = {encoded}");
        assert!(!encoded.contains("scope"), "encoded = {encoded}");
        assert!(encoded.contains("grant_type=refresh_token"));
        assert!(encoded.contains("client_id=abc-app"));
        assert!(encoded.contains("refresh_token=rt-1"));
    }

    #[test]
    fn external_idp_form_emits_optional_when_some() {
        let form = ExternalIdpRefreshForm {
            grant_type: "refresh_token",
            client_id: "abc-app",
            refresh_token: "rt-1",
            client_secret: Some("conf-secret"),
            scope: Some("openid profile offline_access"),
        };
        let encoded = encode_form(&form);
        assert!(encoded.contains("client_secret=conf-secret"));
        // application/x-www-form-urlencoded 按 RFC 1866 把空格编为 +
        assert!(encoded.contains("scope=openid+profile+offline_access"));
    }

    #[test]
    fn external_idp_form_url_encodes_special_chars() {
        let form = ExternalIdpRefreshForm {
            grant_type: "refresh_token",
            client_id: "app/with space",
            refresh_token: "tok+/=",
            client_secret: None,
            scope: None,
        };
        let encoded = encode_form(&form);
        assert!(encoded.contains("client_id=app%2Fwith+space"));
        assert!(encoded.contains("refresh_token=tok%2B%2F%3D"));
    }

    #[test]
    fn external_idp_response_minimal() {
        let body = r#"{"access_token":"new-tok"}"#;
        let parsed: ExternalIdpRefreshResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.access_token, "new-tok");
        assert!(parsed.refresh_token.is_none());
        assert!(parsed.expires_in.is_none());
        assert!(parsed.token_type.is_none());
        assert!(parsed.scope.is_none());
    }

    #[test]
    fn external_idp_response_full() {
        let body = r#"{
            "access_token": "new-tok",
            "refresh_token": "new-rt",
            "expires_in": 3599,
            "token_type": "Bearer",
            "scope": "openid profile offline_access"
        }"#;
        let parsed: ExternalIdpRefreshResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.access_token, "new-tok");
        assert_eq!(parsed.refresh_token.as_deref(), Some("new-rt"));
        assert_eq!(parsed.expires_in, Some(3599));
        assert_eq!(parsed.token_type.as_deref(), Some("Bearer"));
        assert_eq!(parsed.scope.as_deref(), Some("openid profile offline_access"));
    }

    #[test]
    fn external_idp_error_response_basic() {
        let body = r#"{"error":"invalid_grant","error_description":"AADSTS70008: refresh token has expired"}"#;
        let parsed: ExternalIdpErrorResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.error, "invalid_grant");
        assert!(parsed.error_description.is_some());
    }

    #[test]
    fn external_idp_error_response_with_codes() {
        let body = r#"{"error":"invalid_grant","error_description":"...","error_codes":[70008]}"#;
        let parsed: ExternalIdpErrorResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.error, "invalid_grant");
        assert_eq!(parsed.error_codes, Some(vec![70008]));
    }
}
