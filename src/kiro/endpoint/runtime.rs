//! Kiro Runtime 端点（runtime.{region}.kiro.dev）
//!
//! Kiro IDE 实际部署了**两条并行**的对话上游：
//!
//! - 端 1：`https://runtime.{region}.kiro.dev/generateAssistantResponse`（本端点）
//! - 端 2：`https://q.{region}.amazonaws.com/generateAssistantResponse`（见 `ide.rs`）
//!
//! 二者上游限流桶**互相独立**：q 端点上账号被 `USER_REQUEST_RATE_EXCEEDED` 限速时，
//! runtime 端点仍可调用，反之亦然。把账号分到两个端点上，等效拿到了上游配额翻倍。
//!
//! 协议与 ide 端点几乎一致：
//! - REST POST `/generateAssistantResponse`
//! - `Content-Type: application/json`
//! - 请求体根对象需注入 `profileArn`
//! - 头部使用 aws-sdk-js User-Agent（KiroIDE-{version}-{machineId}）
//!
//! 唯一差别在 **URL + host 头** —— 走 `runtime.{region}.kiro.dev` 而非
//! `q.{region}.amazonaws.com`。

use reqwest::RequestBuilder;
use uuid::Uuid;

use super::{KiroEndpoint, RequestContext};
use crate::kiro::kiro_version;

/// Kiro Runtime 端点名称
pub const RUNTIME_ENDPOINT_NAME: &str = "runtime";

/// Kiro Runtime 端点
pub struct RuntimeEndpoint;

impl RuntimeEndpoint {
    pub fn new() -> Self {
        Self
    }

    fn api_region<'a>(&self, ctx: &'a RequestContext<'_>) -> &'a str {
        ctx.credentials.effective_api_region(ctx.config)
    }

    fn host(&self, ctx: &RequestContext<'_>) -> String {
        format!("runtime.{}.kiro.dev", self.api_region(ctx))
    }

    fn x_amz_user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-js/1.0.34 KiroIDE-{}-{}",
            kiro_version::effective(&ctx.config.kiro_version),
            ctx.machine_id
        )
    }

    fn user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-js/1.0.34 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#1.0.34 m/E KiroIDE-{}-{}",
            ctx.config.system_version,
            ctx.config.node_version,
            kiro_version::effective(&ctx.config.kiro_version),
            ctx.machine_id
        )
    }
}

impl Default for RuntimeEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroEndpoint for RuntimeEndpoint {
    fn name(&self) -> &'static str {
        RUNTIME_ENDPOINT_NAME
    }

    fn api_url(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "https://runtime.{}.kiro.dev/generateAssistantResponse",
            self.api_region(ctx)
        )
    }

    fn mcp_url(&self, ctx: &RequestContext<'_>) -> String {
        format!("https://runtime.{}.kiro.dev/mcp", self.api_region(ctx))
    }

    fn decorate_api(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amzn-codewhisperer-optout", "true")
            .header("x-amzn-kiro-agent-mode", "vibe")
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        } else if ctx.credentials.is_external_idp() {
            req = req.header("TokenType", "EXTERNAL_IDP");
        }
        req
    }

    fn decorate_mcp(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        if let Some(arn) = ctx.credentials.effective_profile_arn() {
            req = req.header("x-amzn-kiro-profile-arn", arn);
        }
        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        } else if ctx.credentials.is_external_idp() {
            req = req.header("TokenType", "EXTERNAL_IDP");
        }
        req
    }

    fn transform_api_body(&self, body: &str, ctx: &RequestContext<'_>) -> String {
        inject_profile_arn(body, ctx.credentials.streaming_profile_arn().as_deref())
    }
}

/// 将 profile_arn 注入到请求体 JSON 根对象
///
/// runtime 端点上游强制要求 `profileArn`（同 ide 端点行为，UA 标记 KiroIDE 版本
/// >= 0.12 时尤其严格）；缺失或为 null 会被上游以 400 拒绝。
fn inject_profile_arn(request_body: &str, profile_arn: Option<&str>) -> String {
    if let Some(arn) = profile_arn {
        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(request_body) {
            json["profileArn"] = serde_json::Value::String(arn.to_string());
            if let Ok(body) = serde_json::to_string(&json) {
                return body;
            }
        }
    }
    request_body.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiro::model::credentials::KiroCredentials;
    use crate::model::config::Config;

    fn mk_ctx<'a>(
        creds: &'a KiroCredentials,
        token: &'a str,
        machine_id: &'a str,
        config: &'a Config,
    ) -> RequestContext<'a> {
        RequestContext {
            credentials: creds,
            token,
            machine_id,
            config,
        }
    }

    #[test]
    fn test_api_url_uses_runtime_kiro_dev() {
        let ep = RuntimeEndpoint::new();
        let creds = KiroCredentials {
            region: Some("us-east-1".to_string()),
            ..Default::default()
        };
        let config = Config::default();
        let ctx = mk_ctx(&creds, "tok", "machine", &config);
        assert_eq!(
            ep.api_url(&ctx),
            "https://runtime.us-east-1.kiro.dev/generateAssistantResponse"
        );
        assert_eq!(ep.mcp_url(&ctx), "https://runtime.us-east-1.kiro.dev/mcp");
        assert_eq!(ep.host(&ctx), "runtime.us-east-1.kiro.dev");
    }

    #[test]
    fn test_api_url_respects_eu_central_region() {
        let ep = RuntimeEndpoint::new();
        let creds = KiroCredentials {
            api_region: Some("eu-central-1".to_string()),
            ..Default::default()
        };
        let config = Config::default();
        let ctx = mk_ctx(&creds, "tok", "machine", &config);
        assert_eq!(
            ep.api_url(&ctx),
            "https://runtime.eu-central-1.kiro.dev/generateAssistantResponse"
        );
    }

    #[test]
    fn test_inject_profile_arn_with_some() {
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let arn = Some("arn:aws:codewhisperer:us-east-1:123:profile/ABC");
        let result = inject_profile_arn(body, arn);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            json["profileArn"],
            "arn:aws:codewhisperer:us-east-1:123:profile/ABC"
        );
        assert_eq!(json["conversationState"]["conversationId"], "c1");
    }

    #[test]
    fn test_inject_profile_arn_with_none_keeps_body_unchanged() {
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let result = inject_profile_arn(body, None);
        assert_eq!(result, body);
    }

    #[test]
    fn test_inject_profile_arn_invalid_json_passthrough() {
        let body = "not-valid-json";
        let result = inject_profile_arn(body, Some("arn:test"));
        assert_eq!(result, "not-valid-json");
    }

    #[test]
    fn test_name_is_runtime() {
        let ep = RuntimeEndpoint::new();
        assert_eq!(ep.name(), "runtime");
        assert_eq!(ep.name(), RUNTIME_ENDPOINT_NAME);
    }
}
