//! CodeWhisperer 端点
//!
//! 独立的流式对话兜底桶，与 `ide`/`runtime` 端点在上游 AWS 内部走**不同的服务限流桶**——
//! 当 `q.{region}.amazonaws.com`（`ide`）与 `runtime.{region}.kiro.dev`（`runtime`）
//! 都被 AWS 后台限流击穿时，`codewhisperer.{region}.amazonaws.com` 通常仍有余量。
//! 参考 Quorinex/Kiro-Go 三桶策略。
//!
//! 差异点：
//! - URL host：`codewhisperer.{region}.amazonaws.com`（与 ide 的 `q.*` 完全不同的子域）
//! - `X-Amz-Target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse`
//!   （告知上游按 CodeWhispererStreaming 服务分派，独立于 Q 服务的限流桶）
//! - 其余（body、profileArn 注入、UA、Origin=AI_EDITOR、token 头）全部与流式端点一致
//!
//! **profileArn 走 `streaming_profile_arn()`**（含 BuilderID 占位符），
//! 与 runtime 端点一致，与非流式 ide MCP 分支不同。

use reqwest::RequestBuilder;
use uuid::Uuid;

use super::{KiroEndpoint, RequestContext};
use crate::kiro::kiro_version;

/// CodeWhisperer 端点名称
pub const CODEWHISPERER_ENDPOINT_NAME: &str = "codewhisperer";

/// AWS 内部路由到 CodeWhispererStreaming 服务的 target header 值
const X_AMZ_TARGET: &str = "AmazonCodeWhispererStreamingService.GenerateAssistantResponse";

/// CodeWhisperer 端点（第三桶兜底）
pub struct CodewhispererEndpoint;

impl CodewhispererEndpoint {
    pub fn new() -> Self {
        Self
    }

    fn api_region<'a>(&self, ctx: &'a RequestContext<'_>) -> &'a str {
        ctx.credentials.effective_api_region(ctx.config)
    }

    fn host(&self, ctx: &RequestContext<'_>) -> String {
        format!("codewhisperer.{}.amazonaws.com", self.api_region(ctx))
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

impl Default for CodewhispererEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroEndpoint for CodewhispererEndpoint {
    fn name(&self) -> &'static str {
        CODEWHISPERER_ENDPOINT_NAME
    }

    fn api_url(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "https://codewhisperer.{}.amazonaws.com/generateAssistantResponse",
            self.api_region(ctx)
        )
    }

    fn mcp_url(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "https://codewhisperer.{}.amazonaws.com/mcp",
            self.api_region(ctx)
        )
    }

    fn decorate_api(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amz-target", X_AMZ_TARGET)
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

/// 将 profile_arn 注入到请求体 JSON 根对象（与 ide/runtime 端点行为一致）
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
    use crate::model::config::Config;
    use crate::kiro::model::credentials::KiroCredentials;

    fn test_ctx<'a>(cred: &'a KiroCredentials, cfg: &'a Config) -> RequestContext<'a> {
        RequestContext {
            credentials: cred,
            token: "test-token",
            machine_id: "test-mid",
            config: cfg,
        }
    }

    #[test]
    fn test_api_url_uses_codewhisperer_host() {
        let cred = KiroCredentials::default();
        let cfg = Config::default();
        let ep = CodewhispererEndpoint::new();
        let ctx = test_ctx(&cred, &cfg);
        assert_eq!(
            ep.api_url(&ctx),
            "https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse"
        );
    }

    #[test]
    fn test_endpoint_name() {
        assert_eq!(CodewhispererEndpoint::new().name(), "codewhisperer");
    }

    #[test]
    fn test_inject_profile_arn_preserves_body() {
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let result = inject_profile_arn(body, Some("arn:aws:codewhisperer:us-east-1:123:profile/X"));
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            json["profileArn"],
            "arn:aws:codewhisperer:us-east-1:123:profile/X"
        );
        assert_eq!(json["conversationState"]["conversationId"], "c1");
    }
}
