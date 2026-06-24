//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，支持 Social 和 IdC 认证方式
//! 支持多凭据 (MultiTokenManager) 管理

use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as TokioMutex;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration as StdDuration, Instant};

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::kiro_version::USAGE_API_KIRO_VERSION;
use crate::kiro::machine_id;
use crate::kiro::model::available_models::ListAvailableModelsResponse;
use crate::kiro::model::available_profiles::ListAvailableProfilesResponse;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::events::Event as KiroStreamEvent;
use crate::kiro::model::token_refresh::{
    ExternalIdpErrorResponse, ExternalIdpRefreshForm, ExternalIdpRefreshResponse,
    IdcRefreshRequest, IdcRefreshResponse, RefreshRequest, RefreshResponse,
};
use crate::kiro::model::usage_limits::UsageLimitsResponse;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::model::config::{CacheMode, Config};
use crate::admin::groups::SharedGroupManager;

/// 测活产出 — 写入 traces.db 时复用真实对话路径的 token / credit 字段
#[derive(Debug, Clone, Default)]
pub struct TestActiveOutcome {
    /// 真实使用的模型 ID（写入 trace.model，UI 列显示这个值）
    pub model_id: String,
    /// 输入 tokens：来自 contextUsageEvent + 模型窗口换算（与正常对话同口径）
    pub input_tokens: i32,
    /// 输出 tokens：基于上游返回文本估算（与正常对话同口径）
    pub output_tokens: i32,
    /// 上游下发的 credit 计费量（meteringEvent.usage 累加）
    pub credits: f64,
    /// 上游下发的 contextUsagePercentage（用于排查，可选）
    pub context_usage_percentage: Option<f64>,
    /// 第一个 AssistantResponse 文本字节出现的耗时（毫秒）
    pub first_token_ms: Option<u64>,
}

/// 检查 Token 是否在指定时间内过期
pub(crate) fn is_token_expiring_within(
    credentials: &KiroCredentials,
    minutes: i64,
) -> Option<bool> {
    credentials
        .expires_at
        .as_ref()
        .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires| expires <= Utc::now() + Duration::minutes(minutes))
}

/// 检查 Token 是否已过期（提前 5 分钟判断）
pub(crate) fn is_token_expired(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 5).unwrap_or(true)
}

/// 检查 Token 是否即将过期（10分钟内）
pub(crate) fn is_token_expiring_soon(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 10).unwrap_or(false)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// 生成 API Key 脱敏展示(前 4 + ... + 后 4,长度不足或非 ASCII 回退 ***)
fn mask_api_key(key: &str) -> String {
    if key.is_ascii() && key.len() > 16 {
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    } else {
        "***".to_string()
    }
}

/// 验证 refreshToken 的基本有效性
pub(crate) fn validate_refresh_token(credentials: &KiroCredentials) -> anyhow::Result<()> {
    let refresh_token = credentials
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;

    if refresh_token.is_empty() {
        bail!("refreshToken 为空");
    }

    if refresh_token.len() < 100 || refresh_token.ends_with("...") || refresh_token.contains("...")
    {
        bail!(
            "refreshToken 已被截断（长度: {} 字符）。\n\
             这通常是 Kiro IDE 为了防止凭证被第三方工具使用而故意截断的。",
            refresh_token.len()
        );
    }

    Ok(())
}

/// Refresh Token 永久失效错误
///
/// 当服务端返回 400 + `invalid_grant` 时，表示 refreshToken 已被撤销或过期，
/// 不应重试，需立即禁用对应凭据。
#[derive(Debug)]
pub(crate) struct RefreshTokenInvalidError {
    pub message: String,
}

impl fmt::Display for RefreshTokenInvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RefreshTokenInvalidError {}

/// 刷新 Token
pub(crate) async fn refresh_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    // API Key 凭据不支持 Token 刷新：底层契约级拦截
    // 其他调用点（try_ensure_token / 活跃路径 / add_credential）在调用前已显式分流 API Key；
    // 仅 force_refresh_token_for 未分流，此处 bail 让错误自然传播为 400 BAD_REQUEST。
    if credentials.is_api_key_credential() {
        bail!("API Key 凭据不支持刷新 Token");
    }

    validate_refresh_token(credentials)?;

    // External IdP (Microsoft Entra / Azure AD 等) 优先匹配：
    // 这条分支不走 AWS SSO OIDC，而是直接 POST 到凭据上的 token_endpoint。
    if credentials.is_external_idp() {
        return refresh_external_idp_token(credentials, config, proxy).await;
    }

    // 根据 auth_method 选择刷新方式
    // 如果未指定 auth_method，根据是否有 clientId/clientSecret 自动判断
    let auth_method = credentials.auth_method.as_deref().unwrap_or_else(|| {
        if credentials.client_id.is_some() && credentials.client_secret.is_some() {
            "idc"
        } else {
            "social"
        }
    });

    if auth_method.eq_ignore_ascii_case("idc")
        || auth_method.eq_ignore_ascii_case("builder-id")
        || auth_method.eq_ignore_ascii_case("iam")
    {
        refresh_idc_token(credentials, config, proxy).await
    } else {
        refresh_social_token(credentials, config, proxy).await
    }
}

/// 刷新 Social Token
async fn refresh_social_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 Social Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);

    let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);
    let refresh_domain = format!("prod.{}.auth.desktop.kiro.dev", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = crate::kiro::kiro_version::effective(&config.kiro_version);

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("KiroIDE-{}-{}", kiro_version, machine_id),
        )
        .header("Accept-Encoding", "gzip, compress, deflate, br")
        .header("host", &refresh_domain)
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        // 400 + invalid_grant + Invalid refresh token provided → refreshToken 永久失效
        if status.as_u16() == 400
            && body_text.contains("\"invalid_grant\"")
            && body_text.contains("Invalid refresh token provided")
        {
            return Err(RefreshTokenInvalidError {
                message: format!("Social refreshToken 已失效 (invalid_grant): {}", body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "OAuth 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OAuth 服务暂时不可用",
            _ => "Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: RefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    Ok(new_credentials)
}

/// 刷新 IdC Token (AWS SSO OIDC)
async fn refresh_idc_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 IdC Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let client_id = credentials
        .client_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientId"))?;
    // clientSecret 在公共客户端（PKCE / builder-id）场景可缺失：
    // 留 None 时序列化会自动省略 clientSecret 字段，避免 invalid_client。
    let client_secret = credentials.client_secret.as_ref().cloned();

    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);
    let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let x_amz_user_agent = "aws-sdk-js/3.980.0 KiroIDE";
    let user_agent = format!(
        "aws-sdk-js/3.980.0 ua/2.1 os/{} lang/js md/nodejs#{} api/sso-oidc#3.980.0 m/E KiroIDE",
        os_name, node_version
    );

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = IdcRefreshRequest {
        client_id: client_id.to_string(),
        client_secret,
        refresh_token: refresh_token.to_string(),
        grant_type: "refresh_token".to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("content-type", "application/json")
        .header("x-amz-user-agent", x_amz_user_agent)
        .header("user-agent", &user_agent)
        .header("host", format!("oidc.{}.amazonaws.com", region))
        .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
        .header("amz-sdk-request", "attempt=1; max=4")
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        // 400 + invalid_grant + Invalid refresh token provided → refreshToken 永久失效
        if status.as_u16() == 400
            && body_text.contains("\"invalid_grant\"")
            && body_text.contains("Invalid refresh token provided")
        {
            return Err(RefreshTokenInvalidError {
                message: format!("IdC refreshToken 已失效 (invalid_grant): {}", body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "IdC 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OIDC 服务暂时不可用",
            _ => "IdC Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: IdcRefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    // 同步更新 profile_arn（如果 IdC 响应中包含）
    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    Ok(new_credentials)
}

/// 刷新 External IdP Token（Microsoft Entra / Azure AD 等）
///
/// 与 AWS SSO OIDC 不同，External IdP 凭据走 IdP 自己的 OAuth2 token endpoint，
/// 请求体是 `application/x-www-form-urlencoded`，而非 JSON。
///
/// 字段约束（参见 RFC 6749 §6 + Microsoft identity platform 文档）：
/// - `grant_type=refresh_token` 必填
/// - `client_id` 必填
/// - `refresh_token` 必填
/// - `client_secret` 仅 confidential client 必填，公共客户端（PKCE/native）必须省略
/// - `scope` 可选；省略时 IdP 沿用上次授权的 scope
///
/// 上游 CodeWhisperer 调用侧另需配合 `TokenType: EXTERNAL_IDP` 请求头，详见
/// [`KiroCredentials::is_external_idp`] 调用点（endpoint/ide.rs / endpoint/cli.rs /
/// token_manager 内 REST 调用）。
async fn refresh_external_idp_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 External IdP Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let client_id = credentials
        .client_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("External IdP 刷新需要 clientId"))?;
    let token_endpoint = credentials
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("External IdP 刷新需要 tokenEndpoint"))?;
    let client_secret = credentials.client_secret.as_deref();
    let scope = credentials.scopes.as_deref();

    let client = build_client(proxy, 60, config.tls_backend)?;
    let form = ExternalIdpRefreshForm {
        grant_type: "refresh_token",
        client_id,
        refresh_token,
        client_secret,
        scope,
    };

    // 与 Kiro IDE 行为对齐：use 默认 reqwest UA + 无需 AWS SDK headers。
    let response = client
        .post(token_endpoint)
        .header("accept", "application/json")
        .form(&form)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        // 解析 RFC 6749 标准错误码：`invalid_grant` → refreshToken 永久失效
        if status.as_u16() == 400 || status.as_u16() == 401 {
            if let Ok(err) = serde_json::from_str::<ExternalIdpErrorResponse>(&body_text) {
                if err.error.eq_ignore_ascii_case("invalid_grant") {
                    return Err(RefreshTokenInvalidError {
                        message: format!(
                            "External IdP refreshToken 已失效 (invalid_grant): {}",
                            body_text
                        ),
                    }
                    .into());
                }
            }
        }

        let error_msg = match status.as_u16() {
            400 => "External IdP 刷新参数无效",
            401 => "External IdP 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被 IdP 限流",
            500..=599 => "服务器错误，External IdP 服务暂时不可用",
            _ => "External IdP Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: ExternalIdpRefreshResponse = response.json().await?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    Ok(new_credentials)
}

/// 官方 Kiro 用量 / 模型 REST 接口（getUsageLimits / ListAvailableModels /
/// setUserPreference）仅在 `us-east-1` 与 `eu-central-1` 两个端点提供服务。
///
/// 依据凭据的 SSO 区域选择主端点，并返回另一个端点作为 403 回退候选：
/// - `eu-central-1` 或任何 `eu-*` 区域 → 主端点 `eu-central-1`
/// - 其余区域 → 主端点 `us-east-1`
///
/// 这样导入的 Enterprise / IAM Identity Center (IdC) 账号即使 SSO 区域不是
/// `us-east-1`，也能命中正确的端点，避免 `403 {"message":"Invalid token"}`。
fn rest_api_region_candidates(sso_region: &str) -> [&'static str; 2] {
    let primary_eu = sso_region == "eu-central-1" || sso_region.starts_with("eu-");
    if primary_eu {
        ["eu-central-1", "us-east-1"]
    } else {
        ["us-east-1", "eu-central-1"]
    }
}

/// 获取使用额度信息
pub(crate) async fn get_usage_limits(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<UsageLimitsResponse> {
    tracing::debug!("正在获取使用额度信息...");

    // getUsageLimits 仅在 us-east-1 / eu-central-1 提供服务，
    // 依据凭据 SSO 区域选择主端点，403 时回退到另一个端点。
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    // 用量类接口固定用 USAGE_API_KIRO_VERSION：新版 IDE 会强制要求 profileArn，
    // 对 Enterprise/IdC 账号失败；该版本无需 profileArn。
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    // profileArn 查询串：仅发送真实 ARN，跳过 BuilderID 占位符
    let profile_arn_query = credentials
        .effective_profile_arn()
        .map(|arn| format!("&profileArn={}", urlencoding::encode(arn)))
        .unwrap_or_default();

    // 构建 User-Agent headers
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    let mut last_error: Option<String> = None;
    for (idx, region) in candidates.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!(
            "https://{}/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true{}",
            host, profile_arn_query
        );

        let mut request = client
            .get(&url)
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close");

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        } else if credentials.is_external_idp() {
            request = request.header("TokenType", "EXTERNAL_IDP");
        }

        let response = request.send().await?;

        let status = response.status();
        if status.is_success() {
            let data: UsageLimitsResponse = response.json().await?;
            return Ok(data);
        }

        let body_text = response.text().await.unwrap_or_default();

        // 403 且仍有备用端点时，尝试下一个区域端点（Enterprise/IdC 跨区兼容）
        if status.as_u16() == 403 && idx + 1 < candidates.len() {
            tracing::debug!(
                "getUsageLimits 在 {} 返回 403，尝试备用端点 {}",
                region,
                candidates[idx + 1]
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        let error_msg = match status.as_u16() {
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法获取使用额度",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "获取使用额度失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    // 所有候选端点均失败（理论上循环内已 return / bail，此处为兜底）
    bail!(
        "权限不足，无法获取使用额度: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 获取该凭据当前可用的模型列表
///
/// 上游接口：`GET https://q.{api_region}.amazonaws.com/ListAvailableModels?origin=AI_EDITOR`
/// 返回值随订阅等级不同而不同（如 FREE 账号不含 Opus）。
/// 请求头与构造方式与 [`get_usage_limits`] 完全一致。
pub(crate) async fn get_available_models(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ListAvailableModelsResponse> {
    tracing::debug!("正在获取可用模型列表...");

    // ListAvailableModels 仅在 us-east-1 / eu-central-1 提供服务，
    // 依据凭据 SSO 区域选择主端点，403 时回退到另一个端点。
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    // profileArn 查询串：仅发送真实 ARN，跳过 BuilderID 占位符
    let profile_arn_query = credentials
        .effective_profile_arn()
        .map(|arn| format!("&profileArn={}", urlencoding::encode(arn)))
        .unwrap_or_default();

    // 构建 User-Agent headers（与 get_usage_limits 保持一致）
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    let mut last_error: Option<String> = None;
    for (idx, region) in candidates.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!(
            "https://{}/ListAvailableModels?origin=AI_EDITOR{}",
            host, profile_arn_query
        );

        let mut request = client
            .get(&url)
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close");

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        } else if credentials.is_external_idp() {
            request = request.header("TokenType", "EXTERNAL_IDP");
        }

        let response = request.send().await?;

        let status = response.status();
        if status.is_success() {
            let data: ListAvailableModelsResponse = response.json().await?;
            return Ok(data);
        }

        let body_text = response.text().await.unwrap_or_default();

        // 403 且仍有备用端点时，尝试下一个区域端点（Enterprise/IdC 跨区兼容）
        if status.as_u16() == 403 && idx + 1 < candidates.len() {
            tracing::debug!(
                "ListAvailableModels 在 {} 返回 403，尝试备用端点 {}",
                region,
                candidates[idx + 1]
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        let error_msg = match status.as_u16() {
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法获取可用模型",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "获取可用模型失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    // 所有候选端点均失败（理论上循环内已 return / bail，此处为兜底）
    bail!(
        "权限不足，无法获取可用模型: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 获取该凭据可用的真实 profileArn 列表（`ListAvailableProfiles`）。
///
/// Enterprise / IAM Identity Center (IdC) 账号必须用真实 profileArn 调用流式端点；
/// 该 ARN 既不是 BuilderID 占位符，也不在 OIDC 刷新响应里返回，只能通过本接口获取。
///
/// 上游接口（AWS JSON 1.0，**与用量类的 REST GET 不同**）：
/// `POST https://q.{region}.amazonaws.com/`，请求头
/// `x-amz-target: AmazonCodeWhispererService.ListAvailableProfiles`，
/// `Content-Type: application/x-amz-json-1.0`，Body `{"maxResults":N}`。
///
/// 与 [`get_usage_limits`] 一样仅在 `us-east-1` / `eu-central-1` 提供服务，
/// 依据凭据 SSO 区域选择主端点，主端点未返回 profile 时回退到另一个端点。
pub(crate) async fn list_available_profiles(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ListAvailableProfilesResponse> {
    tracing::debug!("正在获取可用 profile 列表...");

    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    let mut last_error: Option<String> = None;
    let mut empty_seen = false;
    for region in candidates.iter() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!("https://{}/", host);

        let mut request = client
            .post(&url)
            .header("content-type", "application/x-amz-json-1.0")
            .header(
                "x-amz-target",
                "AmazonCodeWhispererService.ListAvailableProfiles",
            )
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close")
            .body(r#"{"maxResults":10}"#);

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        } else if credentials.is_external_idp() {
            request = request.header("TokenType", "EXTERNAL_IDP");
        }

        let response = request.send().await?;
        let status = response.status();

        if status.is_success() {
            let data: ListAvailableProfilesResponse = response.json().await?;
            // 该区域无 profile 时尝试另一个区域端点（账号可能在 eu-central-1）
            if data.first_arn().is_none() {
                empty_seen = true;
                continue;
            }
            return Ok(data);
        }

        let body_text = response.text().await.unwrap_or_default();
        last_error = Some(format!("{} {}", status, body_text));
        // 403 等错误继续尝试下一个候选端点
    }

    // 没有任何端点返回 profile：若至少有一次成功但为空，视为"该账号无 Enterprise profile"
    // （BuilderID 等），返回空结果让调用方回退到占位符逻辑。
    if empty_seen {
        return Ok(ListAvailableProfilesResponse::default());
    }

    bail!(
        "获取可用 profile 失败: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 设置用户偏好（开启/关闭超额）
///
/// 上游接口：`POST https://q.{region}.amazonaws.com/setUserPreference`
/// Body: `{ "overageConfiguration": { "overageStatus": "ENABLED" | "DISABLED" }, "profileArn": "..." }`
pub(crate) async fn set_user_preference(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
    overage_status: &str, // "ENABLED" or "DISABLED"
) -> anyhow::Result<()> {
    tracing::debug!("正在设置用户偏好 overageStatus={}", overage_status);

    // setUserPreference 仅在 us-east-1 / eu-central-1 提供服务，
    // 依据凭据 SSO 区域选择主端点，403 时回退到另一个端点。
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!("aws-sdk-js/1.0.0 KiroIDE-{}-{}", kiro_version, machine_id);

    let client = build_client(proxy, 60, config.tls_backend)?;

    // 构建 body：仅发送真实 profileArn，跳过 BuilderID 占位符
    let body = if let Some(profile_arn) = credentials.effective_profile_arn() {
        serde_json::json!({
            "overageConfiguration": { "overageStatus": overage_status },
            "profileArn": profile_arn,
        })
    } else {
        serde_json::json!({
            "overageConfiguration": { "overageStatus": overage_status },
        })
    };

    let mut last_error: Option<String> = None;
    for (idx, region) in candidates.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!("https://{}/setUserPreference", host);

        let mut request = client
            .post(&url)
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("content-type", "application/json")
            .header("Connection", "close")
            .json(&body);

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        } else if credentials.is_external_idp() {
            request = request.header("TokenType", "EXTERNAL_IDP");
        }

        let response = request.send().await?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let body_text = response.text().await.unwrap_or_default();

        // 403 且仍有备用端点时，尝试下一个区域端点（Enterprise/IdC 跨区兼容）
        if status.as_u16() == 403 && idx + 1 < candidates.len() {
            tracing::debug!(
                "setUserPreference 在 {} 返回 403，尝试备用端点 {}",
                region,
                candidates[idx + 1]
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        let error_msg = match status.as_u16() {
            400 => "请求参数错误，账号可能不支持超额",
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法设置用户偏好",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "设置用户偏好失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    // 所有候选端点均失败（理论上循环内已 return / bail，此处为兜底）
    bail!(
        "权限不足，无法设置用户偏好: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

// ============================================================================
// 多凭据 Token 管理器
// ============================================================================

/// 单个凭据条目的状态
struct CredentialEntry {
    /// 凭据唯一 ID
    id: u64,
    /// 凭据信息
    credentials: KiroCredentials,
    /// API 调用连续失败次数
    failure_count: u32,
    /// API 调用累计失败次数（含所有失败类型：鉴权/额度/风控/瞬态/网络）。
    /// 只增不减，成功不清零，仅手动重置失败计数时归零。仅用于展示与排查。
    total_failure_count: u64,
    /// Token 刷新连续失败次数
    refresh_failure_count: u32,
    /// 是否已禁用
    disabled: bool,
    /// 禁用原因（用于区分手动禁用 vs 自动禁用，便于自愈）
    disabled_reason: Option<DisabledReason>,
    /// API 调用成功次数
    success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    last_used_at: Option<String>,
    /// 临时冷却到期时间（账号级 429 风控触发后短期跳过该凭据）
    /// `Some(t)` 且 `t > now()` 时视为不可用；`t <= now()` 时自动恢复。
    /// 不持久化，进程重启后清空。
    throttled_until: Option<Instant>,
    /// 错误事件滑动窗口（429 / 5xx 时间戳）。
    /// 配合 `effective_cooldown_policy.error_window_secs / error_threshold` 实现
    /// "M 分钟内 N 次错误才触发冷却"——避免单次抖动惩罚长期健康号。
    /// 不持久化。
    throttle_events: VecDeque<Instant>,
    /// 累计触发冷却的时间戳（每次冷却生效时 push 一次）。
    /// 配合 `disable_window_secs / auto_disable_after_trips` 实现"反复触发自动 disable"，
    /// 避免长期慢号反复短冷却循环。不持久化。
    trip_events: VecDeque<Instant>,
    /// 当前进行中（in-flight）的请求数。由 `ConcurrencySlot` RAII 守卫增减：
    /// 请求占用该凭据时 +1，请求结束（成功/失败/网络错误/流式结束）时自动 -1。
    /// 运行时易失指标，不持久化。用 `Arc<AtomicU32>` 以便守卫脱离 entries 锁独立持有。
    in_flight: Arc<AtomicU32>,
    /// 请求耗时滑动平均（毫秒，EWMA α=0.2）。仅成功请求更新。运行时易失指标。
    ewma_latency_ms: Option<f64>,
    /// 计价请求数（credits > 0 的请求累计）。运行时易失指标。
    billed_requests: u64,
    /// 累计 credits 成本（本地估算）。运行时易失指标。
    accrued_cost: f64,
    /// 累计被调度（acquire_context 成功命中）次数。运行时易失指标。
    total_dispatch: u64,
    /// 最近调度时间戳环形缓冲（上限 1000，超限弹出最旧）。
    /// 用于计算 10s/60s/5m 窗口的近期调度数。运行时易失指标。
    dispatch_times: VecDeque<Instant>,
    /// 最近一次预热完成的时刻。用于前端展示「已预热」临时标签（10 分钟内）。
    /// 运行时易失指标，不持久化。
    last_warmup_at: Option<Instant>,
}

/// 禁用原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisabledReason {
    /// Admin API 手动禁用
    Manual,
    /// 连续失败达到阈值后自动禁用
    TooManyFailures,
    /// Token 刷新连续失败达到阈值后自动禁用
    TooManyRefreshFailures,
    /// 额度已用尽（如 MONTHLY_REQUEST_COUNT）
    QuotaExceeded,
    /// Refresh Token 永久失效（服务端返回 invalid_grant）
    InvalidRefreshToken,
    /// 凭据配置无效（如 authMethod=api_key 但缺少 kiroApiKey）
    InvalidConfig,
    /// 错误冷却策略累计触发达阈值后自动禁用（"反复触发"自愈兜底）。
    /// 与 `TooManyFailures` 区分：基于"触发冷却次数"，而非"连续失败次数"。
    AutoThrottled,
}

/// 统计数据持久化条目
#[derive(Serialize, Deserialize)]
struct StatsEntry {
    success_count: u64,
    #[serde(default)]
    total_failure_count: u64,
    last_used_at: Option<String>,
}

// ============================================================================
// Admin API 公开结构
// ============================================================================

/// 凭据条目快照（用于 Admin API 读取）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialEntrySnapshot {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 累计失败次数（所有失败类型，只增不减，仅手动重置归零）
    pub total_failure_count: u64,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 身份提供商（BuilderId / Enterprise / Github / Google / IAM_SSO）
    pub provider: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
    /// Token 过期时间
    pub expires_at: Option<String>,
    /// refreshToken 的 SHA-256 哈希（仅 OAuth 凭据，用于前端去重）
    pub refresh_token_hash: Option<String>,
    /// kiroApiKey 的 SHA-256 哈希（仅 API Key 凭据，用于前端去重）
    pub api_key_hash: Option<String>,
    /// kiroApiKey 的脱敏展示（仅 API Key 凭据，用于前端显示）
    pub masked_api_key: Option<String>,
    /// 用户邮箱（用于前端显示）
    pub email: Option<String>,
    /// API 调用成功次数
    pub success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    pub last_used_at: Option<String>,
    /// 是否配置了凭据级代理
    pub has_proxy: bool,
    /// 代理 URL（用于前端展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Token 刷新连续失败次数
    pub refresh_failure_count: u32,
    /// 禁用原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// 临时冷却剩余秒数（账号级 429 风控）；冷却中且 `> 0` 才返回
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttled_remaining_secs: Option<u64>,
    /// 端点名称（未显式配置时返回 None，由 Admin 层回退到默认值）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// 账号所属分组（可属于多个分组）
    #[serde(default)]
    pub groups: Vec<String>,
    /// 账号来源渠道（纯备注）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_channel: Option<String>,
    /// 当前进行中（in-flight）的请求数（运行时易失指标）
    pub in_flight: u32,
    /// 有效并发上限（凭据级覆盖优先，否则全局默认）
    pub concurrency_limit: u32,
    /// 凭据级并发上限覆盖原始值（None = 未覆盖，用全局默认；用于编辑回填）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency_limit_override: Option<u32>,
    /// 请求耗时滑动平均（毫秒，EWMA）；无样本时 None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ewma_latency_ms: Option<f64>,
    /// 计价请求数（credits>0 的请求累计）
    pub billed_requests: u64,
    /// 累计 credits 成本（本地估算）
    pub accrued_cost: f64,
    /// 累计被调度次数
    pub total_dispatch: u64,
    /// 近期调度数（最近 10 秒）
    pub recent_dispatch_10s: u32,
    /// 近期调度数（最近 60 秒）
    pub recent_dispatch_60s: u32,
    /// 近期调度数（最近 5 分钟）
    pub recent_dispatch_5m: u32,
    /// 调度评分（越高越健康）：成功率*100 + 剩余并发奖励 - EWMA惩罚
    pub dispatch_score: f64,
    /// 调度压力（越高越忙）：60s 调度数 / 有效并发上限
    pub dispatch_pressure: f64,
    /// 最近 10 分钟内是否预热过（用于前端「已预热」临时标签）
    pub warmed_recently: bool,
}

/// 凭据管理器状态快照
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagerSnapshot {
    /// 凭据条目列表
    pub entries: Vec<CredentialEntrySnapshot>,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 总凭据数量
    pub total: usize,
    /// 可用凭据数量
    pub available: usize,
}

/// 多凭据 Token 管理器
///
/// 支持多个凭据的管理，实现固定优先级 + 故障转移策略
/// 故障统计基于 API 调用结果，而非 Token 刷新结果
pub struct MultiTokenManager {
    config: Config,
    /// 全局代理（运行时可修改）
    proxy: Mutex<Option<ProxyConfig>>,
    /// 凭据条目列表
    entries: Mutex<Vec<CredentialEntry>>,
    /// 当前活动凭据 ID
    current_id: Mutex<u64>,
    /// 下一个待分配凭据 ID。进程内单调递增，避免删除账号后新账号复用旧 ID，
    /// 从而继承旧账号按 credential_id 聚合的 trace/usage 历史。
    next_id: AtomicU64,
    /// Token 刷新锁，确保同一时间只有一个刷新操作
    refresh_lock: TokioMutex<()>,
    /// 凭据文件路径（用于回写）
    credentials_path: Option<PathBuf>,
    /// 凭据文件写入锁。`persist_credentials` 用整文件覆写，并发调用会互相踩踏，
    /// 故用此锁串行化所有写盘操作（批量导入等场景会并发触发）。
    persist_lock: Mutex<()>,
    /// 是否为多凭据格式（数组格式才回写；通过 add_credential 动态升级为 true）
    is_multiple_format: AtomicBool,
    /// 负载均衡模式（运行时可修改）
    load_balancing_mode: Mutex<String>,
    /// 默认起点端点名（运行时可修改）。未在凭据级单独配 endpoint 的请求用此值。
    default_endpoint: Mutex<String>,
    /// runtime → ide 自动降级开关（运行时可修改）。false 时 fallback_endpoint 直接返回 None。
    runtime_fallback_enabled: AtomicBool,
    /// 账号级 429 风控故障转移开关（运行时可修改）
    account_throttle_failover: AtomicBool,
    /// 账号级风控冷却时长（秒，运行时可修改）
    account_throttle_cooldown_secs: AtomicU64,
    /// 最近一次统计持久化时间（用于 debounce）
    last_stats_save_at: Mutex<Option<Instant>>,
    /// 统计数据是否有未落盘更新
    stats_dirty: AtomicBool,
    /// Session-Sticky 映射：conversationId → 上次使用的凭据 ID。
    /// 同一会话粘同一凭据 → 上游 prompt cache 前缀复用率从 ~60% 拉到 ~90%。
    sticky_map: Mutex<HashMap<String, StickyEntry>>,
    /// 分组注册表（构造后通过 [`register_group_manager`] 注入）。
    /// 用于按分组查 `cacheMode` 覆盖；未注入或不命中时回退到 [`Config::cache_mode_default`]。
    group_manager: OnceLock<SharedGroupManager>,
}

/// Session-Sticky 条目
struct StickyEntry {
    credential_id: u64,
    last_used: Instant,
}

/// 每个凭据最大 API 调用失败次数
const MAX_FAILURES_PER_CREDENTIAL: u32 = 3;
/// 统计数据持久化防抖间隔
const STATS_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(30);

/// 并发槽位 RAII 守卫
///
/// 构造时对账号的 `in_flight` 计数 +1，`Drop` 时自动 -1。绑定到 `CallContext`，
/// 随请求生命周期存活——流式请求时随 stream 移动，确保流结束（ctx 析构）才释放。
///
/// 用 Drop 而非显式 report_* 释放，是因为请求结束路径分散（成功/各类失败/
/// **网络错误路径故意不调用 report**），只有 RAII 能保证所有路径都精确释放、不泄漏。
pub struct ConcurrencySlot {
    counter: Arc<AtomicU32>,
}

impl ConcurrencySlot {
    /// 占用一个并发槽位：对计数 +1。
    fn acquire(counter: Arc<AtomicU32>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        ConcurrencySlot { counter }
    }
}

impl Drop for ConcurrencySlot {
    fn drop(&mut self) {
        // saturating：即便 clear-concurrency 把计数清零后槽位再析构，也不会回绕到 u32::MAX
        let prev = self.counter.load(Ordering::SeqCst);
        if prev > 0 {
            self.counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// API 调用上下文
///
/// 绑定特定凭据的调用上下文，确保 token、credentials 和 id 的一致性
/// 用于解决并发调用时 current_id 竞态问题
pub struct CallContext {
    /// 凭据 ID（用于 report_success/report_failure）
    pub id: u64,
    /// 凭据信息（用于构建请求头）
    pub credentials: KiroCredentials,
    /// 访问 Token
    pub token: String,
    /// 并发槽位守卫。`None` 仅用于不计并发的内部场景（如测活/预热可自行决定）；
    /// 正常请求路径由 `acquire_context` 注入 `Some(slot)`，请求结束时随 ctx 析构释放。
    pub _slot: Option<ConcurrencySlot>,
}

/// 统计时间戳缓冲中落在最近 `window_secs` 秒内的数量。
fn count_recent(times: &VecDeque<Instant>, now: Instant, window_secs: u64) -> u32 {
    let window = StdDuration::from_secs(window_secs);
    times
        .iter()
        .filter(|t| now.duration_since(**t) <= window)
        .count() as u32
}

/// 计算调度评分（越高越健康）。
///
/// `成功率*100 + 剩余并发奖励 - EWMA惩罚`：
/// - 成功率 = success / (success + total_failure)，无样本视为 1.0
/// - 剩余并发奖励 = (limit - in_flight) / limit * 20（空闲越多越优先）
/// - EWMA 惩罚 = min(ewma_ms / 100, 50)（越慢扣越多，封顶 50）
fn compute_dispatch_score(
    success: u64,
    total_failure: u64,
    in_flight: u32,
    limit: u32,
    ewma_latency_ms: Option<f64>,
) -> f64 {
    let total = success + total_failure;
    let success_rate = if total == 0 {
        1.0
    } else {
        success as f64 / total as f64
    };
    let limit_f = limit.max(1) as f64;
    let free = (limit_f - in_flight as f64).max(0.0);
    let concurrency_bonus = free / limit_f * 20.0;
    let ewma_penalty = ewma_latency_ms.map(|e| (e / 100.0).min(50.0)).unwrap_or(0.0);
    let score = success_rate * 100.0 + concurrency_bonus - ewma_penalty;
    (score * 100.0).round() / 100.0
}

/// 判断某账号的分组集合是否匹配请求所属分组（严格隔离）
///
/// - `group = None`：Key 未绑定分组（含 master apiKey），匹配所有账号。
/// - `group = Some(g)`：仅匹配 `cred_groups` 包含 `g` 的账号。
fn group_matches(cred_groups: &[String], group: Option<&str>) -> bool {
    match group {
        None => true,
        Some(g) => cred_groups.iter().any(|cg| cg == g),
    }
}

fn credential_matches_request(
    credentials: &KiroCredentials,
    model: Option<&str>,
    group: Option<&str>,
) -> bool {
    let is_opus = model
        .map(|m| m.to_ascii_lowercase().contains("opus"))
        .unwrap_or(false);

    if is_opus && !credentials.supports_opus() {
        return false;
    }

    group_matches(&credentials.groups, group)
}

impl MultiTokenManager {
    /// 创建多凭据 Token 管理器
    ///
    /// # Arguments
    /// * `config` - 应用配置
    /// * `credentials` - 凭据列表
    /// * `proxy` - 可选的代理配置
    /// * `credentials_path` - 凭据文件路径（用于回写）
    /// * `is_multiple_format` - 是否为多凭据格式（数组格式才回写）
    pub fn new(
        config: Config,
        credentials: Vec<KiroCredentials>,
        proxy: Option<ProxyConfig>,
        credentials_path: Option<PathBuf>,
        is_multiple_format: bool,
    ) -> anyhow::Result<Self> {
        // 计算当前最大 ID，为没有 ID 的凭据分配新 ID
        let max_existing_id = credentials.iter().filter_map(|c| c.id).max().unwrap_or(0);
        let mut next_id = max_existing_id + 1;
        let mut has_new_ids = false;
        let mut has_new_machine_ids = false;
        let config_ref = &config;

        let entries: Vec<CredentialEntry> = credentials
            .into_iter()
            .map(|mut cred| {
                cred.canonicalize_auth_method();
                let id = cred.id.unwrap_or_else(|| {
                    let id = next_id;
                    next_id += 1;
                    cred.id = Some(id);
                    has_new_ids = true;
                    id
                });
                if cred.fill_default_profile_arn() {
                    has_new_ids = true;
                }
                if cred.machine_id.is_none() {
                    cred.machine_id =
                        Some(machine_id::generate_from_credentials(&cred, config_ref));
                    has_new_machine_ids = true;
                }
                CredentialEntry {
                    id,
                    credentials: cred.clone(),
                    failure_count: 0,
                    total_failure_count: 0,
                    refresh_failure_count: 0,
                    disabled: cred.disabled, // 从配置文件读取 disabled 状态
                    disabled_reason: if cred.disabled {
                        Some(DisabledReason::Manual)
                    } else {
                        None
                    },
                    success_count: 0,
                    last_used_at: None,
                    throttled_until: None,
                    throttle_events: VecDeque::new(),
                    trip_events: VecDeque::new(),
                    in_flight: Arc::new(AtomicU32::new(0)),
                    ewma_latency_ms: None,
                    billed_requests: 0,
                    accrued_cost: 0.0,
                    total_dispatch: 0,
                    dispatch_times: VecDeque::new(),
                    last_warmup_at: None,
                }
            })
            .collect();

        // 校验 API Key 凭据配置完整性：authMethod=api_key 时必须提供 kiroApiKey
        let mut entries = entries;
        for entry in &mut entries {
            if entry.credentials.kiro_api_key.is_none()
                && entry
                    .credentials
                    .auth_method
                    .as_deref()
                    .map(|m| m.eq_ignore_ascii_case("api_key") || m.eq_ignore_ascii_case("apikey"))
                    .unwrap_or(false)
            {
                tracing::warn!(
                    "凭据 #{} 配置了 authMethod=api_key 但缺少 kiroApiKey 字段，已自动禁用",
                    entry.id
                );
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::InvalidConfig);
            }
        }

        // 检测重复 ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut duplicate_ids = Vec::new();
        for entry in &entries {
            if !seen_ids.insert(entry.id) {
                duplicate_ids.push(entry.id);
            }
        }
        if !duplicate_ids.is_empty() {
            anyhow::bail!("检测到重复的凭据 ID: {:?}", duplicate_ids);
        }

        // 选择初始凭据：优先级最高（priority 最小）的可用凭据，无可用凭据时为 0
        let initial_id = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
            .map(|e| e.id)
            .unwrap_or(0);

        let load_balancing_mode = config.load_balancing_mode.clone();
        let default_endpoint = config.default_endpoint.clone();
        let runtime_fallback_enabled = config.runtime_fallback_enabled;
        let throttle_failover = config.account_throttle_failover;
        let throttle_cooldown_secs = config.account_throttle_cooldown_secs;
        let manager = Self {
            config,
            proxy: Mutex::new(proxy),
            entries: Mutex::new(entries),
            current_id: Mutex::new(initial_id),
            next_id: AtomicU64::new(next_id),
            refresh_lock: TokioMutex::new(()),
            credentials_path,
            persist_lock: Mutex::new(()),
            is_multiple_format: AtomicBool::new(is_multiple_format),
            load_balancing_mode: Mutex::new(load_balancing_mode),
            default_endpoint: Mutex::new(default_endpoint),
            runtime_fallback_enabled: AtomicBool::new(runtime_fallback_enabled),
            account_throttle_failover: AtomicBool::new(throttle_failover),
            account_throttle_cooldown_secs: AtomicU64::new(throttle_cooldown_secs),
            last_stats_save_at: Mutex::new(None),
            stats_dirty: AtomicBool::new(false),
            sticky_map: Mutex::new(HashMap::new()),
            group_manager: OnceLock::new(),
        };

        // 单凭据格式自动迁移：升级为数组格式，确保 token rotation 能写盘
        // 触发条件：原文件是单对象格式 && 存在凭据 && 有文件路径
        if !is_multiple_format
            && !manager.entries.lock().is_empty()
            && manager.credentials_path.is_some()
        {
            manager.is_multiple_format.store(true, Ordering::Relaxed);
            if let Err(e) = manager.persist_credentials() {
                tracing::warn!("单凭据格式迁移到数组格式失败: {}", e);
            } else {
                tracing::info!(
                    "已将凭据文件从单对象格式迁移到数组格式，token rotation 将正确持久化"
                );
            }
        }

        // 如果有新分配的 ID 或新生成的 machineId，立即持久化到配置文件
        if has_new_ids || has_new_machine_ids {
            if let Err(e) = manager.persist_credentials() {
                tracing::warn!("补全凭据 ID/machineId 后持久化失败: {}", e);
            } else {
                tracing::info!("已补全凭据 ID/machineId 并写回配置文件");
            }
        }

        // 加载持久化的统计数据（success_count, last_used_at）
        manager.load_stats();

        Ok(manager)
    }

    /// 获取配置的引用
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 注入分组注册表（运行时只能调一次；重复调用静默忽略）。
    ///
    /// 用 `OnceLock` 是因为 `MultiTokenManager` 在 `main.rs` 中比 `GroupManager` 先构造，
    /// 无法走构造参数注入。等到两者都就绪后，main 调一次此方法把分组管理器交给我们。
    pub fn register_group_manager(&self, mgr: SharedGroupManager) {
        if self.group_manager.set(mgr).is_err() {
            tracing::warn!("register_group_manager 被重复调用，已忽略");
        }
    }

    /// 解析某分组实际生效的缓存命中档：
    /// 1. 若分组存在且有 `cacheMode` 覆盖 → 用覆盖值
    /// 2. 否则回退到 `Config::cache_mode_default`
    ///
    /// `group = None`（请求未指定分组）也走全局默认。
    /// 若 `group_manager` 尚未注入（异常路径），同样走全局默认（不影响功能，只是分组覆盖不生效）。
    fn resolve_cache_mode(&self, group: Option<&str>) -> CacheMode {
        group
            .and_then(|g| {
                self.group_manager
                    .get()
                    .and_then(|gm| gm.get(g))
                    .and_then(|grp| grp.cache_mode)
            })
            .unwrap_or(self.config.cache_mode_default)
    }

    /// 解析某分组实际生效的上下文压缩阈值。
    /// 同 `resolve_cache_mode`：分组覆盖 → 全局默认；结果钳制在 [0.5, 1.0]。
    pub fn resolve_compact_threshold(&self, group: Option<&str>) -> f32 {
        let raw = group
            .and_then(|g| {
                self.group_manager
                    .get()
                    .and_then(|gm| gm.get(g))
                    .and_then(|grp| grp.compact_threshold)
            })
            .unwrap_or(self.config.context_compact_threshold_default);
        raw.clamp(0.5, 1.0)
    }

    /// 全局默认压缩阈值（Admin API）
    pub fn get_compact_threshold_default(&self) -> f32 {
        self.config.context_compact_threshold_default.clamp(0.5, 1.0)
    }

    /// 设置全局默认压缩阈值（Admin API）。运行时立即生效 + 持久化。
    pub fn set_compact_threshold_default(&self, threshold: f32) -> anyhow::Result<()> {
        if !(0.5..=1.0).contains(&threshold) {
            anyhow::bail!("阈值必须在 0.5 ~ 1.0 之间，收到: {}", threshold);
        }
        use anyhow::Context;
        let config_path = match self.config.config_path() {
            Some(p) => p.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，全局压缩阈值仅在当前进程不生效（无字段缓存）");
                return Ok(());
            }
        };
        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.context_compact_threshold_default = threshold;
        config
            .save()
            .with_context(|| format!("持久化全局压缩阈值失败: {}", config_path.display()))?;
        // 注意：当前 self.config 是构造期克隆，运行时不持久写回到结构体。
        // 此处仅写盘，下次启动加载。如果要做运行时热更，需要把 context_compact_threshold_default
        // 也提到 AtomicU32 / Mutex<f32>。目前每分组都可覆盖，全局值改动场景不频繁，暂不做。
        tracing::info!("全局上下文压缩阈值已更新到 {}（重启后生效）", threshold);
        Ok(())
    }

    /// 获取全局代理配置的克隆（可安全跨锁使用）
    pub fn proxy(&self) -> Option<ProxyConfig> {
        self.proxy.lock().clone()
    }

    /// 设置全局代理配置（运行时修改，可传 None 清除）
    pub fn set_global_proxy(&self, proxy: Option<ProxyConfig>) {
        *self.proxy.lock() = proxy;
    }

    /// 获取凭据总数
    pub fn total_count(&self) -> usize {
        self.entries.lock().len()
    }

    /// 获取指定分组的凭据总数（group=None 时等于 total_count）
    ///
    /// 用于按分组计算 failover 重试预算，避免小分组按全局账号数获得过多无效重试。
    pub fn total_count_in_group(&self, group: Option<&str>) -> usize {
        self.entries
            .lock()
            .iter()
            .filter(|e| group_matches(&e.credentials.groups, group))
            .count()
    }

    /// 获取可用凭据数量
    pub fn available_count(&self) -> usize {
        let now = Instant::now();
        self.entries
            .lock()
            .iter()
            .filter(|e| !e.disabled && !e.throttled_until.map(|t| t > now).unwrap_or(false))
            .count()
    }

    /// 计算某账号的有效并发上限：凭据级 `concurrency_limit` 覆盖优先，
    /// 否则回退到全局 `Config.default_concurrency_limit`。结果至少为 1。
    fn effective_concurrency_limit(&self, entry: &CredentialEntry) -> u32 {
        entry
            .credentials
            .concurrency_limit
            .unwrap_or(self.config.default_concurrency_limit)
            .max(1)
    }

    /// 取某账号的 `in_flight` 计数器 Arc（克隆），用于构造并发槽位守卫。
    /// 账号不存在时返回 None。
    fn in_flight_counter(&self, id: u64) -> Option<Arc<AtomicU32>> {
        self.entries
            .lock()
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.in_flight.clone())
    }

    /// 强制清零某账号的并发计数（处理卡死/泄漏的槽位）。返回是否命中该账号。
    ///
    /// 注意：这是运维兜底手段。若清零时仍有真实进行中的请求，其槽位 Drop 时
    /// 会因 `prev > 0` 判断而不再下溢——计数最终仍归于一致。
    pub fn clear_concurrency(&self, id: u64) -> bool {
        let entries = self.entries.lock();
        if let Some(entry) = entries.iter().find(|e| e.id == id) {
            entry.in_flight.store(0, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// 记录一次请求结束时的性能指标（由 `UsageRecordHook` 在请求收尾时调用）。
    ///
    /// - `latency_ms`：本次请求耗时。**仅成功请求**更新 EWMA（失败耗时无参考价值，
    ///   且会被超时/重试污染）。EWMA α=0.2：`new = 0.2*x + 0.8*old`。
    /// - `credits`：本次计费量。`> 0` 才累加 `accrued_cost` 且 `billed_requests += 1`。
    pub fn record_request_metrics(&self, id: u64, latency_ms: u64, credits: f64, success: bool) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            if success {
                let x = latency_ms as f64;
                entry.ewma_latency_ms =
                    Some(entry.ewma_latency_ms.map(|o| 0.2 * x + 0.8 * o).unwrap_or(x));
            }
            if credits.is_finite() && credits > 0.0 {
                entry.accrued_cost += credits;
                entry.billed_requests += 1;
            }
        }
    }

    /// 记录一次调度（acquire_context 成功命中该账号时调用）。
    /// total_dispatch += 1，并把当前时刻压入环形缓冲（上限 1000，超限弹最旧）。
    fn record_dispatch(&self, id: u64) {
        const DISPATCH_RING_CAP: usize = 1000;
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.total_dispatch += 1;
            entry.dispatch_times.push_back(Instant::now());
            while entry.dispatch_times.len() > DISPATCH_RING_CAP {
                entry.dispatch_times.pop_front();
            }
        }
    }

    /// 标记某账号刚完成预热（记录当前时刻，供前端展示 10 分钟内的「已预热」标签）。
    pub fn mark_warmed(&self, id: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.last_warmup_at = Some(Instant::now());
        }
    }

    /// 根据负载均衡模式选择下一个凭据
    ///
    /// - priority 模式：选择优先级最高（priority 最小）的可用凭据
    /// - balanced 模式：均衡选择可用凭据
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    fn select_next_credential(&self, model: Option<&str>, group: Option<&str>) -> Option<(u64, KiroCredentials)> {
        let entries = self.entries.lock();
        let now = Instant::now();

        // 过滤可用凭据
        let available: Vec<_> = entries
            .iter()
            .filter(|e| {
                if e.disabled {
                    return false;
                }
                // 临时冷却中（账号级 429 风控）：跳过
                if e.throttled_until.map(|t| t > now).unwrap_or(false) {
                    return false;
                }
                // 模型/分组隔离：请求模型必须由该账号支持，且账号必须匹配请求分组
                if !credential_matches_request(&e.credentials, model, group) {
                    return false;
                }
                // 账号分组隔离：Key 绑定分组时只用该分组内的账号
                if !group_matches(&e.credentials.groups, group) {
                    return false;
                }
                // 并发上限：进行中请求数已达上限则跳过（满则跳过，选下一个）
                if e.in_flight.load(Ordering::SeqCst) >= self.effective_concurrency_limit(e) {
                    return false;
                }
                true
            })
            .collect();

        if available.is_empty() {
            return None;
        }

        let mode = self.load_balancing_mode.lock().clone();
        let mode = mode.as_str();

        match mode {
            "balanced" => {
                // Least-Used 策略：选择成功次数最少的凭据
                // 平局时按优先级排序（数字越小优先级越高）
                let entry = available
                    .iter()
                    .min_by_key(|e| (e.success_count, e.credentials.priority))?;

                Some((entry.id, entry.credentials.clone()))
            }
            _ => {
                // priority 模式（默认）：选择优先级最高的
                let entry = available.iter().min_by_key(|e| e.credentials.priority)?;
                Some((entry.id, entry.credentials.clone()))
            }
        }
    }

    /// 获取 API 调用上下文
    ///
    /// 返回绑定了 id、credentials 和 token 的调用上下文
    /// 确保整个 API 调用过程中使用一致的凭据信息
    ///
    /// 如果 Token 过期或即将过期，会自动刷新
    /// Token 刷新失败会累计到当前凭据，达到阈值后禁用并切换
    ///
    /// # 参数
    /// - `model`: 可选的模型名称，用于过滤支持该模型的凭据（如 opus 模型需要付费订阅）
    /// - `group`: 可选的分组名称
    /// - `sticky_id`: Session-Sticky 提示——如果有值且该凭据当前可用，优先命中它
    pub async fn acquire_context(&self, model: Option<&str>, group: Option<&str>, sticky_id: Option<u64>) -> anyhow::Result<CallContext> {
        let total = self.total_count_in_group(group);
        let max_attempts = (total * MAX_FAILURES_PER_CREDENTIAL as usize).max(1);
        let mut attempt_count = 0;

        // 缓存命中档：决定是否传 sticky_id + sticky 命中时是否放宽并发上限
        let cache_mode = self.resolve_cache_mode(group);
        let effective_sticky_id = if cache_mode == CacheMode::Off {
            None
        } else {
            sticky_id
        };

        loop {
            if attempt_count >= max_attempts {
                anyhow::bail!(
                    "所有凭据均无法获取有效 Token（可用: {}/{}）",
                    self.available_count(),
                    total
                );
            }

            let (id, credentials) = {
                let is_balanced = self.load_balancing_mode.lock().as_str() == "balanced";

                // Session-Sticky：如果传了 sticky_id，先检查该凭据是否可用
                let sticky_hit = effective_sticky_id.and_then(|sid| {
                    let entries = self.entries.lock();
                    let now = Instant::now();
                    entries
                        .iter()
                        .find(|e| {
                            // High 档：sticky 命中放宽到常规上限 ×2 强粘同号（软顶防爆）
                            // Low/Off：使用常规并发上限
                            let cap = match cache_mode {
                                CacheMode::High => {
                                    self.effective_concurrency_limit(e).saturating_mul(2)
                                }
                                _ => self.effective_concurrency_limit(e),
                            };
                            e.id == sid
                                && !e.disabled
                                && !e.throttled_until.map(|t| t > now).unwrap_or(false)
                                && credential_matches_request(&e.credentials, model, group)
                                && e.in_flight.load(Ordering::SeqCst) < cap
                        })
                        .map(|e| (e.id, e.credentials.clone()))
                });

                if let Some(hit) = sticky_hit {
                    hit
                } else {
                // balanced 模式：每次请求都重新均衡选择，不固定 current_id
                // priority 模式：优先使用 current_id 指向的凭据
                let current_hit = if is_balanced {
                    None
                } else {
                    let entries = self.entries.lock();
                    let current_id = *self.current_id.lock();
                    let now = Instant::now();
                    entries
                        .iter()
                        .find(|e| {
                            e.id == current_id
                                && !e.disabled
                                && !e.throttled_until.map(|t| t > now).unwrap_or(false)
                                && credential_matches_request(&e.credentials, model, group)
                                && e.in_flight.load(Ordering::SeqCst)
                                    < self.effective_concurrency_limit(e)
                        })
                        .map(|e| (e.id, e.credentials.clone()))
                };

                if let Some(hit) = current_hit {
                    hit
                } else {
                    // 当前凭据不可用或 balanced 模式，根据负载均衡策略选择
                    let mut best = self.select_next_credential(model, group);

                    // 没有可用凭据：如果是"自动禁用导致全灭"，做一次类似重启的自愈
                    if best.is_none() {
                        let mut entries = self.entries.lock();
                        if entries.iter().any(|e| {
                            e.disabled && e.disabled_reason == Some(DisabledReason::TooManyFailures)
                        }) {
                            tracing::warn!(
                                "所有凭据均已被自动禁用，执行自愈：重置失败计数并重新启用（等价于重启）"
                            );
                            for e in entries.iter_mut() {
                                if e.disabled_reason == Some(DisabledReason::TooManyFailures) {
                                    e.disabled = false;
                                    e.disabled_reason = None;
                                    e.failure_count = 0;
                                }
                            }
                            drop(entries);
                            best = self.select_next_credential(model, group);
                        }
                    }

                    if let Some((new_id, new_creds)) = best {
                        // 更新 current_id
                        let mut current_id = self.current_id.lock();
                        *current_id = new_id;
                        (new_id, new_creds)
                    } else {
                        let entries = self.entries.lock();
                        // 注意：必须在 bail! 之前计算 available_count，
                        // 因为 available_count() 会尝试获取 entries 锁，
                        // 而此时我们已经持有该锁，会导致死锁
                        let available = entries.iter().filter(|e| !e.disabled).count();
                        anyhow::bail!("所有凭据均已禁用（{}/{}）", available, total);
                    }
                }
                } // sticky_hit else end
            };

            // 尝试获取/刷新 Token
            match self.try_ensure_token(id, &credentials).await {
                Ok(mut ctx) => {
                    // 占用并发槽位：克隆该账号的 in_flight Arc 构造 RAII 守卫，
                    // 随 ctx 存活到请求结束（含流式流结束）才释放。
                    if let Some(counter) = self.in_flight_counter(id) {
                        ctx._slot = Some(ConcurrencySlot::acquire(counter));
                    }
                    // 记录调度（每次成功命中 +1，含后续可能失败的尝试）
                    self.record_dispatch(id);
                    return Ok(ctx);
                }
                Err(e) => {
                    let has_available = if e.downcast_ref::<RefreshTokenInvalidError>().is_some() {
                        // 先尝试从源文件重新加载（适用于 IDE 退出后 token rotation 导致失效的场景）
                        if self.try_reload_credential_from_file(id) {
                            // 找到新 Token，不计入失败次数，直接重试
                            continue;
                        }
                        tracing::warn!("凭据 #{} refreshToken 永久失效: {}", id, e);
                        self.report_refresh_token_invalid(id)
                    } else {
                        tracing::warn!("凭据 #{} Token 刷新失败: {}", id, e);
                        self.report_refresh_failure(id)
                    };
                    attempt_count += 1;
                    if !has_available {
                        anyhow::bail!("所有凭据均已禁用（0/{}）", total);
                    }
                }
            }
        }
    }

    /// 选择优先级最高的未禁用凭据作为当前凭据（内部方法）
    ///
    /// 纯粹按优先级选择，不排除当前凭据，用于优先级变更后立即生效
    fn select_highest_priority(&self) {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（不排除当前凭据）
        if let Some(best) = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
        {
            if best.id != *current_id {
                tracing::info!(
                    "优先级变更后切换凭据: #{} -> #{}（优先级 {}）",
                    *current_id,
                    best.id,
                    best.credentials.priority
                );
                *current_id = best.id;
            }
        }
    }

    /// 尝试使用指定凭据获取有效 Token
    ///
    /// 使用双重检查锁定模式，确保同一时间只有一个刷新操作
    ///
    /// # Arguments
    /// * `id` - 凭据 ID，用于更新正确的条目
    /// * `credentials` - 凭据信息
    async fn try_ensure_token(
        &self,
        id: u64,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<CallContext> {
        // API Key 凭据直接使用 kiro_api_key 作为 Bearer Token，无需刷新
        if credentials.is_api_key_credential() {
            let token = credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            return Ok(CallContext {
                id,
                credentials: credentials.clone(),
                token,
                _slot: None,
            });
        }

        // 第一次检查（无锁）：快速判断是否需要刷新
        let needs_refresh = is_token_expired(credentials) || is_token_expiring_soon(credentials);

        let creds = if needs_refresh {
            // 获取刷新锁，确保同一时间只有一个刷新操作
            let _guard = self.refresh_lock.lock().await;

            // 第二次检查：获取锁后重新读取凭据，因为其他请求可能已经完成刷新
            let current_creds = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .map(|e| e.credentials.clone())
                    .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", id))?
            };

            if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                // 确实需要刷新
                let global_proxy = self.proxy.lock().clone();
                let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                let new_creds =
                    refresh_token(&current_creds, &self.config, effective_proxy.as_ref()).await?;

                if is_token_expired(&new_creds) {
                    anyhow::bail!("刷新后的 Token 仍然无效或已过期");
                }

                // 更新凭据
                {
                    let mut entries = self.entries.lock();
                    if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                        entry.credentials = new_creds.clone();
                    }
                }

                // 回写凭据到文件（仅多凭据格式），失败只记录警告
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                }

                new_creds
            } else {
                // 其他请求已经完成刷新，直接使用新凭据
                tracing::debug!("Token 已被其他请求刷新，跳过刷新");
                current_creds
            }
        } else {
            credentials.clone()
        };

        let token = creds
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.refresh_failure_count = 0;
            }
        }

        Ok(CallContext {
            id,
            credentials: creds,
            token,
            _slot: None,
        })
    }

    /// 将凭据列表回写到源文件
    ///
    /// 仅在以下条件满足时回写：
    /// - 源文件是多凭据格式（数组）
    /// - credentials_path 已设置
    ///
    /// # Returns
    /// - `Ok(true)` - 成功写入文件
    /// - `Ok(false)` - 跳过写入（非多凭据格式或无路径配置）
    /// - `Err(_)` - 写入失败
    fn persist_credentials(&self) -> anyhow::Result<bool> {
        use anyhow::Context;

        // 仅多凭据格式才回写
        if !self.is_multiple_format.load(Ordering::Relaxed) {
            return Ok(false);
        }

        let path = match &self.credentials_path {
            Some(p) => p,
            None => return Ok(false),
        };

        // 收集所有凭据
        let credentials: Vec<KiroCredentials> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    let mut cred = e.credentials.clone();
                    cred.canonicalize_auth_method();
                    // 同步 disabled 状态到凭据对象
                    cred.disabled = e.disabled;
                    cred
                })
                .collect()
        };

        // 序列化为 pretty JSON
        let json = serde_json::to_string_pretty(&credentials).context("序列化凭据失败")?;

        // 写入文件（在 Tokio runtime 内使用 block_in_place 避免阻塞 worker）
        // 持 persist_lock 串行化整文件覆写，避免批量导入等并发场景下写盘互相踩踏。
        let _write_guard = self.persist_lock.lock();
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| std::fs::write(path, &json))
                .with_context(|| format!("回写凭据文件失败: {:?}", path))?;
        } else {
            std::fs::write(path, &json).with_context(|| format!("回写凭据文件失败: {:?}", path))?;
        }

        tracing::debug!("已回写凭据到文件: {:?}", path);
        Ok(true)
    }

    /// 尝试从凭据文件重新加载指定凭据的 Token
    ///
    /// 当 refreshToken 失效 (invalid_grant) 时，检查源文件是否已被其他客户端更新
    /// （例如本地 IDE 退出时刷新了 Token，导致 token rotation）。
    /// 如果文件中存在不同的 refreshToken，更新内存凭据并返回 true。
    ///
    /// # 匹配规则（按优先级）
    /// 1. 文件中与内存凭据 `id` 相同的条目
    /// 2. 文件中与内存凭据 `email` 相同的条目
    /// 3. 文件与内存均只有一个凭据时，直接匹配
    ///
    /// # 更新范围
    /// 仅更新 token 相关字段（refreshToken / accessToken / expiresAt），
    /// 保留代理、region、machineId 等配置不变。
    fn try_reload_credential_from_file(&self, id: u64) -> bool {
        use crate::kiro::model::credentials::CredentialsConfig;

        let path = match self.credentials_path.as_ref() {
            Some(p) => p.clone(),
            None => return false,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let file_config: CredentialsConfig = match serde_json::from_str(&content) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let file_creds = file_config.into_sorted_credentials();
        if file_creds.is_empty() {
            return false;
        }

        // 先读取当前凭据的身份信息（不持有锁，避免死锁）
        let (current_cred_id, current_email, current_refresh_token, entries_len) = {
            let entries = self.entries.lock();
            match entries.iter().find(|e| e.id == id) {
                Some(entry) => (
                    entry.credentials.id,
                    entry.credentials.email.clone(),
                    entry.credentials.refresh_token.clone(),
                    entries.len(),
                ),
                None => return false,
            }
        };

        // 从文件中查找对应凭据
        let matched = file_creds
            .iter()
            .find(|fc| {
                if fc.id.is_some() && fc.id == current_cred_id {
                    return true;
                }
                if fc.email.is_some() && fc.email == current_email {
                    return true;
                }
                false
            })
            .or_else(|| {
                if file_creds.len() == 1 && entries_len == 1 {
                    file_creds.first()
                } else {
                    None
                }
            });

        let file_cred = match matched {
            Some(c) => c,
            None => return false,
        };

        // 文件中的 refreshToken 必须存在且与当前不同，才值得更新
        if file_cred.refresh_token.is_none() || file_cred.refresh_token == current_refresh_token {
            return false;
        }

        let new_refresh_token = file_cred.refresh_token.clone();
        let new_access_token = file_cred.access_token.clone();
        let new_expires_at = file_cred.expires_at.clone();

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials.refresh_token = new_refresh_token;
                entry.credentials.access_token = new_access_token;
                entry.credentials.expires_at = new_expires_at;
                entry.disabled = false;
                entry.disabled_reason = None;
                entry.refresh_failure_count = 0;
                entry.failure_count = 0;
            }
        }

        tracing::info!(
            "凭据 #{} 从文件检测到新 refreshToken（疑似 IDE token rotation），已自动恢复，将重试",
            id
        );
        true
    }

    /// 获取缓存目录（凭据文件所在目录）
    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.credentials_path.as_ref().and_then(|p| {
            p.parent().map(|d| {
                // 当传入相对路径如 "credentials.json"（无目录前缀）时 parent 为空串，
                // 直接 join 出来的子路径会落到 CWD，且 read_dir("") 会报错导致历史日志重建为 0。
                // 这里归一化为 "."，保证 join / read_dir 行为正确。
                if d.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    d.to_path_buf()
                }
            })
        })
    }

    /// 统计数据文件路径
    fn stats_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("kiro_stats.json"))
    }

    /// 从磁盘加载统计数据并应用到当前条目
    fn load_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // 首次运行时文件不存在
        };

        let stats: HashMap<String, StatsEntry> = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("解析统计缓存失败，将忽略: {}", e);
                return;
            }
        };

        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(s) = stats.get(&entry.id.to_string()) {
                entry.success_count = s.success_count;
                entry.total_failure_count = s.total_failure_count;
                entry.last_used_at = s.last_used_at.clone();
            }
        }
        *self.last_stats_save_at.lock() = Some(Instant::now());
        self.stats_dirty.store(false, Ordering::Relaxed);
        tracing::info!("已从缓存加载 {} 条统计数据", stats.len());
    }

    /// 将当前统计数据持久化到磁盘
    fn save_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let stats: HashMap<String, StatsEntry> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    (
                        e.id.to_string(),
                        StatsEntry {
                            success_count: e.success_count,
                            total_failure_count: e.total_failure_count,
                            last_used_at: e.last_used_at.clone(),
                        },
                    )
                })
                .collect()
        };

        match serde_json::to_string_pretty(&stats) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("保存统计缓存失败: {}", e);
                } else {
                    *self.last_stats_save_at.lock() = Some(Instant::now());
                    self.stats_dirty.store(false, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!("序列化统计数据失败: {}", e),
        }
    }

    /// 标记统计数据已更新，并按 debounce 策略决定是否立即落盘
    fn save_stats_debounced(&self) {
        self.stats_dirty.store(true, Ordering::Relaxed);

        let should_flush = {
            let last = *self.last_stats_save_at.lock();
            match last {
                Some(last_saved_at) => last_saved_at.elapsed() >= STATS_SAVE_DEBOUNCE,
                None => true,
            }
        };

        if should_flush {
            self.save_stats();
        }
    }

    /// 报告指定凭据 API 调用成功
    ///
    /// 重置该凭据的失败计数
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_success(&self, id: u64) {
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.success_count += 1;
                entry.last_used_at = Some(Utc::now().to_rfc3339());
                // 成功 = 风控已解除，提前结束冷却
                entry.throttled_until = None;
                tracing::debug!(
                    "凭据 #{} API 调用成功（累计 {} 次）",
                    id,
                    entry.success_count
                );
            }
        }
        self.save_stats_debounced();
    }

    /// 报告指定凭据 API 调用失败
    ///
    /// 增加失败计数，达到阈值时禁用凭据并切换到优先级最高的可用凭据
    /// 返回是否还有可用凭据可以重试
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_failure(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.failure_count += 1;
            entry.total_failure_count += 1;
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            let failure_count = entry.failure_count;

            tracing::warn!(
                "凭据 #{} API 调用失败（{}/{}）",
                id,
                failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if failure_count >= MAX_FAILURES_PER_CREDENTIAL {
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::TooManyFailures);
                tracing::error!("凭据 #{} 已连续失败 {} 次，已被禁用", id, failure_count);

                // 切换到优先级最高的可用凭据
                if let Some(next) = entries
                    .iter()
                    .filter(|e| !e.disabled)
                    .min_by_key(|e| e.credentials.priority)
                {
                    *current_id = next.id;
                    tracing::info!(
                        "已切换到凭据 #{}（优先级 {}）",
                        next.id,
                        next.credentials.priority
                    );
                } else {
                    tracing::error!("所有凭据均已禁用！");
                }
            }

            entries.iter().any(|e| !e.disabled)
        };
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据额度已用尽
    ///
    /// 用于处理 402 Payment Required 且 reason 为 `MONTHLY_REQUEST_COUNT` 的场景：
    /// - 立即禁用该凭据（不等待连续失败阈值）
    /// - 切换到下一个可用凭据继续重试
    /// - 返回是否还有可用凭据
    pub fn report_quota_exhausted(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::QuotaExceeded);
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            // 设为阈值，便于在管理面板中直观看到该凭据已不可用
            entry.failure_count = MAX_FAILURES_PER_CREDENTIAL;
            entry.total_failure_count += 1;

            tracing::error!(
                "凭据 #{} 额度已用尽（MONTHLY_REQUEST_COUNT 或 OVERAGE_REQUEST_LIMIT_EXCEEDED），已被禁用",
                id
            );

            // 切换到优先级最高的可用凭据
            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据刷新 Token 失败。
    ///
    /// 连续刷新失败达到阈值后禁用凭据并切换，阈值内保持当前凭据不切换，
    /// 与 API 401/403 的累计失败策略保持一致。
    pub fn report_refresh_failure(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.refresh_failure_count += 1;
            let refresh_failure_count = entry.refresh_failure_count;

            tracing::warn!(
                "凭据 #{} Token 刷新失败（{}/{}）",
                id,
                refresh_failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if refresh_failure_count < MAX_FAILURES_PER_CREDENTIAL {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::TooManyRefreshFailures);

            tracing::error!(
                "凭据 #{} Token 已连续刷新失败 {} 次，已被禁用",
                id,
                refresh_failure_count
            );

            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据的 refreshToken 永久失效（invalid_grant）。
    ///
    /// 立即禁用凭据，不累计、不重试。
    /// 返回是否还有可用凭据。
    pub fn report_refresh_token_invalid(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::InvalidRefreshToken);

            tracing::error!(
                "凭据 #{} refreshToken 已失效 (invalid_grant)，已立即禁用",
                id
            );

            if let Some(next) = entries
                .iter()
                .filter(|e| !e.disabled)
                .min_by_key(|e| e.credentials.priority)
            {
                *current_id = next.id;
                tracing::info!(
                    "已切换到凭据 #{}（优先级 {}）",
                    next.id,
                    next.credentials.priority
                );
                true
            } else {
                tracing::error!("所有凭据均已禁用！");
                false
            }
        };
        self.save_stats_debounced();
        result
    }

    /// 切换到优先级最高的可用凭据
    ///
    /// 返回是否成功切换
    pub fn switch_to_next(&self) -> bool {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（排除当前凭据）
        if let Some(next) = entries
            .iter()
            .filter(|e| !e.disabled && e.id != *current_id)
            .min_by_key(|e| e.credentials.priority)
        {
            *current_id = next.id;
            tracing::info!(
                "已切换到凭据 #{}（优先级 {}）",
                next.id,
                next.credentials.priority
            );
            true
        } else {
            // 没有其他可用凭据，检查当前凭据是否可用
            entries.iter().any(|e| e.id == *current_id && !e.disabled)
        }
    }

    // ========================================================================
    // Admin API 方法
    // ========================================================================

    /// 克隆全部凭据（含敏感字段：refreshToken、accessToken、clientSecret 等）
    ///
    /// 仅用于 Admin API 导出场景，调用方需自行保证脱敏与权限控制。
    /// 返回值按调用时的顺序克隆，未做排序。
    pub fn clone_all_credentials(&self) -> Vec<KiroCredentials> {
        let entries = self.entries.lock();
        entries
            .iter()
            .map(|e| {
                let mut cred = e.credentials.clone();
                cred.canonicalize_auth_method();
                cred.disabled = e.disabled;
                cred.id = Some(e.id);
                cred
            })
            .collect()
    }

    /// 获取管理器状态快照（用于 Admin API）
    pub fn snapshot(&self) -> ManagerSnapshot {
        let entries = self.entries.lock();
        let current_id = *self.current_id.lock();
        let now = Instant::now();
        let available = entries
            .iter()
            .filter(|e| !e.disabled && !e.throttled_until.map(|t| t > now).unwrap_or(false))
            .count();

        ManagerSnapshot {
            entries: entries
                .iter()
                .map(|e| CredentialEntrySnapshot {
                    id: e.id,
                    priority: e.credentials.priority,
                    disabled: e.disabled,
                    failure_count: e.failure_count,
                    total_failure_count: e.total_failure_count,
                    auth_method: if e.credentials.is_api_key_credential() {
                        Some("api_key".to_string())
                    } else {
                        e.credentials.auth_method.as_deref().map(|m| {
                            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam")
                            {
                                "idc".to_string()
                            } else {
                                m.to_string()
                            }
                        })
                    },
                    provider: if e.credentials.is_api_key_credential() {
                        None
                    } else {
                        e.credentials.provider.clone()
                    },
                    has_profile_arn: e.credentials.profile_arn.is_some(),
                    expires_at: if e.credentials.is_api_key_credential() {
                        None // API Key 凭据本地不维护过期时间（服务端策略未知）
                    } else {
                        e.credentials.expires_at.clone()
                    },
                    refresh_token_hash: if e.credentials.is_api_key_credential() {
                        None
                    } else {
                        e.credentials.refresh_token.as_deref().map(sha256_hex)
                    },
                    api_key_hash: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(sha256_hex)
                    } else {
                        None
                    },
                    masked_api_key: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(mask_api_key)
                    } else {
                        None
                    },
                    email: e.credentials.email.clone(),
                    success_count: e.success_count,
                    last_used_at: e.last_used_at.clone(),
                    has_proxy: e.credentials.proxy_url.is_some(),
                    proxy_url: e.credentials.proxy_url.clone(),
                    refresh_failure_count: e.refresh_failure_count,
                    disabled_reason: e.disabled_reason.map(|r| {
                        match r {
                            DisabledReason::Manual => "Manual",
                            DisabledReason::TooManyFailures => "TooManyFailures",
                            DisabledReason::TooManyRefreshFailures => "TooManyRefreshFailures",
                            DisabledReason::QuotaExceeded => "QuotaExceeded",
                            DisabledReason::InvalidRefreshToken => "InvalidRefreshToken",
                            DisabledReason::InvalidConfig => "InvalidConfig",
                            DisabledReason::AutoThrottled => "AutoThrottled",
                        }
                        .to_string()
                    }),
                    throttled_remaining_secs: e
                        .throttled_until
                        .and_then(|t| t.checked_duration_since(now))
                        .map(|d| d.as_secs())
                        .filter(|s| *s > 0),
                    endpoint: e.credentials.endpoint.clone(),
                    groups: e.credentials.groups.clone(),
                    source_channel: e.credentials.source_channel.clone(),
                    in_flight: e.in_flight.load(Ordering::SeqCst),
                    concurrency_limit: e
                        .credentials
                        .concurrency_limit
                        .unwrap_or(self.config.default_concurrency_limit)
                        .max(1),
                    concurrency_limit_override: e.credentials.concurrency_limit,
                    ewma_latency_ms: e.ewma_latency_ms,
                    billed_requests: e.billed_requests,
                    accrued_cost: e.accrued_cost,
                    total_dispatch: e.total_dispatch,
                    recent_dispatch_10s: count_recent(&e.dispatch_times, now, 10),
                    recent_dispatch_60s: count_recent(&e.dispatch_times, now, 60),
                    recent_dispatch_5m: count_recent(&e.dispatch_times, now, 300),
                    dispatch_score: compute_dispatch_score(
                        e.success_count,
                        e.total_failure_count,
                        e.in_flight.load(Ordering::SeqCst),
                        e.credentials
                            .concurrency_limit
                            .unwrap_or(self.config.default_concurrency_limit)
                            .max(1),
                        e.ewma_latency_ms,
                    ),
                    dispatch_pressure: {
                        let limit = e
                            .credentials
                            .concurrency_limit
                            .unwrap_or(self.config.default_concurrency_limit)
                            .max(1);
                        count_recent(&e.dispatch_times, now, 60) as f64 / limit as f64
                    },
                    warmed_recently: e
                        .last_warmup_at
                        .map(|t| now.duration_since(t).as_secs() < 600)
                        .unwrap_or(false),
                })
                .collect(),
            current_id,
            total: entries.len(),
            available,
        }
    }

    /// 设置凭据禁用状态（Admin API）
    pub fn set_disabled(&self, id: u64, disabled: bool) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.disabled = disabled;
            if !disabled {
                // 启用时重置失败计数
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.disabled_reason = None;
                entry.throttled_until = None;
            } else {
                entry.disabled_reason = Some(DisabledReason::Manual);
            }
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 标记凭据进入临时冷却期（账号级 429 风控触发，或上游 5xx 瞬态错误）
    ///
    /// 升级行为（计数 + 窗口）：
    /// 1. push 当前时间戳到 `throttle_events`，剪掉 `error_window_secs` 之前的过期项
    /// 2. 窗口内事件数 ≥ `error_threshold` 才设 `throttled_until`，否则只记录不冷却
    /// 3. 触发冷却时 push 一个 `trip_events` 时间戳（用于自动 disable 计数）
    /// 4. `disable_window_secs` 内 trip 数 ≥ `auto_disable_after_trips` → 整号 disable
    /// 5. 冷却时长走凭据级覆盖，未设取全局 `error_cooldown_policy.cooldown_secs`
    ///
    /// `cooldown` 入参保留在签名上以兼容旧调用——但**不再被使用**，时长完全由
    /// effective policy 决定。这是为了避免修改所有调用点。
    ///
    /// 返回剩余可用凭据数（已排除冷却中的）。
    pub fn report_account_throttled(&self, id: u64, _legacy_cooldown: StdDuration) -> usize {
        let now = Instant::now();
        let policy = self.effective_cooldown_policy(id);
        let win = StdDuration::from_secs(policy.error_window_secs as u64);
        let dwin = StdDuration::from_secs(policy.disable_window_secs as u64);

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                // 1. 加事件 + 剪窗口
                entry.throttle_events.push_back(now);
                while let Some(&t) = entry.throttle_events.front() {
                    if now.duration_since(t) > win {
                        entry.throttle_events.pop_front();
                    } else {
                        break;
                    }
                }
                // 计入累计失败（账号风控不动连续 failure_count，避免冷却结束后误禁用）
                entry.total_failure_count += 1;

                let in_window = entry.throttle_events.len() as u32;
                tracing::debug!(
                    "凭据 #{} 错误窗口计数 {}/{}（{}s 内）",
                    id, in_window, policy.error_threshold, policy.error_window_secs
                );

                // 2. 达阈值才设冷却
                if in_window >= policy.error_threshold {
                    let cooldown = StdDuration::from_secs(policy.cooldown_secs as u64);
                    let until = now + cooldown;
                    entry.throttled_until = Some(match entry.throttled_until {
                        Some(prev) if prev > until => prev,
                        _ => until,
                    });
                    // 触发冷却 → push 一个 trip 事件
                    entry.trip_events.push_back(now);
                    // 清空错误窗口，避免冷却结束后立即又达阈值
                    entry.throttle_events.clear();

                    tracing::warn!(
                        "凭据 #{} 触发账号级风控，冷却 {} 秒（窗口 {}s 内累计 {} 次错误）",
                        id, cooldown.as_secs(), policy.error_window_secs, in_window
                    );

                    // 3. 累计 trips 窗口剪枝
                    while let Some(&t) = entry.trip_events.front() {
                        if now.duration_since(t) > dwin {
                            entry.trip_events.pop_front();
                        } else {
                            break;
                        }
                    }

                    // 4. 反复触发 → 自动 disable
                    if entry.trip_events.len() as u32 >= policy.auto_disable_after_trips {
                        entry.disabled = true;
                        entry.disabled_reason = Some(DisabledReason::AutoThrottled);
                        tracing::error!(
                            "凭据 #{} 因 {}s 内累计触发冷却 {} 次，自动 disable",
                            id, policy.disable_window_secs, entry.trip_events.len()
                        );
                    }
                }
            }

            let throttled_now = Instant::now();
            entries
                .iter()
                .filter(|e| {
                    !e.disabled
                        && !e.throttled_until.map(|t| t > throttled_now).unwrap_or(false)
                })
                .count()
        }
    }

    /// 计算指定凭据的生效冷却策略（凭据级覆盖 > 全局兜底）。
    ///
    /// 每子字段独立 fallback——凭据 `cooldown_override.error_threshold = Some(3)`
    /// 但其他字段未设 → 阈值用 3、其他字段用全局值。
    fn effective_cooldown_policy(&self, id: u64) -> crate::model::config::ErrorCooldownPolicy {
        let global = self.config.error_cooldown_policy.clone();
        let entries = self.entries.lock();
        let override_opt = entries
            .iter()
            .find(|e| e.id == id)
            .and_then(|e| e.credentials.cooldown_override.clone());
        drop(entries);

        let Some(o) = override_opt else { return global; };
        crate::model::config::ErrorCooldownPolicy {
            error_window_secs: o.error_window_secs.unwrap_or(global.error_window_secs),
            error_threshold: o.error_threshold.unwrap_or(global.error_threshold),
            cooldown_secs: o.cooldown_secs.unwrap_or(global.cooldown_secs),
            auto_disable_after_trips: o
                .auto_disable_after_trips
                .unwrap_or(global.auto_disable_after_trips),
            disable_window_secs: o.disable_window_secs.unwrap_or(global.disable_window_secs),
        }
    }

    /// 手动解除指定凭据的临时冷却（Admin API）
    ///
    /// 即使冷却尚未到期也立即清除，让该凭据重新参与调度。
    pub fn clear_throttle(&self, id: u64) -> anyhow::Result<()> {
        let mut entries = self.entries.lock();
        let entry = entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
        entry.throttled_until = None;
        tracing::info!("凭据 #{} 风控冷却已被手动解除", id);
        Ok(())
    }

    /// 以"额度已用尽"为原因禁用凭据（Admin 一键超额功能）
    ///
    /// 与手动禁用不同，原因记录为 `QuotaExceeded`，便于自愈逻辑识别。
    pub fn disable_quota_exceeded(&self, id: u64) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.disabled = true;
            entry.disabled_reason = Some(DisabledReason::QuotaExceeded);
        }
        self.persist_credentials()?;
        Ok(())
    }

    /// 设置凭据优先级（Admin API）
    ///
    /// 修改优先级后会立即按新优先级重新选择当前凭据。
    /// 即使持久化失败，内存中的优先级和当前凭据选择也会生效。
    pub fn set_priority(&self, id: u64, priority: u32) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.priority = priority;
        }
        // 立即按新优先级重新选择当前凭据（无论持久化是否成功）
        self.select_highest_priority();
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 重置凭据失败计数并重新启用（Admin API）
    pub fn reset_and_enable(&self, id: u64) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            if entry.disabled_reason == Some(DisabledReason::InvalidConfig) {
                anyhow::bail!("凭据 #{} 因配置无效被禁用，请修正配置后重启服务", id);
            }
            entry.failure_count = 0;
            entry.total_failure_count = 0;
            entry.refresh_failure_count = 0;
            entry.disabled = false;
            entry.disabled_reason = None;
            entry.throttled_until = None;
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    pub fn reset_success_count(&self, id: Option<u64>) -> anyhow::Result<u32> {
        let mut count = 0u32;
        {
            let mut entries = self.entries.lock();
            match id {
                Some(target_id) => {
                    let entry = entries
                        .iter_mut()
                        .find(|e| e.id == target_id)
                        .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", target_id))?;
                    entry.success_count = 0;
                    count = 1;
                }
                None => {
                    for entry in entries.iter_mut() {
                        entry.success_count = 0;
                        count += 1;
                    }
                }
            }
        }
        self.save_stats();
        Ok(count)
    }

    /// 解析并回填 Enterprise / IdC 账号的真实 profileArn。
    ///
    /// 流式端点（`generateAssistantResponse`）强制要求 profileArn：不带 → 400
    /// `profileArn is required`。Enterprise / IdC 账号若带 BuilderID 占位符会因
    /// token 身份不匹配触发 403，真实 profileArn 只能通过 `ListAvailableProfiles` 获取。
    ///
    /// 行为：
    /// - API Key 凭据 / 已有真实（非占位符）profileArn → 直接返回，不发起网络请求；
    /// - 否则调用上游 `ListAvailableProfiles`，命中真实 ARN 时写回凭据并持久化；
    /// - 上游无 profile（如纯 BuilderID 账号）→ 返回 `None`，由调用方回退到占位符。
    ///
    /// 返回应当用于本次请求的 profileArn（`Some` 表示真实 ARN）。
    pub async fn resolve_profile_arn_for(
        &self,
        id: u64,
        token: &str,
    ) -> anyhow::Result<Option<String>> {
        use crate::kiro::model::credentials::is_placeholder_profile_arn;

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据没有 profileArn 概念
        if credentials.is_api_key_credential() {
            return Ok(None);
        }

        // 已有真实 ARN（含 Social 共享 ARN）→ 直接用，无需查询
        if let Some(arn) = credentials.profile_arn.as_deref() {
            if !is_placeholder_profile_arn(arn) {
                return Ok(Some(arn.to_string()));
            }
        }

        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let profiles =
            list_available_profiles(&credentials, &self.config, token, effective_proxy.as_ref())
                .await?;

        let Some(arn) = profiles.first_arn().map(|s| s.to_string()) else {
            // 无 Enterprise profile（如纯 BuilderID 账号）：保持占位符回退逻辑
            return Ok(None);
        };

        // 写回真实 ARN 并持久化
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials.profile_arn = Some(arn.clone());
            }
        }
        if let Err(e) = self.persist_credentials() {
            tracing::warn!("profileArn 回填后持久化失败（不影响本次请求）: {}", e);
        }
        tracing::info!("凭据 #{} 已解析并回填真实 profileArn: {}", id, arn);

        Ok(Some(arn))
    }

    /// 获取指定凭据的使用额度（Admin API）
    pub async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据直接使用 kiro_api_key，无需刷新
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else {
            // 检查是否需要刷新 token
            let needs_refresh =
                is_token_expired(&credentials) || is_token_expiring_soon(&credentials);

            if needs_refresh {
                let _guard = self.refresh_lock.lock().await;
                let current_creds = {
                    let entries = self.entries.lock();
                    entries
                        .iter()
                        .find(|e| e.id == id)
                        .map(|e| e.credentials.clone())
                        .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
                };

                if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                    let global_proxy = self.proxy.lock().clone();
                    let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                    let new_creds =
                        refresh_token(&current_creds, &self.config, effective_proxy.as_ref())
                            .await?;
                    {
                        let mut entries = self.entries.lock();
                        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                            entry.credentials = new_creds.clone();
                        }
                    }
                    // 持久化失败只记录警告，不影响本次请求
                    if let Err(e) = self.persist_credentials() {
                        tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                    }
                    new_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
                } else {
                    current_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
                }
            } else {
                credentials
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        };

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let usage_limits =
            get_usage_limits(&credentials, &self.config, &token, effective_proxy.as_ref()).await?;

        // 更新订阅等级到凭据（仅在发生变化时持久化）
        if let Some(subscription_title) = usage_limits.subscription_title() {
            let changed = {
                let mut entries = self.entries.lock();
                if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                    let old_title = entry.credentials.subscription_title.clone();
                    if old_title.as_deref() != Some(subscription_title) {
                        entry.credentials.subscription_title = Some(subscription_title.to_string());
                        tracing::info!(
                            "凭据 #{} 订阅等级已更新: {:?} -> {}",
                            id,
                            old_title,
                            subscription_title
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if changed {
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("订阅等级更新后持久化失败（不影响本次请求）: {}", e);
                }
            }
        }

        // 回填邮箱：当凭据尚无邮箱，或现有 email 不是合法邮箱（如 KAM
        // durable 导出里的 "mrdev47" 这种本地昵称）时，用上游 userInfo.email 覆盖
        if let Some(email) = usage_limits.email() {
            let changed = {
                let mut entries = self.entries.lock();
                if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                    let needs_fill = entry
                        .credentials
                        .email
                        .as_deref()
                        .map(|s| {
                            // 轻量校验：含 @ 且 @ 后有 . 才视为合法邮箱
                            !s.contains('@')
                                || !s
                                    .split_once('@')
                                    .map(|(_, domain)| domain.contains('.'))
                                    .unwrap_or(false)
                        })
                        .unwrap_or(true);
                    if needs_fill {
                        let prev = entry.credentials.email.clone();
                        entry.credentials.email = Some(email.to_string());
                        match prev.as_deref() {
                            Some(old) if !old.is_empty() => tracing::info!(
                                "凭据 #{} 邮箱已覆盖: {} -> {}",
                                id,
                                old,
                                email
                            ),
                            _ => tracing::info!("凭据 #{} 邮箱已回填: {}", id, email),
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if changed {
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("邮箱回填后持久化失败（不影响本次请求）: {}", e);
                }
            }
        }

        Ok(usage_limits)
    }

    /// 为只读型上游查询准备有效 token 与最新凭据快照
    ///
    /// 复用 [`Self::get_usage_limits_for`] 的 token 准备流程：API Key 凭据直接用
    /// kiroApiKey；OAuth 凭据按需在 `refresh_lock` 内刷新并持久化。返回的凭据是
    /// 刷新后重新读取的最新快照，调用方据此构造请求。
    async fn prepare_request_token(
        &self,
        id: u64,
    ) -> anyhow::Result<(String, KiroCredentials)> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据直接使用 kiro_api_key，无需刷新
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else if is_token_expired(&credentials) || is_token_expiring_soon(&credentials) {
            let _guard = self.refresh_lock.lock().await;
            let current_creds = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .map(|e| e.credentials.clone())
                    .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
            };

            if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                let global_proxy = self.proxy.lock().clone();
                let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                let new_creds =
                    refresh_token(&current_creds, &self.config, effective_proxy.as_ref()).await?;
                {
                    let mut entries = self.entries.lock();
                    if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                        entry.credentials = new_creds.clone();
                    }
                }
                // 持久化失败只记录警告，不影响本次请求
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                }
                new_creds
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
            } else {
                current_creds
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        } else {
            credentials
                .access_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
        };

        // 重新读取最新凭据（刷新可能改写了 access_token 之外的字段）
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        Ok((token, credentials))
    }

    /// 获取指定凭据当前可用的模型列表（Admin API）
    ///
    /// 按需实时查询上游 `ListAvailableModels`，不做缓存。
    pub async fn get_available_models_for(
        &self,
        id: u64,
    ) -> anyhow::Result<ListAvailableModelsResponse> {
        let (token, credentials) = self.prepare_request_token(id).await?;
        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        get_available_models(&credentials, &self.config, &token, effective_proxy.as_ref()).await
    }

    /// 对话测活：对指定凭据发一条真实的 `generateAssistantResponse` 请求。
    ///
    /// 与余额查询走的是完全不同的 API 端点——余额查询可能通过（如账号被临时封禁
    /// 时 getUsageLimits 仍返回 200），但对话接口会直接返回 403。
    /// 这里注入真实的 profileArn（与对话路径完全一致），确保测活结果与真实使用场景吻合。
    ///
    /// 成功时解析流式响应（AWS Event Stream），从 contextUsage / metering 事件
    /// 提取真实的 input_tokens / output_tokens / credits 写入 trace。
    pub async fn test_conversation_for(&self, id: u64) -> anyhow::Result<TestActiveOutcome> {
        let (token, credentials) = self.prepare_request_token(id).await?;
        let region = credentials.effective_api_region(&self.config);
        let host = format!("q.{}.amazonaws.com", region);
        let url = format!("https://{}/generateAssistantResponse", host);
        let machine_id = machine_id::generate_from_credentials(&credentials, &self.config);
        let kiro_version = &self.config.kiro_version;
        // 测活默认请求模型：与 Kiro IDE 的轻量「ping」一致
        let test_model = "claude-sonnet-4.5";

        // 构建最小对话请求体，在根对象注入 profileArn（与 IDE endpoint 完全一致）
        let mut body = serde_json::json!({
            "conversationState": {
                "chatTriggerType": "MANUAL",
                "conversationId": uuid::Uuid::new_v4().to_string(),
                "currentMessage": {
                    "userInputMessage": {
                        "content": "ping",
                        "modelId": test_model,
                        "origin": "AI_EDITOR",
                    }
                },
                "history": [],
            }
        });
        // streaming_profile_arn() 与正常对话路径一致：
        // - 真实 ARN → 注入；占位符 ARN → 返回 None 不注入（避免 403）
        if let Some(arn) = credentials.streaming_profile_arn() {
            body["profileArn"] = serde_json::Value::String(arn);
        }

        let user_agent = format!(
            "aws-sdk-js/1.0.34 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#1.0.34 m/E KiroIDE-{}-{}",
            self.config.system_version, self.config.node_version, kiro_version, machine_id,
        );
        let amz_user_agent = format!("aws-sdk-js/1.0.34 KiroIDE-{}-{}", kiro_version, machine_id);

        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let client = build_client(effective_proxy.as_ref(), 30, self.config.tls_backend)?;

        let mut request = client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-amzn-codewhisperer-optout", "true")
            .header("x-amzn-kiro-agent-mode", "vibe")
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close");

        // 注入真实的 profileArn（与实际对话路径完全一致）
        // 这是之前失败的根因：缺 profileArn → 400，带占位 ARN → 403
        if let Some(ref arn) = credentials.profile_arn {
            request = request.header("x-amzn-kiro-profile-arn", arn);
        }
        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        } else if credentials.is_external_idp() {
            request = request.header("TokenType", "EXTERNAL_IDP");
        }

        let request_started_at = Instant::now();
        let response = request.body(body.to_string()).send().await?;
        let status = response.status();
        if !status.is_success() {
            let err_body = response.text().await.unwrap_or_default();
            bail!("HTTP {} {}", status, err_body);
        }

        // 流式响应一次性 buffer 解析（测活仅一次 ping，体积小）
        let body_bytes = response.bytes().await?;
        let mut decoder = EventStreamDecoder::new();
        if let Err(e) = decoder.feed(&body_bytes) {
            tracing::warn!("测活解码缓冲区溢出: {}", e);
        }

        let mut text_content = String::new();
        let mut credits = 0.0_f64;
        let mut context_usage_percentage: Option<f64> = None;
        let mut first_token_at: Option<Instant> = None;
        for result in decoder.decode_iter() {
            match result {
                Ok(frame) => {
                    if let Ok(event) = KiroStreamEvent::from_frame(frame) {
                        match event {
                            KiroStreamEvent::AssistantResponse(resp) => {
                                if first_token_at.is_none() && !resp.content.is_empty() {
                                    first_token_at = Some(Instant::now());
                                }
                                text_content.push_str(&resp.content);
                            }
                            KiroStreamEvent::ContextUsage(ctx) => {
                                context_usage_percentage = Some(ctx.context_usage_percentage);
                            }
                            KiroStreamEvent::Metering(m) => {
                                credits += m.usage;
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("测活解码事件失败（可忽略）: {}", e);
                }
            }
        }

        // 计算 input/output tokens（与正常对话同口径）
        let window_size = crate::anthropic::get_context_window_size(test_model);
        let input_tokens = context_usage_percentage
            .map(|pct| (pct * (window_size as f64) / 100.0) as i32)
            .unwrap_or(0);
        let output_tokens = if text_content.is_empty() {
            0
        } else {
            crate::token::estimate_output_tokens(&[serde_json::json!({
                "type": "text",
                "text": text_content,
            })])
        };
        let first_token_ms = first_token_at
            .map(|t| t.duration_since(request_started_at).as_millis() as u64);

        Ok(TestActiveOutcome {
            model_id: test_model.to_string(),
            input_tokens,
            output_tokens,
            credits,
            context_usage_percentage,
            first_token_ms,
        })
    }

    /// 设置用户偏好（开启/关闭超额）— Admin API
    ///
    /// 与 `get_usage_limits_for` 类似的 token 准备流程，最后调用上游
    /// `setUserPreference` 接口写入新的 `overageStatus`。
    pub async fn set_user_preference_for(
        &self,
        id: u64,
        overage_status: &str,
    ) -> anyhow::Result<()> {
        // 仅接受 "ENABLED" / "DISABLED"，其它值早 fail
        if overage_status != "ENABLED" && overage_status != "DISABLED" {
            anyhow::bail!("overageStatus 必须是 ENABLED 或 DISABLED");
        }

        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // API Key 凭据：直接当 Bearer 用
        let token = if credentials.is_api_key_credential() {
            credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?
        } else {
            // 复用与 get_usage_limits_for 完全相同的过期检查与刷新逻辑
            let needs_refresh =
                is_token_expired(&credentials) || is_token_expiring_soon(&credentials);

            if needs_refresh {
                let _guard = self.refresh_lock.lock().await;
                let current_creds = {
                    let entries = self.entries.lock();
                    entries
                        .iter()
                        .find(|e| e.id == id)
                        .map(|e| e.credentials.clone())
                        .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
                };

                if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                    let global_proxy = self.proxy.lock().clone();
                    let effective_proxy = current_creds.effective_proxy(global_proxy.as_ref());
                    let new_creds =
                        refresh_token(&current_creds, &self.config, effective_proxy.as_ref())
                            .await?;
                    {
                        let mut entries = self.entries.lock();
                        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                            entry.credentials = new_creds.clone();
                        }
                    }
                    if let Err(e) = self.persist_credentials() {
                        tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                    }
                    new_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
                } else {
                    current_creds
                        .access_token
                        .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
                }
            } else {
                credentials
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
            }
        };

        // 重新读取最新的凭据快照（refresh 可能已修改 access_token 之外的字段）
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        set_user_preference(
            &credentials,
            &self.config,
            &token,
            effective_proxy.as_ref(),
            overage_status,
        )
        .await
    }

    /// 添加新凭据（Admin API）
    ///
    /// # 流程
    /// 1. 验证凭据基本字段（API Key: kiroApiKey 不为空; OAuth: refreshToken 不为空）
    /// 2. 基于 kiroApiKey 或 refreshToken 的 SHA-256 哈希检测重复
    /// 3. OAuth: 尝试刷新 Token 验证凭据有效性; API Key: 跳过
    /// 4. 分配新 ID（当前最大 ID + 1）
    /// 5. 添加到 entries 列表
    /// 6. 持久化到配置文件
    ///
    /// # 返回
    /// - `Ok(u64)` - 新凭据 ID
    /// - `Err(_)` - 验证失败或添加失败
    pub async fn add_credential(&self, new_cred: KiroCredentials) -> anyhow::Result<u64> {
        // 1. 基本验证
        if new_cred.is_api_key_credential() {
            let api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            if api_key.is_empty() {
                anyhow::bail!("kiroApiKey 为空");
            }
        } else {
            validate_refresh_token(&new_cred)?;
        }

        // 2. 基于哈希检测重复
        if new_cred.is_api_key_credential() {
            let new_api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 kiroApiKey"))?;
            let new_api_key_hash = sha256_hex(new_api_key);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .kiro_api_key
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_api_key_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（kiroApiKey 重复）");
            }
        } else {
            let new_refresh_token = new_cred
                .refresh_token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;
            let new_refresh_token_hash = sha256_hex(new_refresh_token);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .refresh_token
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_refresh_token_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（refreshToken 重复）");
            }
        }

        // 3. 验证凭据有效性（API Key 无需网络刷新）
        let mut validated_cred = if new_cred.is_api_key_credential() {
            new_cred.clone()
        } else {
            let global_proxy = self.proxy.lock().clone();
            let effective_proxy = new_cred.effective_proxy(global_proxy.as_ref());
            refresh_token(&new_cred, &self.config, effective_proxy.as_ref()).await?
        };

        // 捕获原始输入的去重指纹。刷新可能轮换 refreshToken，且下方 step 5 会把
        // new_cred 的字段 move 走，故必须在此处（字段尚完整时）取指纹，
        // 供插入临界区的权威去重重检使用。
        let dedup_is_api_key = new_cred.is_api_key_credential();
        let dedup_hash: Option<String> = if dedup_is_api_key {
            new_cred
                .kiro_api_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .map(sha256_hex)
        } else {
            new_cred.refresh_token.as_deref().map(sha256_hex)
        };

        // 4. 分配新 ID。必须使用单调计数器，不能按当前 entries 最大值重算；
        // 否则删除最后一个账号后再添加会复用旧 ID，导致 trace/usage/kiro_stats
        // 这类按 credential_id 聚合的历史被新账号继承。
        let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // 5. 设置 ID 并保留用户输入的元数据
        validated_cred.id = Some(new_id);
        validated_cred.priority = new_cred.priority;
        validated_cred.auth_method = new_cred.auth_method.map(|m| {
            if m.eq_ignore_ascii_case("builder-id") || m.eq_ignore_ascii_case("iam") {
                "idc".to_string()
            } else {
                m
            }
        });
        if new_cred.profile_arn.is_some() {
            validated_cred.profile_arn = new_cred.profile_arn;
        }
        validated_cred.provider = new_cred.provider;
        validated_cred.fill_default_profile_arn();
        validated_cred.client_id = new_cred.client_id;
        validated_cred.client_secret = new_cred.client_secret;
        validated_cred.region = new_cred.region;
        validated_cred.auth_region = new_cred.auth_region;
        validated_cred.api_region = new_cred.api_region;
        validated_cred.machine_id = new_cred.machine_id;
        validated_cred.email = new_cred.email;
        validated_cred.proxy_url = new_cred.proxy_url;
        validated_cred.proxy_username = new_cred.proxy_username;
        validated_cred.proxy_password = new_cred.proxy_password;
        validated_cred.kiro_api_key = new_cred.kiro_api_key;

        {
            let mut entries = self.entries.lock();
            // 并发安全：token 刷新（网络）在锁外完成，期间可能有其它并发的
            // add_credential 通过了步骤 2 的预去重并已插入同一凭据。故在持锁的
            // 插入点用原始输入指纹再做一次权威去重，关闭 TOCTOU（如命中则 bail，
            // next_id 即便已自增也只是跳号，无副作用）。
            if let Some(hash) = &dedup_hash {
                let dup = entries.iter().any(|e| {
                    let entry_hash = if dedup_is_api_key {
                        e.credentials.kiro_api_key.as_deref().map(sha256_hex)
                    } else {
                        e.credentials.refresh_token.as_deref().map(sha256_hex)
                    };
                    entry_hash.as_deref() == Some(hash.as_str())
                });
                if dup {
                    let msg = if dedup_is_api_key {
                        "凭据已存在（kiroApiKey 重复）"
                    } else {
                        "凭据已存在（refreshToken 重复）"
                    };
                    anyhow::bail!(msg);
                }
            }
            entries.push(CredentialEntry {
                id: new_id,
                credentials: validated_cred,
                failure_count: 0,
                total_failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: 0,
                last_used_at: None,
                throttled_until: None,
                throttle_events: VecDeque::new(),
                trip_events: VecDeque::new(),
                in_flight: Arc::new(AtomicU32::new(0)),
                ewma_latency_ms: None,
                billed_requests: 0,
                accrued_cost: 0.0,
                total_dispatch: 0,
                dispatch_times: VecDeque::new(),
                last_warmup_at: None,
            });
        }

        // 6. 升级为多凭据格式（确保后续 token rotation 能写盘）并持久化
        self.is_multiple_format.store(true, Ordering::Relaxed);
        self.persist_credentials()?;

        tracing::info!("成功添加凭据 #{}", new_id);
        Ok(new_id)
    }

    /// 更新凭据的可编辑字段（Admin API）
    ///
    /// 支持更新 email、proxy_url、proxy_username、proxy_password。
    /// 传 `None` 表示不修改该字段，传 `Some("")` 表示清除该字段。
    pub fn update_credential(
        &self,
        id: u64,
        email: Option<Option<String>>,
        proxy_url: Option<Option<String>>,
        proxy_username: Option<Option<String>>,
        proxy_password: Option<Option<String>>,
        groups: Option<Vec<String>>,
        source_channel: Option<Option<String>>,
        concurrency_limit: Option<Option<u32>>,
    ) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            if let Some(v) = email {
                entry.credentials.email = v.filter(|s| !s.is_empty());
            }
            if let Some(v) = proxy_url {
                entry.credentials.proxy_url = v.filter(|s| !s.is_empty());
            }
            if let Some(v) = proxy_username {
                entry.credentials.proxy_username = v.filter(|s| !s.is_empty());
            }
            if let Some(v) = proxy_password {
                entry.credentials.proxy_password = v.filter(|s| !s.is_empty());
            }
            if let Some(g) = groups {
                entry.credentials.groups =
                    g.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            if let Some(v) = source_channel {
                entry.credentials.source_channel =
                    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            }
            if let Some(v) = concurrency_limit {
                // 内层 None = 清除覆盖（回退全局默认）；Some(0) 视为清除（避免锁死账号）
                entry.credentials.concurrency_limit = v.filter(|n| *n > 0);
            }
        }
        self.persist_credentials()?;
        Ok(())
    }

    /// 列出所有凭据当前引用的分组名（去重排序）。
    /// 用于启动迁移到 GroupManager 注册表，以及前端的引用计数显示。
    pub fn list_credential_groups(&self) -> Vec<String> {
        let entries = self.entries.lock();
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in entries.iter() {
            for g in &e.credentials.groups {
                if !g.is_empty() {
                    set.insert(g.clone());
                }
            }
        }
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        list
    }

    /// 统计指定分组被多少个凭据引用（用于分组管理页 / 删除前提示）。
    pub fn count_credentials_with_group(&self, group: &str) -> usize {
        let entries = self.entries.lock();
        entries
            .iter()
            .filter(|e| e.credentials.groups.iter().any(|g| g == group))
            .count()
    }

    /// 把所有凭据 `groups` 字段中等于 `old` 的元素改为 `new`（分组改名级联用）。
    /// 已经显式带 `new` 的凭据不会重复添加。返回受影响的凭据数。
    pub fn rename_credential_group(&self, old: &str, new: &str) -> anyhow::Result<usize> {
        let mut affected = 0usize;
        {
            let mut entries = self.entries.lock();
            for entry in entries.iter_mut() {
                let groups = &mut entry.credentials.groups;
                let mut hit = false;
                let mut already_has_new = false;
                for g in groups.iter() {
                    if g == old {
                        hit = true;
                    }
                    if g == new {
                        already_has_new = true;
                    }
                }
                if hit {
                    if already_has_new {
                        // old 和 new 共存：只去掉 old，避免重复
                        groups.retain(|g| g != old);
                    } else {
                        for g in groups.iter_mut() {
                            if g == old {
                                *g = new.to_string();
                            }
                        }
                    }
                    affected += 1;
                }
            }
        }
        if affected > 0 {
            self.persist_credentials()?;
        }
        Ok(affected)
    }

    /// 把 `name` 这个分组从所有凭据的 `groups` 字段中移除（强删分组级联用）。
    /// 返回受影响的凭据数。
    pub fn remove_credential_group(&self, name: &str) -> anyhow::Result<usize> {
        let mut affected = 0usize;
        {
            let mut entries = self.entries.lock();
            for entry in entries.iter_mut() {
                let before = entry.credentials.groups.len();
                entry.credentials.groups.retain(|g| g != name);
                if entry.credentials.groups.len() != before {
                    affected += 1;
                }
            }
        }
        if affected > 0 {
            self.persist_credentials()?;
        }
        Ok(affected)
    }

    /// 删除凭据（Admin API）
    ///
    /// # 前置条件
    /// - 凭据必须已禁用（disabled = true）
    ///
    /// # 行为
    /// 1. 验证凭据存在
    /// 2. 验证凭据已禁用
    /// 3. 从 entries 移除
    /// 4. 如果删除的是当前凭据，切换到优先级最高的可用凭据
    /// 5. 如果删除后没有凭据，将 current_id 重置为 0
    /// 6. 持久化到文件
    ///
    /// # 返回
    /// - `Ok(())` - 删除成功
    /// - `Err(_)` - 凭据不存在或持久化失败
    pub fn delete_credential(&self, id: u64) -> anyhow::Result<()> {
        let was_current = {
            let mut entries = self.entries.lock();

            // 查找凭据
            let _entry = entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            // 记录是否是当前凭据
            let current_id = *self.current_id.lock();
            let was_current = current_id == id;

            // 删除凭据
            entries.retain(|e| e.id != id);

            was_current
        };

        // 如果删除的是当前凭据，切换到优先级最高的可用凭据
        if was_current {
            self.select_highest_priority();
        }

        // 如果删除后没有任何凭据，将 current_id 重置为 0（与初始化行为保持一致）
        {
            let entries = self.entries.lock();
            if entries.is_empty() {
                let mut current_id = self.current_id.lock();
                *current_id = 0;
                tracing::info!("所有凭据已删除，current_id 已重置为 0");
            }
        }

        // 持久化更改
        self.persist_credentials()?;

        // 立即回写统计数据，清除已删除凭据的残留条目
        self.save_stats();

        tracing::info!("已删除凭据 #{}", id);
        Ok(())
    }

    /// 更新指定凭据的 refreshToken（Admin API）
    ///
    /// # 前置条件
    /// - 凭据必须已禁用（disabled = true），防止意外覆盖正在使用的 Token
    ///
    /// # 行为
    /// 1. 验证凭据存在且已禁用
    /// 2. 验证新 refreshToken 格式
    /// 3. 更新 refreshToken
    /// 4. 重置 refresh_failure_count（保持 disabled 状态，让用户手动启用）
    /// 5. 持久化到文件
    pub fn update_refresh_token(
        &self,
        id: u64,
        new_refresh_token: String,
        new_access_token: Option<String>,
        new_expires_at: Option<String>,
    ) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();

            // 用索引定位，避免两次线性扫描和后续 unwrap
            let idx = entries
                .iter()
                .position(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            if !entries[idx].disabled {
                anyhow::bail!(
                    "只能为已禁用的凭据更新 refreshToken（请先禁用凭据 #{}）",
                    id
                );
            }

            // 验证新 refreshToken 格式
            let tmp_creds = KiroCredentials {
                refresh_token: Some(new_refresh_token.clone()),
                ..entries[idx].credentials.clone()
            };
            validate_refresh_token(&tmp_creds)?;

            // 检查是否与现有其他凭据重复
            let new_hash = sha256_hex(&new_refresh_token);
            let duplicate = entries.iter().enumerate().any(|(i, e)| {
                i != idx
                    && e.credentials
                        .refresh_token
                        .as_ref()
                        .map(|t| sha256_hex(t) == new_hash)
                        .unwrap_or(false)
            });
            if duplicate {
                anyhow::bail!("refreshToken 与其他凭据重复");
            }

            let entry = &mut entries[idx];
            entry.credentials.refresh_token = Some(new_refresh_token);
            // 若调用方提供了 accessToken（来自导入/导出），则直接保留，无需立即调认证服务器
            // 否则清空，下次使用时系统会自动刷新
            entry.credentials.access_token = new_access_token;
            entry.credentials.expires_at = new_expires_at;
            entry.refresh_failure_count = 0;
        }
        self.persist_credentials()?;
        tracing::info!("凭据 #{} refreshToken 已更新", id);
        Ok(())
    }

    /// 强制刷新指定凭据的 Token（Admin API）
    ///
    /// 无条件调用上游 API 重新获取 access token，不检查是否过期。
    /// 适用于排查问题、Token 异常但未过期、主动更新凭据状态等场景。
    pub async fn force_refresh_token_for(&self, id: u64) -> anyhow::Result<()> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // 获取刷新锁防止并发刷新
        let _guard = self.refresh_lock.lock().await;

        // 无条件调用 refresh_token
        let global_proxy = self.proxy.lock().clone();
        let effective_proxy = credentials.effective_proxy(global_proxy.as_ref());
        let new_creds = refresh_token(&credentials, &self.config, effective_proxy.as_ref()).await?;

        // 更新 entries 中对应凭据
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.credentials = new_creds;
                entry.refresh_failure_count = 0;
            }
        }

        // 持久化
        if let Err(e) = self.persist_credentials() {
            tracing::warn!("强制刷新 Token 后持久化失败: {}", e);
        }

        tracing::info!("凭据 #{} Token 已强制刷新", id);
        Ok(())
    }

    /// 获取负载均衡模式（Admin API）
    pub fn get_load_balancing_mode(&self) -> String {
        self.load_balancing_mode.lock().clone()
    }

    fn persist_load_balancing_mode(&self, mode: &str) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，负载均衡模式仅在当前进程生效: {}", mode);
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.load_balancing_mode = mode.to_string();
        config
            .save()
            .with_context(|| format!("持久化负载均衡模式失败: {}", config_path.display()))?;

        Ok(())
    }

    /// 设置负载均衡模式（Admin API）
    pub fn set_load_balancing_mode(&self, mode: String) -> anyhow::Result<()> {
        // 验证模式值
        if mode != "priority" && mode != "balanced" {
            anyhow::bail!("无效的负载均衡模式: {}", mode);
        }

        let previous_mode = self.get_load_balancing_mode();
        if previous_mode == mode {
            return Ok(());
        }

        *self.load_balancing_mode.lock() = mode.clone();

        if let Err(err) = self.persist_load_balancing_mode(&mode) {
            *self.load_balancing_mode.lock() = previous_mode;
            return Err(err);
        }

        tracing::info!("负载均衡模式已设置为: {}", mode);
        Ok(())
    }

    /// 获取当前默认起点端点（Admin API）
    pub fn get_default_endpoint(&self) -> String {
        self.default_endpoint.lock().clone()
    }

    /// 设置默认起点端点（Admin API）。运行时立即生效 + 持久化。
    /// 调用方负责校验端点名在 provider 注册表里存在。
    pub fn set_default_endpoint(&self, endpoint: String) -> anyhow::Result<()> {
        let trimmed = endpoint.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("端点名不能为空");
        }
        let previous = self.get_default_endpoint();
        if previous == trimmed {
            return Ok(());
        }

        *self.default_endpoint.lock() = trimmed.clone();

        if let Err(err) = self.persist_default_endpoint(&trimmed) {
            *self.default_endpoint.lock() = previous;
            return Err(err);
        }

        tracing::info!("默认起点端点已设置为: {}", trimmed);
        Ok(())
    }

    fn persist_default_endpoint(&self, endpoint: &str) -> anyhow::Result<()> {
        use anyhow::Context;
        let config_path = match self.config.config_path() {
            Some(p) => p.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，默认起点端点仅在当前进程生效: {}", endpoint);
                return Ok(());
            }
        };
        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.default_endpoint = endpoint.to_string();
        config
            .save()
            .with_context(|| format!("持久化默认起点端点失败: {}", config_path.display()))?;
        Ok(())
    }

    /// 获取 runtime → ide 自动降级开关（Admin API）
    pub fn get_runtime_fallback_enabled(&self) -> bool {
        self.runtime_fallback_enabled.load(Ordering::Relaxed)
    }

    /// 设置 runtime → ide 自动降级开关（Admin API）。运行时立即生效 + 持久化。
    pub fn set_runtime_fallback_enabled(&self, enabled: bool) -> anyhow::Result<()> {
        let previous = self.get_runtime_fallback_enabled();
        if previous == enabled {
            return Ok(());
        }
        self.runtime_fallback_enabled.store(enabled, Ordering::Relaxed);

        if let Err(err) = self.persist_runtime_fallback_enabled(enabled) {
            self.runtime_fallback_enabled.store(previous, Ordering::Relaxed);
            return Err(err);
        }
        tracing::info!("runtime→ide 自动降级已{}", if enabled { "启用" } else { "禁用" });
        Ok(())
    }

    fn persist_runtime_fallback_enabled(&self, enabled: bool) -> anyhow::Result<()> {
        use anyhow::Context;
        let config_path = match self.config.config_path() {
            Some(p) => p.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，runtime 降级开关仅在当前进程生效: {}", enabled);
                return Ok(());
            }
        };
        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.runtime_fallback_enabled = enabled;
        config
            .save()
            .with_context(|| format!("持久化 runtime 降级开关失败: {}", config_path.display()))?;
        Ok(())
    }

    /// 统计当前每个端点上"挂着"的可用凭据数（按 endpoint 字段或默认端点归属）。
    /// 返回 (endpoint_name, count) 列表，仅统计未禁用的凭据。
    pub fn endpoint_distribution(&self) -> Vec<(String, usize)> {
        let default_ep = self.get_default_endpoint();
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for e in self.entries.lock().iter().filter(|e| !e.disabled) {
            let ep = e
                .credentials
                .endpoint
                .clone()
                .unwrap_or_else(|| default_ep.clone());
            *counts.entry(ep).or_insert(0) += 1;
        }
        counts.into_iter().collect()
    }

    /// 获取账号级风控故障转移配置（Admin API）
    pub fn get_account_throttle_failover(&self) -> bool {
        self.account_throttle_failover.load(Ordering::Relaxed)
    }

    /// 获取账号级风控冷却时长秒数（Admin API）
    pub fn get_account_throttle_cooldown_secs(&self) -> u64 {
        self.account_throttle_cooldown_secs.load(Ordering::Relaxed)
    }

    /// 设置账号级风控故障转移配置（Admin API）
    ///
    /// 任一参数传 `None` 表示不修改该字段。
    pub fn set_account_throttle_config(
        &self,
        failover: Option<bool>,
        cooldown_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        if let Some(secs) = cooldown_secs {
            // 限定一个合理范围：1 秒到 24 小时
            if !(1..=86_400).contains(&secs) {
                anyhow::bail!("冷却时长必须在 1..=86400 秒内: {}", secs);
            }
        }

        let prev_failover = self.get_account_throttle_failover();
        let prev_cooldown = self.get_account_throttle_cooldown_secs();
        let new_failover = failover.unwrap_or(prev_failover);
        let new_cooldown = cooldown_secs.unwrap_or(prev_cooldown);

        if new_failover == prev_failover && new_cooldown == prev_cooldown {
            return Ok(());
        }

        self.account_throttle_failover
            .store(new_failover, Ordering::Relaxed);
        self.account_throttle_cooldown_secs
            .store(new_cooldown, Ordering::Relaxed);

        if let Err(err) = self.persist_account_throttle_config(new_failover, new_cooldown) {
            // 回滚内存值
            self.account_throttle_failover
                .store(prev_failover, Ordering::Relaxed);
            self.account_throttle_cooldown_secs
                .store(prev_cooldown, Ordering::Relaxed);
            return Err(err);
        }

        tracing::info!(
            "账号级风控配置已更新: failover={}, cooldown_secs={}",
            new_failover,
            new_cooldown
        );
        Ok(())
    }

    fn persist_account_throttle_config(&self, failover: bool, cooldown_secs: u64) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，账号级风控配置仅在当前进程生效");
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.account_throttle_failover = failover;
        config.account_throttle_cooldown_secs = cooldown_secs;
        config
            .save()
            .with_context(|| format!("持久化账号级风控配置失败: {}", config_path.display()))?;

        Ok(())
    }

    // ============ Session-Sticky 调度 ============

    /// 查询 conversationId 上次粘到的凭据 ID
    pub fn sticky_lookup(&self, conversation_id: &str) -> Option<u64> {
        self.sticky_map
            .lock()
            .get(conversation_id)
            .map(|e| e.credential_id)
    }

    /// 记录 conversationId → credential_id 的粘性映射。
    ///
    /// 若该 conversation 所属分组（或全局）档为 `Off`，直接 no-op（不写也不读 sticky）。
    /// 这样下次同 conversation 来时 `sticky_lookup` 拿不到结果，自然走纯负载均衡。
    pub fn sticky_record(&self, conversation_id: &str, credential_id: u64, group: Option<&str>) {
        if self.resolve_cache_mode(group) == CacheMode::Off {
            return;
        }
        const MAX_ENTRIES: usize = 10_000;
        const EVICT_TTL: StdDuration = StdDuration::from_secs(300);
        let mut map = self.sticky_map.lock();
        map.insert(
            conversation_id.to_string(),
            StickyEntry {
                credential_id,
                last_used: Instant::now(),
            },
        );
        // lazy evict：超容量或每 256 次写入清一次过期
        if map.len() > MAX_ENTRIES || map.len() % 256 == 0 {
            let now = Instant::now();
            map.retain(|_, e| now.duration_since(e.last_used) < EVICT_TTL);
            if map.len() > MAX_ENTRIES {
                Self::sticky_evict_oldest(&mut map, MAX_ENTRIES);
            }
        }
    }

    /// 清理超过 TTL 的 sticky 条目
    pub fn sticky_evict_expired(&self, ttl: StdDuration) {
        let mut map = self.sticky_map.lock();
        let now = Instant::now();
        map.retain(|_, e| now.duration_since(e.last_used) < ttl);
    }

    fn sticky_evict_oldest(map: &mut HashMap<String, StickyEntry>, target: usize) {
        while map.len() > target {
            let oldest_key = map
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                map.remove(&key);
            } else {
                break;
            }
        }
    }
}

impl Drop for MultiTokenManager {
    fn drop(&mut self) {
        if self.stats_dirty.load(Ordering::Relaxed) {
            self.save_stats();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_is_token_expired_with_expired_token() {
        let mut credentials = KiroCredentials::default();
        credentials.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_with_valid_token() {
        let mut credentials = KiroCredentials::default();
        let future = Utc::now() + Duration::hours(1);
        credentials.expires_at = Some(future.to_rfc3339());
        assert!(!is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_within_5_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(3);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_no_expires_at() {
        let credentials = KiroCredentials::default();
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_within_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(8);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_beyond_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(15);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(!is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_validate_refresh_token_missing() {
        let credentials = KiroCredentials::default();
        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_refresh_token_valid() {
        let mut credentials = KiroCredentials::default();
        credentials.refresh_token = Some("a".repeat(150));
        let result = validate_refresh_token(&credentials);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex("test");
        assert_eq!(
            result,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_api_key_credential() {
        let config = Config::default();
        let mut credentials = KiroCredentials::default();
        credentials.kiro_api_key = Some("ksk_test_key_123".to_string());
        credentials.auth_method = Some("api_key".to_string());

        let result = refresh_token(&credentials, &config, None).await;

        assert!(result.is_err(), "API Key 凭据应被 refresh_token 拒绝");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("API Key 凭据不支持刷新"),
            "期望错误消息包含 'API Key 凭据不支持刷新'，实际: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_refresh_token() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.refresh_token = Some("a".repeat(150));

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("凭据已存在"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_success() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_test_key_123".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(id > 0);
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_api_key() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.kiro_api_key = Some("ksk_existing_key".to_string());
        existing.auth_method = Some("api_key".to_string());

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.kiro_api_key = Some("ksk_existing_key".to_string());
        duplicate.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 重复")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_empty_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some(String::new());
        cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("kiroApiKey 为空")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_missing_key_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        // kiro_api_key is None

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("缺少 kiroApiKey")
        );
    }

    #[tokio::test]
    async fn test_add_credential_api_key_and_oauth_coexist() {
        let config = Config::default();

        let mut oauth_cred = KiroCredentials::default();
        oauth_cred.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![oauth_cred], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_new_key".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    // MultiTokenManager 测试

    #[test]
    fn test_multi_token_manager_new() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.priority = 0;
        let mut cred2 = KiroCredentials::default();
        cred2.priority = 1;

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    #[test]
    fn test_multi_token_manager_empty_credentials() {
        let config = Config::default();
        let result = MultiTokenManager::new(config, vec![], None, None, false);
        // 支持 0 个凭据启动（可通过管理面板添加）
        assert!(result.is_ok());
        let manager = result.unwrap();
        assert_eq!(manager.total_count(), 0);
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_duplicate_ids() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.id = Some(1);
        let mut cred2 = KiroCredentials::default();
        cred2.id = Some(1); // 重复 ID

        let result = MultiTokenManager::new(config, vec![cred1, cred2], None, None, false);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("重复的凭据 ID"),
            "错误消息应包含 '重复的凭据 ID'，实际: {}",
            err_msg
        );
    }

    #[test]
    fn test_multi_token_manager_api_key_missing_kiro_api_key_auto_disabled() {
        let config = Config::default();

        // auth_method=api_key 但缺少 kiro_api_key → 应被自动禁用
        let mut bad_cred = KiroCredentials::default();
        bad_cred.auth_method = Some("api_key".to_string());
        // kiro_api_key 保持 None

        let mut good_cred = KiroCredentials::default();
        good_cred.refresh_token = Some("valid_token".to_string());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 1); // bad_cred 被禁用，只剩 1 个可用
    }

    #[test]
    fn test_multi_token_manager_api_key_with_kiro_api_key_not_disabled() {
        let config = Config::default();

        // auth_method=api_key 且有 kiro_api_key → 不应被禁用
        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        cred.kiro_api_key = Some("ksk_test123".to_string());

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_report_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        // 前两次失败不会禁用（使用 ID 1）
        assert!(manager.report_failure(1));
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 2);

        // 第三次失败会禁用第一个凭据
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 1);

        // 继续失败第二个凭据（使用 ID 2）
        assert!(manager.report_failure(2));
        assert!(manager.report_failure(2));
        assert!(!manager.report_failure(2)); // 所有凭据都禁用了
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_report_success() {
        let config = Config::default();
        let cred = KiroCredentials::default();

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();

        // 失败两次（使用 ID 1）
        manager.report_failure(1);
        manager.report_failure(1);

        // 成功后重置计数（使用 ID 1）
        manager.report_success(1);

        // 再失败两次不会禁用
        manager.report_failure(1);
        manager.report_failure(1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_switch_to_next() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.refresh_token = Some("token1".to_string());
        let mut cred2 = KiroCredentials::default();
        cred2.refresh_token = Some("token2".to_string());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        let initial_id = manager.snapshot().current_id;

        // 切换到下一个
        assert!(manager.switch_to_next());
        assert_ne!(manager.snapshot().current_id, initial_id);
    }

    #[test]
    fn test_set_load_balancing_mode_persists_to_config_file() {
        let config_path =
            std::env::temp_dir().join(format!("kiro-load-balancing-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&config_path, r#"{"loadBalancingMode":"priority"}"#).unwrap();

        let config = Config::load(&config_path).unwrap();
        let manager =
            MultiTokenManager::new(config, vec![KiroCredentials::default()], None, None, false)
                .unwrap();

        manager
            .set_load_balancing_mode("balanced".to_string())
            .unwrap();

        let persisted = Config::load(&config_path).unwrap();
        assert_eq!(persisted.load_balancing_mode, "balanced");
        assert_eq!(manager.get_load_balancing_mode(), "balanced");

        std::fs::remove_file(&config_path).unwrap();
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_auto_recovers_all_disabled() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.access_token = Some("t1".to_string());
        cred1.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());
        let mut cred2 = KiroCredentials::default();
        cred2.access_token = Some("t2".to_string());
        cred2.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(1);
        }
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(2);
        }

        assert_eq!(manager.available_count(), 0);

        // 应触发自愈：重置失败计数并重新启用，避免必须重启进程
        let ctx = manager.acquire_context(None, None, None).await.unwrap();
        assert!(ctx.token == "t1" || ctx.token == "t2");
        assert_eq!(manager.available_count(), 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_balanced_retries_until_bad_credential_disabled()
     {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut bad_cred = KiroCredentials::default();
        bad_cred.priority = 0;
        bad_cred.refresh_token = Some("bad".to_string());

        let mut good_cred = KiroCredentials::default();
        good_cred.priority = 1;
        good_cred.access_token = Some("good-token".to_string());
        good_cred.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();

        let ctx = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "good-token");
    }

    #[test]
    fn test_multi_token_manager_report_refresh_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        assert_eq!(manager.available_count(), 2);
        for _ in 0..(MAX_FAILURES_PER_CREDENTIAL - 1) {
            assert!(manager.report_refresh_failure(1));
        }
        assert_eq!(manager.available_count(), 2);

        assert!(manager.report_refresh_failure(1));
        assert_eq!(manager.available_count(), 1);

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled);
        assert_eq!(first.refresh_failure_count, MAX_FAILURES_PER_CREDENTIAL);
        assert_eq!(snapshot.current_id, 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_refresh_failure_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_refresh_failure(1);
            manager.report_refresh_failure(2);
        }
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None, None, None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
    }

    #[test]
    fn test_multi_token_manager_report_quota_exhausted() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        assert_eq!(manager.available_count(), 2);
        assert!(manager.report_quota_exhausted(1));
        assert_eq!(manager.available_count(), 1);

        // 再禁用第二个后，无可用凭据
        assert!(!manager.report_quota_exhausted(2));
        assert_eq!(manager.available_count(), 0);
    }

    #[tokio::test]
    async fn test_multi_token_manager_quota_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        manager.report_quota_exhausted(1);
        manager.report_quota_exhausted(2);
        assert_eq!(manager.available_count(), 0);

        let err = manager
            .acquire_context(None, None, None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
        assert_eq!(manager.available_count(), 0);
    }

    // ============ 凭据级 Region 优先级测试 ============

    #[test]
    fn test_credential_region_priority_uses_credential_auth_region() {
        // 凭据配置了 auth_region 时，应使用凭据的 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-west-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-west-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_credential_region() {
        // 凭据未配置 auth_region 但配置了 region 时，应回退到凭据.region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-central-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_config() {
        // 凭据未配置 auth_region 和 region 时，应回退到 config
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials::default();
        assert!(credentials.auth_region.is_none());
        assert!(credentials.region.is_none());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn test_multiple_credentials_use_respective_regions() {
        // 多凭据场景下，不同凭据使用各自的 auth_region
        let mut config = Config::default();
        config.region = "ap-northeast-1".to_string();

        let mut cred1 = KiroCredentials::default();
        cred1.auth_region = Some("us-east-1".to_string());

        let mut cred2 = KiroCredentials::default();
        cred2.region = Some("eu-west-1".to_string());

        let cred3 = KiroCredentials::default(); // 无 region，使用 config

        assert_eq!(cred1.effective_auth_region(&config), "us-east-1");
        assert_eq!(cred2.effective_auth_region(&config), "eu-west-1");
        assert_eq!(cred3.effective_auth_region(&config), "ap-northeast-1");
    }

    #[test]
    fn test_idc_oidc_endpoint_uses_credential_auth_region() {
        // 验证 IdC OIDC endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);

        assert_eq!(refresh_url, "https://oidc.eu-central-1.amazonaws.com/token");
    }

    #[test]
    fn test_social_refresh_endpoint_uses_credential_auth_region() {
        // 验证 Social refresh endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("ap-southeast-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);

        assert_eq!(
            refresh_url,
            "https://prod.ap-southeast-1.auth.desktop.kiro.dev/refreshToken"
        );
    }

    #[test]
    fn test_api_call_uses_effective_api_region() {
        // 验证 API 调用使用 effective_api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-west-1".to_string());

        // 凭据.region 不参与 api_region 回退链
        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.us-west-2.amazonaws.com");
    }

    #[test]
    fn test_api_call_uses_credential_api_region() {
        // 凭据配置了 api_region 时，API 调用应使用凭据的 api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.api_region = Some("eu-central-1".to_string());

        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.eu-central-1.amazonaws.com");
    }

    #[test]
    fn test_rest_api_region_candidates_us_default() {
        // 非 EU 区域 → 主端点 us-east-1，回退 eu-central-1
        assert_eq!(
            rest_api_region_candidates("us-east-1"),
            ["us-east-1", "eu-central-1"]
        );
        assert_eq!(
            rest_api_region_candidates("us-east-2"),
            ["us-east-1", "eu-central-1"]
        );
        assert_eq!(
            rest_api_region_candidates("ap-southeast-1"),
            ["us-east-1", "eu-central-1"]
        );
    }

    #[test]
    fn test_rest_api_region_candidates_eu() {
        // EU 区域 → 主端点 eu-central-1，回退 us-east-1
        assert_eq!(
            rest_api_region_candidates("eu-central-1"),
            ["eu-central-1", "us-east-1"]
        );
        assert_eq!(
            rest_api_region_candidates("eu-west-1"),
            ["eu-central-1", "us-east-1"]
        );
        assert_eq!(
            rest_api_region_candidates("eu-north-1"),
            ["eu-central-1", "us-east-1"]
        );
    }

    #[test]
    fn test_rest_api_region_candidates_uses_credential_auth_region() {
        // Enterprise/IdC 账号导入时仅带 SSO region 字段（无 api_region），
        // effective_auth_region 会回退到 credential.region，进而选对端点。
        let config = Config::default(); // 默认 region = us-east-1

        let mut eu_cred = KiroCredentials::default();
        eu_cred.region = Some("eu-west-1".to_string());
        let sso_region = eu_cred.effective_auth_region(&config);
        assert_eq!(
            rest_api_region_candidates(sso_region),
            ["eu-central-1", "us-east-1"]
        );

        // 未配置任何 region 的凭据回退到 config 默认 us-east-1
        let plain_cred = KiroCredentials::default();
        let sso_region = plain_cred.effective_auth_region(&config);
        assert_eq!(
            rest_api_region_candidates(sso_region),
            ["us-east-1", "eu-central-1"]
        );
    }

    #[test]
    fn test_credential_region_empty_string_treated_as_set() {
        // 空字符串 auth_region 被视为已设置（虽然不推荐，但行为应一致）
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("".to_string());

        let region = credentials.effective_auth_region(&config);
        // 空字符串被视为已设置，不会回退到 config
        assert_eq!(region, "");
    }

    #[test]
    fn test_auth_and_api_region_independent() {
        // auth_region 和 api_region 互不影响
        let mut config = Config::default();
        config.region = "default".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("auth-only".to_string());
        credentials.api_region = Some("api-only".to_string());

        assert_eq!(credentials.effective_auth_region(&config), "auth-only");
        assert_eq!(credentials.effective_api_region(&config), "api-only");
    }

    // ── is_multiple_format 自动升级 ──────────────────────────────────────────

    fn tmp_creds_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kiro_test_{}.json", name));
        p
    }

    /// 单凭据格式（is_multiple_format=false）启动时自动迁移为数组格式，
    /// 迁移后 persist_credentials 能正确写盘，token rotation 不再丢失。
    #[test]
    fn test_single_format_auto_migrates_to_multiple_on_startup() {
        let path = tmp_creds_path("single_migrate");
        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some("ksk_test_migrate_key".to_string());
        cred.auth_method = Some("api_key".to_string());
        let single_json = serde_json::to_string(&cred).unwrap();
        std::fs::write(&path, &single_json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            false,
        )
        .unwrap();

        assert!(
            manager.is_multiple_format.load(Ordering::Relaxed),
            "单凭据格式应在启动时自动升级为 true"
        );

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.trim_start().starts_with('['),
            "迁移后文件应为数组格式，实际: {}",
            &content[..content.len().min(50)]
        );

        let _ = std::fs::remove_file(&path);
    }

    /// 空凭据列表时不触发迁移
    #[test]
    fn test_empty_credentials_no_migration() {
        let path = tmp_creds_path("empty_no_migrate");
        std::fs::write(&path, "{}").unwrap();

        let manager =
            MultiTokenManager::new(Config::default(), vec![], None, Some(path.clone()), false)
                .unwrap();

        assert!(
            !manager.is_multiple_format.load(Ordering::Relaxed),
            "无凭据时不应触发格式升级"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// add_credential 后 is_multiple_format 必须升级为 true，文件写为数组格式
    #[tokio::test(flavor = "multi_thread")]
    async fn test_add_credential_upgrades_multiple_format() {
        let path = tmp_creds_path("add_cred_upgrade");
        std::fs::write(&path, "[]").unwrap();

        let manager =
            MultiTokenManager::new(Config::default(), vec![], None, Some(path.clone()), false)
                .unwrap();

        assert!(!manager.is_multiple_format.load(Ordering::Relaxed));

        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some("ksk_test_upgrade_key".to_string());
        cred.auth_method = Some("api_key".to_string());

        manager.add_credential(cred).await.unwrap();

        assert!(
            manager.is_multiple_format.load(Ordering::Relaxed),
            "add_credential 后 is_multiple_format 应升级为 true"
        );

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.trim_start().starts_with('['),
            "add_credential 后文件应为数组格式"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_add_credential_does_not_reuse_deleted_id() {
        let path = tmp_creds_path("add_cred_no_reuse_deleted_id");
        let mut cred1 = KiroCredentials::default();
        cred1.id = Some(1);
        cred1.kiro_api_key = Some("ksk_existing_1".to_string());
        cred1.auth_method = Some("api_key".to_string());

        let mut cred2 = KiroCredentials::default();
        cred2.id = Some(2);
        cred2.kiro_api_key = Some("ksk_existing_2".to_string());
        cred2.auth_method = Some("api_key".to_string());

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred1, cred2],
            None,
            Some(path.clone()),
            true,
        )
        .unwrap();

        manager.delete_credential(2).unwrap();

        let mut new_cred = KiroCredentials::default();
        new_cred.kiro_api_key = Some("ksk_new_3".to_string());
        new_cred.auth_method = Some("api_key".to_string());

        let new_id = manager.add_credential(new_cred).await.unwrap();
        assert_eq!(
            new_id, 3,
            "new credential IDs must not reuse deleted IDs, otherwise historical failure logs attach to the new account"
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── 并发去重（TOCTOU 回归守卫） ───────────────────────────────────────────

    /// 并发添加多个相同的 API Key 凭据，必须只插入一条。
    ///
    /// `add_credential` 的去重预检（步骤 2）与插入（步骤 5）不在同一临界区，
    /// token 刷新（网络）在锁外完成。8 个并发任务极易有多个同时通过预检，
    /// 此时不带"插入点权威重检"的实现会让重复凭据全部插入。本测试即为此回归守卫。
    /// 选用 API Key 凭据是为了跳过网络刷新，使竞态可在纯本地复现。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_add_same_api_key_inserts_once() {
        let path = tmp_creds_path("concurrent_dedup");
        let manager = Arc::new(
            MultiTokenManager::new(Config::default(), vec![], None, Some(path.clone()), true).unwrap(),
        );

        const N: usize = 8;
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let m = Arc::clone(&manager);
            handles.push(tokio::spawn(async move {
                let mut c = KiroCredentials::default();
                c.kiro_api_key = Some("ksk_duplicate".to_string());
                c.auth_method = Some("api_key".to_string());
                m.add_credential(c).await
            }));
        }

        let mut ok_count = 0_usize;
        for h in handles {
            if h.await.unwrap().is_ok() {
                ok_count += 1;
            }
        }
        assert_eq!(ok_count, 1, "并发添加同一凭据应只成功一次，实际成功 {ok_count} 次");

        let snapshot = manager.snapshot();
        assert_eq!(
            snapshot.entries.len(),
            1,
            "应只插入一条相同凭据，实际 {} 条",
            snapshot.entries.len()
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── try_reload_credential_from_file ─────────────────────────────────────

    /// 文件中有新 refreshToken 时，reload 返回 true 并更新内存凭据
    #[test]
    fn test_reload_from_file_succeeds_when_token_rotated() {
        let path = tmp_creds_path("reload_rotated");

        // 初始 token
        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.refresh_token = Some("original_token_aaaa".repeat(10));
        let initial_json = serde_json::to_vec_pretty(&[&cred]).unwrap();
        std::fs::write(&path, &initial_json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            true,
        )
        .unwrap();

        // 模拟 IDE rotation：文件写入新 token
        let mut updated_cred = KiroCredentials::default();
        updated_cred.id = Some(1);
        updated_cred.refresh_token = Some("rotated_token_bbbb".repeat(10));
        updated_cred.access_token = Some("new_access".to_string());
        let updated_json = serde_json::to_vec_pretty(&[&updated_cred]).unwrap();
        std::fs::write(&path, &updated_json).unwrap();

        let reloaded = manager.try_reload_credential_from_file(1);
        assert!(reloaded, "文件中有新 token，reload 应返回 true");

        let snapshot = manager.snapshot();
        let entry = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(!entry.disabled, "reload 后凭据应重新启用");
        assert_eq!(entry.failure_count, 0);

        let _ = std::fs::remove_file(&path);
    }

    /// 文件 token 与内存相同时，reload 返回 false（无更新可用）
    #[test]
    fn test_reload_from_file_returns_false_when_token_unchanged() {
        let path = tmp_creds_path("reload_unchanged");

        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.refresh_token = Some("same_token".repeat(15));
        let json = serde_json::to_vec_pretty(&[&cred]).unwrap();
        std::fs::write(&path, &json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            true,
        )
        .unwrap();

        let reloaded = manager.try_reload_credential_from_file(1);
        assert!(!reloaded, "token 未变化，reload 应返回 false");

        let _ = std::fs::remove_file(&path);
    }

    /// 未配置 credentials_path 时，reload 返回 false
    #[test]
    fn test_reload_from_file_returns_false_without_path() {
        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.refresh_token = Some("some_token".repeat(15));

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            None, // 无文件路径
            false,
        )
        .unwrap();

        let reloaded = manager.try_reload_credential_from_file(1);
        assert!(!reloaded, "无 credentials_path 时应返回 false");
    }

    /// 单凭据文件无 ID 字段时，通过单凭据规则匹配
    #[test]
    fn test_reload_from_file_single_credential_no_id() {
        let path = tmp_creds_path("reload_single_no_id");

        // 初始：无 ID 字段
        let mut cred = KiroCredentials::default();
        cred.refresh_token = Some("original_no_id".repeat(10));
        let initial_json = serde_json::to_vec_pretty(&[&cred]).unwrap();
        std::fs::write(&path, &initial_json).unwrap();

        let manager = MultiTokenManager::new(
            Config::default(),
            vec![cred],
            None,
            Some(path.clone()),
            true,
        )
        .unwrap();

        // 文件更新为新 token（无 ID）
        let mut updated = KiroCredentials::default();
        updated.refresh_token = Some("rotated_no_id".repeat(10));
        let updated_json = serde_json::to_vec_pretty(&[&updated]).unwrap();
        std::fs::write(&path, &updated_json).unwrap();

        // 获取实际 ID（manager 自动分配）
        let actual_id = manager.snapshot().entries[0].id;
        let reloaded = manager.try_reload_credential_from_file(actual_id);
        assert!(reloaded, "单凭据无 ID 时仍应能匹配并 reload");

        let _ = std::fs::remove_file(&path);
    }

    // ===== 账号分组隔离回归测试 =====

    /// 构造一个带 token、属于指定分组的可用凭据
    fn grouped_cred(token: &str, groups: &[&str]) -> KiroCredentials {
        let mut c = KiroCredentials::default();
        c.access_token = Some(token.to_string());
        c.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());
        c.groups = groups.iter().map(|s| s.to_string()).collect();
        c
    }

    #[test]
    fn test_group_matches_helper() {
        // 未绑定分组(None)匹配任何账号
        assert!(group_matches(&[], None));
        assert!(group_matches(&["g1".to_string()], None));
        // 绑定分组时只匹配 groups 含该名的账号
        assert!(group_matches(&["g1".to_string(), "g2".to_string()], Some("g1")));
        assert!(!group_matches(&["g2".to_string()], Some("g1")));
        assert!(!group_matches(&[], Some("g1")));
    }

    #[test]
    fn test_select_next_credential_filters_by_group() {
        // A∈g1, B∈g2, C∈无分组
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g2"]),
                grouped_cred("c", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        // g1 只能选到 A(id=1)
        let g1 = manager.select_next_credential(None, Some("g1"));
        assert_eq!(g1.map(|(id, _)| id), Some(1));
        // g2 只能选到 B(id=2)
        let g2 = manager.select_next_credential(None, Some("g2"));
        assert_eq!(g2.map(|(id, _)| id), Some(2));
        // 不存在的分组 → 无可用账号
        assert!(manager.select_next_credential(None, Some("nope")).is_none());
        // 未绑定分组(None) → 可选到账号
        assert!(manager.select_next_credential(None, None).is_some());
    }

    #[tokio::test]
    async fn test_acquire_context_priority_current_respects_model_support() {
        let mut free_cred = grouped_cred("free", &[]);
        free_cred.subscription_title = Some("KIRO FREE".to_string());

        let mut pro_cred = grouped_cred("pro", &[]);
        pro_cred.subscription_title = Some("KIRO PRO".to_string());
        pro_cred.priority = 10;

        let manager =
            MultiTokenManager::new(Config::default(), vec![free_cred, pro_cred], None, None, false)
                .unwrap();

        // Warm current_id with the highest-priority Free account.
        let current = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(current.id, 1);

        let opus = manager
            .acquire_context(Some("claude-opus-4.6"), None, None)
            .await
            .unwrap();
        assert_eq!(
            opus.id, 2,
            "priority current_id must not bypass Opus subscription filtering"
        );
    }

    /// 并发槽位：请求结束（ctx 析构）后 in_flight 必须归零，不泄漏。
    #[tokio::test]
    async fn test_concurrency_slot_releases_on_drop() {
        let cred = grouped_cred("c1", &[]);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        {
            let ctx = manager.acquire_context(None, None, None).await.unwrap();
            let snap = manager.snapshot();
            assert_eq!(snap.entries[0].in_flight, 1, "占用后 in_flight 应为 1");
            drop(ctx);
        }
        let snap = manager.snapshot();
        assert_eq!(snap.entries[0].in_flight, 0, "ctx 析构后 in_flight 应归零");
    }

    /// 并发槽位：通过 take 转移到外部持有者后，原 ctx 析构不应释放，
    /// 只有转移后的持有者析构时才释放。这是 KiroProvider → KiroCallResult →
    /// 流式消费 整条链路的核心契约（见 docs/endpoint-and-cooldown-redesign.md
    /// Phase 3）。
    #[tokio::test]
    async fn test_concurrency_slot_transfers_via_take() {
        let cred = grouped_cred("c1", &[]);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        let mut ctx = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(
            manager.snapshot().entries[0].in_flight,
            1,
            "acquire 后 in_flight 应为 1"
        );

        // 模拟 KiroProvider 成功路径：把 slot 从 ctx 转移给 KiroCallResult
        let moved_slot = ctx._slot.take();
        assert!(moved_slot.is_some(), "take 后应拿到 slot");
        drop(ctx);
        assert_eq!(
            manager.snapshot().entries[0].in_flight,
            1,
            "ctx 内 _slot=None，析构不应递减计数"
        );

        // 模拟流式消费结束：转移后的持有者析构
        drop(moved_slot);
        assert_eq!(
            manager.snapshot().entries[0].in_flight,
            0,
            "moved slot 析构后 in_flight 必须归零"
        );
    }

    /// 错误冷却：窗口阈值前不应触发冷却（容忍单次抖动）。
    #[tokio::test]
    async fn test_throttle_window_below_threshold_no_cooldown() {
        let cred = grouped_cred("c1", &[]);
        let mut config = Config::default();
        // 5s 窗口、5 次阈值（默认值，显式声明便于阅读）
        config.error_cooldown_policy.error_window_secs = 60;
        config.error_cooldown_policy.error_threshold = 5;
        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        let id = manager.snapshot().entries[0].id;

        for _ in 0..4 {
            manager.report_account_throttled(id, StdDuration::from_secs(0));
        }
        assert!(
            manager.snapshot().entries[0].throttled_remaining_secs.is_none(),
            "4 次错误（< 阈值 5）不应触发冷却"
        );
    }

    /// 错误冷却：达阈值才触发；冷却时长走 policy.cooldown_secs，与入参 cooldown 无关。
    #[tokio::test]
    async fn test_throttle_window_at_threshold_triggers_cooldown() {
        let cred = grouped_cred("c1", &[]);
        let mut config = Config::default();
        config.error_cooldown_policy.error_window_secs = 60;
        config.error_cooldown_policy.error_threshold = 3;
        config.error_cooldown_policy.cooldown_secs = 600;
        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        let id = manager.snapshot().entries[0].id;

        for _ in 0..3 {
            // 入参传 0 但实际冷却时长应来自 policy
            manager.report_account_throttled(id, StdDuration::from_secs(0));
        }
        let snap = manager.snapshot();
        let remaining_secs = snap.entries[0]
            .throttled_remaining_secs
            .expect("3 次累计 = 阈值 → 应触发冷却");
        assert!(
            remaining_secs > 500,
            "冷却时长应取 policy.cooldown_secs=600，实际剩余 {} 秒",
            remaining_secs
        );
    }

    /// 错误冷却：累计触发达阈值后整号自动 disable（避免长期慢号反复短冷却）。
    #[tokio::test]
    async fn test_repeated_trips_auto_disable() {
        let cred = grouped_cred("c1", &[]);
        let mut config = Config::default();
        // 极小阈值便于测试：1 次错误就 trip，3 次 trip 就 disable
        config.error_cooldown_policy.error_window_secs = 60;
        config.error_cooldown_policy.error_threshold = 1;
        config.error_cooldown_policy.cooldown_secs = 1;
        config.error_cooldown_policy.auto_disable_after_trips = 3;
        config.error_cooldown_policy.disable_window_secs = 3600;
        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        let id = manager.snapshot().entries[0].id;

        for _ in 0..2 {
            manager.report_account_throttled(id, StdDuration::from_secs(0));
        }
        assert!(
            !manager.snapshot().entries[0].disabled,
            "2 次 trip 不到 disable 阈值（3）"
        );

        manager.report_account_throttled(id, StdDuration::from_secs(0));
        assert!(
            manager.snapshot().entries[0].disabled,
            "3 次 trip = 阈值 → 整号应自动 disable"
        );
        assert_eq!(
            manager.snapshot().entries[0].disabled_reason.as_deref(),
            Some("AutoThrottled")
        );
    }

    /// 凭据级覆盖：单凭据 cooldown_override 优先于全局策略。
    #[tokio::test]
    async fn test_credential_cooldown_override() {
        let mut cred = grouped_cred("c1", &[]);
        // 凭据级覆盖：阈值 = 2（全局是 5）
        cred.cooldown_override = Some(crate::kiro::model::credentials::PartialCooldownPolicy {
            error_threshold: Some(2),
            ..Default::default()
        });
        let mut config = Config::default();
        config.error_cooldown_policy.error_threshold = 5;
        config.error_cooldown_policy.cooldown_secs = 600;
        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        let id = manager.snapshot().entries[0].id;

        manager.report_account_throttled(id, StdDuration::from_secs(0));
        assert!(
            manager.snapshot().entries[0].throttled_remaining_secs.is_none(),
            "1 次 < 凭据级阈值 2"
        );

        manager.report_account_throttled(id, StdDuration::from_secs(0));
        assert!(
            manager.snapshot().entries[0].throttled_remaining_secs.is_some(),
            "2 次 = 凭据级阈值（不是全局 5），应触发冷却"
        );
    }

    /// 并发上限：单账号达上限后无法再获取（满则跳过，无其他账号时全灭）。
    #[tokio::test]
    async fn test_concurrency_limit_blocks_when_full() {
        let mut cred = grouped_cred("c1", &[]);
        cred.concurrency_limit = Some(2);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        let c1 = manager.acquire_context(None, None, None).await.unwrap();
        let c2 = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(manager.snapshot().entries[0].in_flight, 2);

        // 第三个请求：唯一账号已满 → 应失败
        let c3 = manager.acquire_context(None, None, None).await;
        assert!(c3.is_err(), "账号并发已满且无其他账号，应获取失败");

        // 释放一个后可再获取
        drop(c1);
        let c4 = manager.acquire_context(None, None, None).await;
        assert!(c4.is_ok(), "释放槽位后应能再次获取");
        drop(c2);
        drop(c4);
    }

    /// 并发上限：满账号被跳过，调度到另一个可用账号。
    #[tokio::test]
    async fn test_concurrency_limit_skips_to_next_credential() {
        let mut a = grouped_cred("a", &[]);
        a.priority = 0;
        a.concurrency_limit = Some(1);
        let mut b = grouped_cred("b", &[]);
        b.priority = 1;
        b.concurrency_limit = Some(5);
        let manager =
            MultiTokenManager::new(Config::default(), vec![a, b], None, None, false).unwrap();

        // 第一个请求命中优先级最高的 a
        let c1 = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(c1.id, 1);

        // a 已满（limit=1）→ 第二个请求应跳到 b
        let c2 = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(c2.id, 2, "a 并发已满，应跳到 b");
        drop(c1);
        drop(c2);
    }

    /// clear_concurrency 强制清零计数。
    #[tokio::test]
    async fn test_clear_concurrency_resets_count() {
        let cred = grouped_cred("c1", &[]);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        let _c1 = manager.acquire_context(None, None, None).await.unwrap();
        assert_eq!(manager.snapshot().entries[0].in_flight, 1);

        assert!(manager.clear_concurrency(1), "应命中账号");
        assert_eq!(
            manager.snapshot().entries[0].in_flight,
            0,
            "clear 后应归零"
        );
        // 不存在的账号返回 false
        assert!(!manager.clear_concurrency(999));
    }

    /// record_request_metrics：EWMA 计算 / credits 累加 / 失败不更新 EWMA。
    #[test]
    fn test_record_request_metrics() {
        let cred = grouped_cred("c1", &[]);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        // 首个成功样本：EWMA = 该样本
        manager.record_request_metrics(1, 1000, 0.5, true);
        let s = manager.snapshot();
        let e = &s.entries[0];
        assert_eq!(e.ewma_latency_ms, Some(1000.0));
        assert_eq!(e.billed_requests, 1);
        assert!((e.accrued_cost - 0.5).abs() < 1e-9);

        // 第二个成功样本 2000ms：EWMA = 0.2*2000 + 0.8*1000 = 1200
        manager.record_request_metrics(1, 2000, 0.5, true);
        let s = manager.snapshot();
        let e = &s.entries[0];
        assert!((e.ewma_latency_ms.unwrap() - 1200.0).abs() < 1e-9);
        assert_eq!(e.billed_requests, 2);
        assert!((e.accrued_cost - 1.0).abs() < 1e-9);

        // 失败请求：不更新 EWMA；credits=0 不计价
        manager.record_request_metrics(1, 9999, 0.0, false);
        let s = manager.snapshot();
        let e = &s.entries[0];
        assert!(
            (e.ewma_latency_ms.unwrap() - 1200.0).abs() < 1e-9,
            "失败请求不应污染 EWMA"
        );
        assert_eq!(e.billed_requests, 2, "credits=0 不计价");
        assert!((e.accrued_cost - 1.0).abs() < 1e-9);
    }

    /// record_dispatch：计数 + 窗口统计 + cap 1000 弹出。
    #[tokio::test]
    async fn test_record_dispatch_and_recent_windows() {
        let cred = grouped_cred("c1", &[]);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        for _ in 0..5 {
            manager.record_dispatch(1);
        }
        let s = manager.snapshot();
        let e = &s.entries[0];
        assert_eq!(e.total_dispatch, 5);
        assert_eq!(e.recent_dispatch_10s, 5, "刚记录的应落在 10s 窗口");
        assert_eq!(e.recent_dispatch_60s, 5);
        assert_eq!(e.recent_dispatch_5m, 5);
    }

    /// record_dispatch 环形缓冲上限 1000：total 持续增长，窗口数不超过 1000。
    #[tokio::test]
    async fn test_dispatch_ring_buffer_cap() {
        let cred = grouped_cred("c1", &[]);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        for _ in 0..1200 {
            manager.record_dispatch(1);
        }
        let s = manager.snapshot();
        let e = &s.entries[0];
        assert_eq!(e.total_dispatch, 1200, "total 累计不受缓冲上限影响");
        assert_eq!(e.recent_dispatch_5m, 1000, "环形缓冲上限 1000");
    }

    /// compute_dispatch_score 公式验算。
    #[test]
    fn test_compute_dispatch_score() {
        // 全成功、并发全空闲、无 EWMA：100 + 20 - 0 = 120
        assert!((compute_dispatch_score(10, 0, 0, 10, None) - 120.0).abs() < 1e-9);
        // 全成功、并发占满、无 EWMA：100 + 0 - 0 = 100
        assert!((compute_dispatch_score(10, 0, 10, 10, None) - 100.0).abs() < 1e-9);
        // 50% 成功率、全空闲、EWMA 1000ms：50 + 20 - 10 = 60
        assert!((compute_dispatch_score(5, 5, 0, 10, Some(1000.0)) - 60.0).abs() < 1e-9);
        // EWMA 惩罚封顶 50：100 + 20 - 50 = 70（ewma 10000ms → penalty 100 但封顶 50）
        assert!((compute_dispatch_score(1, 0, 0, 10, Some(10000.0)) - 70.0).abs() < 1e-9);
        // 无样本视为成功率 1.0
        assert!((compute_dispatch_score(0, 0, 0, 10, None) - 120.0).abs() < 1e-9);
    }

    #[test]
    fn test_total_count_in_group() {
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g1", "g2"]),
                grouped_cred("c", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        assert_eq!(manager.total_count_in_group(Some("g1")), 2); // A,B
        assert_eq!(manager.total_count_in_group(Some("g2")), 1); // B
        assert_eq!(manager.total_count_in_group(None), 3); // 全部
        assert_eq!(manager.total_count_in_group(Some("none")), 0);
    }

    #[test]
    fn test_balanced_mode_independent_per_group() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();
        // g1: A(id1),B(id2)；g2: C(id3)
        let manager = MultiTokenManager::new(
            config,
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g1"]),
                grouped_cred("c", &["g2"]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        // 让 A(id1) 成功若干次 → balanced 应转向 success_count 更小的 B(id2)
        manager.report_success(1);
        manager.report_success(1);
        let pick = manager.select_next_credential(None, Some("g1"));
        assert_eq!(pick.map(|(id, _)| id), Some(2), "balanced 应在 g1 内选 success_count 最小的 B");
        // g2 不受 g1 计数影响，仍只会选到 C(id3)
        let pick_g2 = manager.select_next_credential(None, Some("g2"));
        assert_eq!(pick_g2.map(|(id, _)| id), Some(3));
    }

    #[tokio::test]
    async fn test_acquire_context_strict_isolation_fails_when_group_empty() {
        // g1 只有一个账号 A(id1)，禁用后绑定 g1 的请求应直接失败，不回退到 g2/无分组
        let manager = MultiTokenManager::new(
            Config::default(),
            vec![
                grouped_cred("a", &["g1"]),
                grouped_cred("b", &["g2"]),
                grouped_cred("c", &[]),
            ],
            None,
            None,
            false,
        )
        .unwrap();

        // 正常情况下 g1 能拿到 context
        assert!(manager.acquire_context(None, Some("g1"), None).await.is_ok());

        // 手动禁用 g1 内唯一账号 A(id1)
        manager.set_disabled(1, true).unwrap();

        // 严格隔离：g1 无可用账号 → Err，且不会选到 B/C
        let res = manager.acquire_context(None, Some("g1"), None).await;
        assert!(res.is_err(), "g1 内全部账号禁用后应失败，不回退到其他分组");

        // 但 g2 仍可用
        assert!(manager.acquire_context(None, Some("g2"), None).await.is_ok());
    }
}
