//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多凭据故障转移和重试
//! 支持按凭据级 endpoint 切换不同 Kiro API 端点

use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::admin::trace_db::{TraceAttempt, TraceSink, outcome, truncate_snippet};
use crate::http_client::{ProxyConfig, build_client, build_streaming_client, http_shard_count};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::error::UpstreamRateLimitError;
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::MultiTokenManager;
use crate::model::config::TlsBackend;
use parking_lot::Mutex;

/// 每个凭据的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
///
/// 注：上游 429 多为账号级速率配额（SERVICE_REQUEST_RATE_EXCEEDED），高峰期
/// 多账号同时触顶时，过多重试会在账号间连环撞墙、放大限流。故上限取较小值，
/// 配合 429 专用长退避（见 retry_delay_throttle），被限时尽早返回而非耗尽配额。
const MAX_TOTAL_RETRIES: usize = 4;

/// HTTP Client 缓存容量上限（不含常驻的全局代理 client）。
/// 代理池条目较多时，避免每个不同代理都常驻一个 reqwest::Client 导致内存无界增长。
const CLIENT_CACHE_CAP: usize = 64;

/// 一个账户（一个 effective proxy）的 HTTP Client **分片集**：N 个独立 `Client`，每个各自一条
/// 到上游 host 的 HTTP/2 连接。`pick()` 按原子游标 round-robin 选一个,把同账户的并发请求摊到
/// N 条独立连接上——复现"多进程各自一条连接"的并行度,根治单 H2 连接多路复用的首字节瓶颈。
/// 见 [`crate::http_client::http_shard_count`]。
struct ShardSet {
    clients: Vec<Client>,
    cursor: AtomicUsize,
}

impl ShardSet {
    fn new(clients: Vec<Client>) -> Self {
        debug_assert!(!clients.is_empty(), "ShardSet 至少要有一个 client");
        Self {
            clients,
            cursor: AtomicUsize::new(0),
        }
    }

    /// round-robin 取一个 client(clone 廉价,内部是 Arc)。
    fn pick(&self) -> Client {
        let n = self.clients.len().max(1);
        let i = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        self.clients[i].clone()
    }
}

/// 构建 N 个分片 client(`build` 为单个 client 的构造闭包),组装成 [`ShardSet`]。
fn build_shard_set<F>(mut build: F) -> anyhow::Result<ShardSet>
where
    F: FnMut() -> anyhow::Result<Client>,
{
    let n = http_shard_count();
    let mut clients = Vec::with_capacity(n);
    for _ in 0..n {
        clients.push(build()?);
    }
    Ok(ShardSet::new(clients))
}

/// 带容量上限的 HTTP Client 缓存。
///
/// - key 为 effective proxy 配置（None = 直连/全局回退）
/// - value 为该账户的 [`ShardSet`](N 个独立 Client, round-robin 摊连接)
/// - 受保护 key（全局代理对应的 effective 配置）永不被淘汰
/// - 超出容量时按插入顺序淘汰最旧的「非受保护」条目
struct ClientCache {
    map: HashMap<Option<ProxyConfig>, ShardSet>,
    /// 插入顺序（仅记录可淘汰的非受保护 key）
    order: std::collections::VecDeque<Option<ProxyConfig>>,
    /// 受保护、不参与淘汰的 key（全局代理）
    protected: Option<ProxyConfig>,
    cap: usize,
}

impl ClientCache {
    fn new(protected: Option<ProxyConfig>, initial: ShardSet, cap: usize) -> Self {
        let mut map = HashMap::new();
        map.insert(protected.clone(), initial);
        Self {
            map,
            order: std::collections::VecDeque::new(),
            protected,
            cap,
        }
    }

    /// round-robin 取该 key 分片集里的一个 client。
    fn get(&self, key: &Option<ProxyConfig>) -> Option<Client> {
        self.map.get(key).map(|s| s.pick())
    }

    /// 插入新分片集,必要时淘汰最旧的非受保护条目
    fn insert(&mut self, key: Option<ProxyConfig>, shard: ShardSet) {
        if key == self.protected || self.map.contains_key(&key) {
            self.map.insert(key, shard);
            return;
        }
        while self.order.len() >= self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, shard);
    }
}

/// API 调用结果，附带本次实际命中的上游凭据 ID（用于用量统计）
pub struct KiroCallResult {
    pub response: reqwest::Response,
    pub credential_id: u64,
    /// 并发槽位守卫，从 CallContext 转移而来。
    /// 持有期 = 上游响应消费的整个生命周期：流式时跟随 SSE unfold state、
    /// 非流式时跟随 `response.bytes()`。Drop 时对凭据 in_flight -1。
    /// 命名以 `_` 起头表明外部不直接读，靠 RAII 释放。
    pub _slot: Option<crate::kiro::token_manager::ConcurrencySlot>,
}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多凭据故障转移和重试机制
/// 按凭据 `endpoint` 字段选择 [`KiroEndpoint`] 实现
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于凭据无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// 非流式 Client 缓存：key = effective proxy config, value = ShardSet(N 条独立 H2 连接)
    /// 不同代理配置的凭据使用不同的 Client,共享相同代理的凭据复用 Client。
    /// 带容量上限淘汰（全局代理 client 常驻），避免代理数量增长导致内存无界增长。
    client_cache: Mutex<ClientCache>,
    /// 流式专用 Client 缓存(同结构,用 build_streaming_client 构建,H2 keepalive 保活)。
    /// 流式路径独立分片,与非流式解耦——同一 credential 的流式和非流式请求走不同的 H2 连接组。
    streaming_client_cache: Mutex<ClientCache>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 端点实现注册表（key: endpoint 名称）
    endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
    /// 已尝试过 profileArn 解析的凭据 ID（进程内）。
    ///
    /// 避免对「无 Enterprise profile」的账号（如纯 BuilderID）在每次请求都重复调用
    /// `ListAvailableProfiles`。命中真实 ARN 的账号会把 ARN 持久化进凭据，之后
    /// 通过 `streaming_profile_arn()` 直接命中，不再进入解析路径。
    profile_resolution_attempted: Mutex<HashSet<u64>>,
}

impl KiroProvider {
    /// 创建带代理配置和端点注册表的 KiroProvider 实例
    ///
    /// # Arguments
    /// * `token_manager` - 多凭据 Token 管理器
    /// * `proxy` - 全局代理配置
    /// * `endpoints` - 端点名 → 实现的注册表（至少包含 `default_endpoint` 对应条目）
    /// * `default_endpoint` - 凭据未显式指定 endpoint 时使用的名称
    pub fn with_proxy(
        token_manager: Arc<MultiTokenManager>,
        proxy: Option<ProxyConfig>,
        endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
        default_endpoint: String,
    ) -> Self {
        assert!(
            endpoints.contains_key(&default_endpoint),
            "默认端点 {} 未在 endpoints 注册表中",
            default_endpoint
        );
        let tls_backend = token_manager.config().tls_backend;
        // 预热:构建全局代理对应的分片集(N 条独立 H2 连接,作为受保护的常驻条目)。
        let initial_shard = build_shard_set(|| build_client(proxy.as_ref(), 720, tls_backend))
            .expect("创建 HTTP 客户端失败");
        let client_cache = ClientCache::new(proxy.clone(), initial_shard, CLIENT_CACHE_CAP);
        // 流式专用分片集同样预热全局代理条目。
        let initial_streaming_shard =
            build_shard_set(|| build_streaming_client(proxy.as_ref(), 720, tls_backend))
                .expect("创建流式 HTTP 客户端失败");
        let streaming_client_cache =
            ClientCache::new(proxy.clone(), initial_streaming_shard, CLIENT_CACHE_CAP);

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(client_cache),
            streaming_client_cache: Mutex::new(streaming_client_cache),
            tls_backend,
            endpoints,
            profile_resolution_attempted: Mutex::new(HashSet::new()),
        }
    }

    /// 根据凭据的代理配置获取（或创建并缓存）对应的**非流式** reqwest::Client。
    /// 返回的 Client 是从该账户 ShardSet 里 round-robin 取的一个,同账户并发会摊到 N 条独立连接。
    fn client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client);
        }
        let shard = build_shard_set(|| build_client(effective.as_ref(), 720, self.tls_backend))?;
        let client = shard.pick();
        cache.insert(effective, shard);
        Ok(client)
    }

    /// 根据凭据的代理配置获取（或创建并缓存）对应的**流式** reqwest::Client。
    /// 走 [`build_streaming_client`](H2 keepalive 保活),从独立的 streaming_client_cache 分片集取。
    /// 与 [`Self::client_for`] 使用完全独立的 H2 连接组,防止流式长时间占用连接影响非流式辅助请求。
    fn streaming_client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.streaming_client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client);
        }
        let shard =
            build_shard_set(|| build_streaming_client(effective.as_ref(), 720, self.tls_backend))?;
        let client = shard.pick();
        cache.insert(effective, shard);
        Ok(client)
    }

    /// 根据凭据选择 endpoint 实现
    fn endpoint_for(
        &self,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        // 凭据级 endpoint 优先；否则用 token_manager 的运行时默认值（可被 Admin 动态修改）
        let runtime_default = self.token_manager.get_default_endpoint();
        let name = credentials
            .endpoint
            .as_deref()
            .unwrap_or(&runtime_default);
        self.endpoints
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未知端点: {}", name))
    }

    /// 端点降级链：runtime → ide → codewhisperer。
    ///
    /// AWS 后台对 `runtime.{region}.kiro.dev` / `q.{region}.amazonaws.com`
    /// / `codewhisperer.{region}.amazonaws.com` 三个 host + 服务 target 各自
    /// **独立限流**——某个桶被击穿时切到下一桶大概率能通。参考 Kiro-Go 三桶策略。
    ///
    /// 语义：**错误驱动、逐级下探**。当前桶被 400/403/429 拒后调本函数拿到下一个桶，
    /// 若下一桶也被拒可递归再调（provider.rs 里循环即可）。
    /// 链尾（`codewhisperer` / `ide`/`cli` 未开 fallback）返回 `None`。
    ///
    /// 开关读取顺序（凭据级 > 全局）：
    /// 1. `credentials.runtime_fallback = Some(true)` → 强制开（即使全局关）
    /// 2. `credentials.runtime_fallback = Some(false)` → 强制关（即使全局开）
    /// 3. `credentials.runtime_fallback = None` → 跟随 token_manager 的全局开关
    fn fallback_endpoint(
        &self,
        current: &str,
        credentials: &KiroCredentials,
    ) -> Option<Arc<dyn KiroEndpoint>> {
        let enabled = credentials
            .runtime_fallback
            .unwrap_or_else(|| self.token_manager.get_runtime_fallback_enabled());
        if !enabled {
            return None;
        }
        match current {
            "runtime" => self.endpoints.get("ide").cloned(),
            "ide" => self.endpoints.get("codewhisperer").cloned(),
            _ => None,
        }
    }

    /// 暴露内部的 token_manager（供请求收尾时记录每账号性能指标）。
    pub fn token_manager(&self) -> &Arc<MultiTokenManager> {
        &self.token_manager
    }

    /// 在发起请求前，确保 Enterprise / IdC 账号的真实 profileArn 已解析并写入 `ctx`。
    ///
    /// 流式端点强制要求 profileArn；Enterprise / IdC 账号必须先把 BuilderID
    /// 占位符解析为真实 ARN，纯 BuilderID 账号则回退占位符。
    /// 仅对「OAuth 凭据 + profileArn 缺失或为占位符」的账号触发一次上游
    /// `ListAvailableProfiles` 查询（进程内去重）：
    /// - 命中真实 ARN → 写回 `ctx.credentials.profile_arn` 并由 token_manager 持久化；
    ///   之后该凭据的 `streaming_profile_arn()` 直接命中，不再进入此路径。
    /// - 无 Enterprise profile（纯 BuilderID 等）→ 保持占位符回退逻辑，并标记已尝试，
    ///   避免每次请求重复查询。
    async fn ensure_profile_arn(&self, ctx: &mut crate::kiro::token_manager::CallContext) {
        use crate::kiro::model::credentials::is_placeholder_profile_arn;

        if ctx.credentials.is_api_key_credential() {
            return;
        }
        let needs = match ctx.credentials.profile_arn.as_deref() {
            None => true,
            Some(arn) => is_placeholder_profile_arn(arn),
        };
        if !needs {
            return;
        }
        // 进程内去重：仅在「拿到上游确定结果」后才标记已尝试，避免一次网络抖动
        // 把账号永久卡在占位符上（重启前不再重试）。
        if self.profile_resolution_attempted.lock().contains(&ctx.id) {
            return;
        }
        match self
            .token_manager
            .resolve_profile_arn_for(ctx.id, &ctx.token)
            .await
        {
            Ok(Some(arn)) => {
                ctx.credentials.profile_arn = Some(arn);
                self.profile_resolution_attempted.lock().insert(ctx.id);
            }
            Ok(None) => {
                // 上游确认该账号无 Enterprise profile（纯 BuilderID 等）：标记已尝试，
                // 后续请求回退到占位符逻辑，不再重复查询。
                self.profile_resolution_attempted.lock().insert(ctx.id);
            }
            Err(e) => {
                // 网络/瞬态错误：不标记，下次请求再试；本次按原 profileArn 继续
                tracing::warn!("凭据 #{} 解析真实 profileArn 失败（按原 profileArn 继续）: {}", ctx.id, e);
            }
        }
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多凭据故障转移（见 [`Self::call_api_with_retry`]）。
    /// `sink` 可选，用于逐跳上报链路追踪。
    pub async fn call_api(
        &self,
        request_body: &str,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        self.call_api_with_retry(request_body, false, sink, group).await
    }

    /// 发送流式 API 请求
    pub async fn call_api_stream(
        &self,
        request_body: &str,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        self.call_api_with_retry(request_body, true, sink, group).await
    }

    /// 发送 MCP API 请求（WebSearch 等工具调用）
    pub async fn call_mcp(
        &self,
        request_body: &str,
        group: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        self.call_mcp_with_retry(request_body, group).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(
        &self,
        request_body: &str,
        group: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();

        for attempt in 0..max_retries {
            // MCP 调用（WebSearch 等工具）不涉及模型选择，也不参与分组隔离
            let ctx = match self.token_manager.acquire_context(None, group, None).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    // endpoint 解析失败：记为失败，换下一张凭据
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.mcp_url(&rctx);
            let body = endpoint.transform_mcp_body(request_body, &rctx);

            let base = self
                .client_for(&ctx.credentials)?
                .post(&url)
                .body(body)
                .header("content-type", endpoint.content_type());
            let request = endpoint.decorate_mcp(base, &rctx);

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "MCP 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();
            // `Response::text` 会消费 response，先保存 Retry-After。该值来自已通过
            // HTTP header 校验的上游响应，适配层仍会在写回前再次校验。
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);

            // 成功响应
            if status.is_success() {
                self.token_manager.report_success(ctx.id);
                return Ok(response);
            }

            // 失败响应
            let body = response.text().await.unwrap_or_default();

            // ─── MCP 端点降级（runtime → ide）───────────────────────
            let endpoint_name_mcp = endpoint.name();
            if matches!(status.as_u16(), 400 | 403 | 429)
                && !endpoint.is_account_throttled(&body)
                && !endpoint.is_client_validation_error(&body)
            {
                // 链式端点降级 runtime → ide → codewhisperer
                let mut cur_name: &str = endpoint_name_mcp;
                while let Some(fallback) =
                    self.fallback_endpoint(cur_name, &ctx.credentials)
                {
                    let fb_name = fallback.name();
                    tracing::info!(
                        "MCP 端点降级 [{}] → [{}]（凭据 #{}，HTTP {}）",
                        cur_name,
                        fb_name,
                        ctx.id,
                        status.as_u16()
                    );
                    let fb_rctx = RequestContext {
                        credentials: &ctx.credentials,
                        token: &ctx.token,
                        machine_id: &machine_id,
                        config,
                    };
                    let fb_url = fallback.mcp_url(&fb_rctx);
                    let fb_body = fallback.transform_mcp_body(request_body, &fb_rctx);
                    let fb_base = self
                        .client_for(&ctx.credentials)?
                        .post(&fb_url)
                        .body(fb_body)
                        .header("content-type", fallback.content_type())
                        .header("Connection", "close");
                    let fb_request = fallback.decorate_mcp(fb_base, &fb_rctx);
                    match fb_request.send().await {
                        Ok(fb_resp) if fb_resp.status().is_success() => {
                            self.token_manager.report_success(ctx.id);
                            return Ok(fb_resp);
                        }
                        Ok(fb_resp) => {
                            tracing::warn!(
                                "MCP 降级端点 [{}] 也失败（HTTP {}），尝试链上下一桶",
                                fb_name,
                                fb_resp.status().as_u16()
                            );
                            cur_name = fb_name;
                            continue;
                        }
                        Err(fb_err) => {
                            tracing::warn!(
                                "MCP 降级端点 [{}] 网络错误: {}，尝试链上下一桶",
                                fb_name,
                                fb_err
                            );
                            cur_name = fb_name;
                            continue;
                        }
                    }
                }
            }
            // ─── MCP 端点降级结束 ────────────────────────────────────

            // 402 额度用尽
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 400 Bad Request
            if status.as_u16() == 400 {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 401/403 凭据问题
            if matches!(status.as_u16(), 401 | 403) {
                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self.token_manager.force_refresh_token_for(ctx.id).await.is_ok() {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 瞬态错误
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                tracing::warn!(
                    "MCP 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                last_error = if status.as_u16() == 429 {
                    Some(UpstreamRateLimitError::new(retry_after.clone()).into())
                } else {
                    Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body))
                };
                if attempt + 1 < max_retries {
                    // 429 限流用更长退避；408/5xx 仍用通用快速退避
                    let delay = if status.as_u16() == 429 {
                        Self::retry_delay_throttle(attempt)
                    } else {
                        Self::retry_delay(attempt)
                    };
                    sleep(delay).await;
                }
                continue;
            }

            // 其他 4xx
            if status.is_client_error() {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 兜底
            last_error = if status.as_u16() == 429 {
                Some(UpstreamRateLimitError::new(retry_after.clone()).into())
            } else {
                Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body))
            };
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("MCP 请求失败：已达到最大重试次数（{}次）", max_retries)
        }))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个凭据最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(凭据数量 × 每凭据重试次数, MAX_TOTAL_RETRIES)
    /// - 硬上限 9 次，避免无限重试
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
        sink: Option<&dyn TraceSink>,
        group: Option<&str>,
    ) -> anyhow::Result<KiroCallResult> {
        // 重试预算按当前请求所属分组的账号数计算，避免小分组按全局账号数获得过多无效重试
        let total_credentials = self.token_manager.total_count_in_group(group).max(1);
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息
        let model = Self::extract_model_from_request(request_body);
        // Session-Sticky：提取 conversationId，查 sticky map 得到上次使用的凭据
        let conversation_id = Self::extract_conversation_id(request_body);
        let sticky_id = conversation_id
            .as_deref()
            .and_then(|cid| self.token_manager.sticky_lookup(cid));

        for attempt in 0..max_retries {
            let attempt_start = Instant::now();
            // 获取调用上下文（绑定 index、credentials、token）
            let mut ctx = match self.token_manager.acquire_context(model.as_deref(), group, sticky_id).await {
                Ok(c) => c,
                Err(e) => {
                    Self::emit_attempt(
                        sink, attempt, 0, "", None, outcome::UNKNOWN,
                        Some(&e.to_string()), attempt_start,
                    );
                    last_error = Some(e);
                    continue;
                }
            };

            // 确保 Enterprise / IdC 账号的真实 profileArn 已解析（流式端点强制要求）
            self.ensure_profile_arn(&mut ctx).await;

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    Self::emit_attempt(
                        sink, attempt, ctx.id, "", None, outcome::UNKNOWN,
                        Some(&e.to_string()), attempt_start,
                    );
                    last_error = Some(e);
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };
            let endpoint_name = endpoint.name();

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.api_url(&rctx);
            let body = endpoint.transform_api_body(request_body, &rctx);

            tracing::debug!("使用端点 [{}] POST {}", endpoint.name(), url);
            tracing::debug!("实际发送请求体: {}", body);

            let base_client = if is_stream {
                self.streaming_client_for(&ctx.credentials)?
            } else {
                self.client_for(&ctx.credentials)?
            };
            let base = base_client
                .post(&url)
                .body(body)
                .header("content-type", endpoint.content_type());
            let request = endpoint.decorate_api(base, &rctx);

            // 打印实际发送的请求头（RUST_LOG=debug 时输出，便于排查问题）
            let request = request.build().map_err(|e| anyhow::anyhow!("构建请求失败: {}", e))?;
            if tracing::enabled!(tracing::Level::DEBUG) {
                for (k, v) in request.headers() {
                    tracing::debug!("  header {}: {}", k, v.to_str().unwrap_or("<binary>"));
                }
            }
            let http_client = if is_stream {
                self.streaming_client_for(&ctx.credentials)?
            } else {
                self.client_for(&ctx.credentials)?
            };
            let response = match http_client.execute(request).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "API 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    Self::emit_attempt(
                        sink, attempt, ctx.id, endpoint_name, None,
                        outcome::NETWORK_ERROR, Some(&e.to_string()), attempt_start,
                    );
                    // 网络错误通常是上游/链路瞬态问题，不应导致"禁用凭据"或"切换凭据"
                    // （否则一段时间网络抖动会把所有凭据都误禁用，需要重启才能恢复）
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();
            // `Response::text` 会消费 response，先保存 Retry-After。该值来自已通过
            // HTTP header 校验的上游响应，适配层仍会在写回前再次校验。
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);

            // 成功响应
            if status.is_success() {
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::SUCCESS, None, attempt_start,
                );
                self.token_manager.report_success(ctx.id);
                // Session-Sticky：记录本次成功使用的凭据，下次同 conversationId 优先复用。
                // token_manager 内部按 group 解析 cache_mode，Off 档自动 no-op。
                if let Some(cid) = conversation_id.as_deref() {
                    self.token_manager.sticky_record(cid, ctx.id, group);
                }
                return Ok(KiroCallResult {
                    response,
                    credential_id: ctx.id,
                    _slot: ctx._slot.take(),
                });
            }

            // 失败响应：读取 body 用于日志/错误信息
            let body = response.text().await.unwrap_or_default();

            // ─── 端点降级（runtime → ide）─────────────────────────────
            // runtime.{region}.kiro.dev 与 q.{region}.amazonaws.com 限流桶独立。
            // 当 runtime 返回 400/403/429 时，立即用 ide 端点重发同一请求——
            // 大概率能通（独立桶未被限流）。不消耗重试预算，不切换账号。
            if matches!(status.as_u16(), 400 | 403 | 429)
                && !endpoint.is_account_throttled(&body)
                && !endpoint.is_client_validation_error(&body)
            {
                // 链式端点降级 runtime → ide → codewhisperer：
                // 每桶都是 AWS 内部独立限流单元，逐级下探直到成功或链尾。
                let mut cur_name: &str = endpoint_name;
                while let Some(fallback) =
                    self.fallback_endpoint(cur_name, &ctx.credentials)
                {
                    let fb_name = fallback.name();
                    tracing::info!(
                        "端点降级 [{}] → [{}]（凭据 #{}，HTTP {}）",
                        cur_name,
                        fb_name,
                        ctx.id,
                        status.as_u16()
                    );

                    let fb_rctx = RequestContext {
                        credentials: &ctx.credentials,
                        token: &ctx.token,
                        machine_id: &machine_id,
                        config,
                    };
                    let fb_url = fallback.api_url(&fb_rctx);
                    let fb_body = fallback.transform_api_body(request_body, &fb_rctx);
                    let fb_base_client = if is_stream {
                        self.streaming_client_for(&ctx.credentials)?
                    } else {
                        self.client_for(&ctx.credentials)?
                    };
                    let fb_base = fb_base_client
                        .post(&fb_url)
                        .body(fb_body)
                        .header("content-type", fallback.content_type());
                    let fb_request = fallback.decorate_api(fb_base, &fb_rctx);
                    let fb_request = fb_request
                        .build()
                        .map_err(|e| anyhow::anyhow!("构建降级请求失败: {}", e))?;

                    let fb_client = if is_stream {
                        self.streaming_client_for(&ctx.credentials)?
                    } else {
                        self.client_for(&ctx.credentials)?
                    };
                    match fb_client.execute(fb_request).await {
                        Ok(fb_resp) if fb_resp.status().is_success() => {
                            Self::emit_attempt(
                                sink, attempt, ctx.id, fb_name, Some(fb_resp.status().as_u16()),
                                outcome::SUCCESS, None, attempt_start,
                            );
                            self.token_manager.report_success(ctx.id);
                            if let Some(cid) = conversation_id.as_deref() {
                                self.token_manager.sticky_record(cid, ctx.id, group);
                            }
                            return Ok(KiroCallResult {
                                response: fb_resp,
                                credential_id: ctx.id,
                                _slot: ctx._slot.take(),
                            });
                        }
                        Ok(fb_resp) => {
                            let fb_status = fb_resp.status();
                            let fb_body_text = fb_resp.text().await.unwrap_or_default();
                            tracing::warn!(
                                "降级端点 [{}] 也失败（HTTP {}），尝试链上下一桶",
                                fb_name,
                                fb_status.as_u16()
                            );
                            Self::emit_attempt(
                                sink, attempt, ctx.id, fb_name, Some(fb_status.as_u16()),
                                outcome::TRANSIENT, Some(&fb_body_text), attempt_start,
                            );
                            cur_name = fb_name;
                            continue;
                        }
                        Err(fb_err) => {
                            tracing::warn!(
                                "降级端点 [{}] 网络错误: {}，尝试链上下一桶",
                                fb_name,
                                fb_err
                            );
                            cur_name = fb_name;
                            continue;
                        }
                    }
                }
                // fallback 链全部走完仍失败：回退常规流程（换号 / 冷却 / 上报错误）
            }
            // ─── 端点降级结束 ────────────────────────────────────────

            // 402 Payment Required 且额度用尽：禁用凭据并故障转移
            if status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body) {
                tracing::warn!(
                    "API 请求失败（额度已用尽，禁用凭据并切换，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::QUOTA_EXHAUSTED, Some(&body), attempt_start,
                );

                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 400 Bad Request - 请求问题，重试/切换凭据无意义
            if status.as_u16() == 400 {
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(400),
                    outcome::BAD_REQUEST, Some(&body), attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 401/403 - 更可能是凭据/权限问题：计入失败并允许故障转移
            if matches!(status.as_u16(), 401 | 403) {
                tracing::warn!(
                    "API 请求失败（可能为凭据错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::AUTH_FAILED, Some(&body), attempt_start,
                );

                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self.token_manager.force_refresh_token_for(ctx.id).await.is_ok() {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 429 + suspicious activity = 账号级临时风控
            // 仅当前凭据被针对，故障转移到其它凭据可立即恢复（受配置开关控制）。
            if status.as_u16() == 429
                && self.token_manager.get_account_throttle_failover()
                && endpoint.is_account_throttled(&body)
            {
                let cooldown_secs = self
                    .token_manager
                    .get_account_throttle_cooldown_secs()
                    .max(1);
                let cooldown = std::time::Duration::from_secs(cooldown_secs);
                tracing::warn!(
                    "API 请求失败（账号级风控，凭据 #{} 冷却 {}s 并切换，尝试 {}/{}）: {}",
                    ctx.id,
                    cooldown_secs,
                    attempt + 1,
                    max_retries,
                    body
                );

                self.token_manager.report_account_throttled(ctx.id, cooldown);
                let remaining = self
                    .token_manager
                    .available_count_for_request(model.as_deref(), group);
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(429),
                    outcome::ACCOUNT_THROTTLED, Some(&body), attempt_start,
                );
                let rate_limit_error = UpstreamRateLimitError::new(
                    retry_after.clone().or_else(|| Some(cooldown_secs.to_string())),
                );

                if remaining == 0 {
                    return Err(rate_limit_error.into());
                }
                last_error = Some(rate_limit_error.into());
                continue;
            }

            // 客户端请求格式错误（messages 数组违反协议）：根因在调用方，重试无意义
            // 上游常以 5xx 返回，必须在下方"瞬态错误重试"分支之前拦截，否则会被当作
            // 上游故障重试 max_retries 次，把一个坏请求放大成多次 503（503 风暴）。
            // 直接终止：不重试、不切换凭据、不计入凭据失败。
            if endpoint.is_client_validation_error(&body) {
                tracing::warn!(
                    "API 请求失败（客户端请求格式错误，不重试）: {} {}",
                    status,
                    body
                );
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::BAD_REQUEST, Some(&body), attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 524 / gateway timeout：上游边缘层超时，继续在本次请求内重试通常只会
            // 放大客户端等待时间和 Claude 端 Retrying 轮数；快速返回，让客户端下一次调用
            // 重新建连。
            if status.as_u16() == 524 || endpoint.is_gateway_timeout(&body) {
                tracing::warn!(
                    "API 请求失败（上游网关超时，不重试）: {} {}",
                    status,
                    body
                );
                Self::emit_attempt(
                    sink,
                    attempt,
                    ctx.id,
                    endpoint_name,
                    Some(status.as_u16()),
                    outcome::TRANSIENT,
                    Some(&body),
                    attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 429/408/5xx - 瞬态上游错误：重试但不禁用或切换凭据
            // （避免 429 high traffic / 502 high load 等瞬态错误把所有凭据锁死）
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                tracing::warn!(
                    "API 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::TRANSIENT, Some(&body), attempt_start,
                );
                last_error = if status.as_u16() == 429 {
                    Some(UpstreamRateLimitError::new(retry_after.clone()).into())
                } else {
                    Some(anyhow::anyhow!(
                        "{} API 请求失败: {} {}",
                        api_type,
                        status,
                        body
                    ))
                };
                if attempt + 1 < max_retries {
                    // 429 限流用更长退避给账号配额恢复时间；408/5xx 仍用通用快速退避
                    let delay = if status.as_u16() == 429 {
                        Self::retry_delay_throttle(attempt)
                    } else {
                        Self::retry_delay(attempt)
                    };
                    sleep(delay).await;
                }
                continue;
            }

            // 其他 4xx - 通常为请求/配置问题：直接返回，不计入凭据失败
            if status.is_client_error() {
                Self::emit_attempt(
                    sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                    outcome::BAD_REQUEST, Some(&body), attempt_start,
                );
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 兜底：当作可重试的瞬态错误处理（不切换凭据）
            tracing::warn!(
                "API 请求失败（未知错误，尝试 {}/{}）: {} {}",
                attempt + 1,
                max_retries,
                status,
                body
            );
            Self::emit_attempt(
                sink, attempt, ctx.id, endpoint_name, Some(status.as_u16()),
                outcome::UNKNOWN, Some(&body), attempt_start,
            );
            last_error = Some(anyhow::anyhow!(
                "{} API 请求失败: {} {}",
                api_type,
                status,
                body
            ));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        // 所有重试都失败
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "{} API 请求失败：已达到最大重试次数（{}次）",
                api_type,
                max_retries
            )
        }))
    }

    /// 向 trace sink 上报一跳结果（sink 为 None 时无开销）
    #[allow(clippy::too_many_arguments)]
    fn emit_attempt(
        sink: Option<&dyn TraceSink>,
        attempt: usize,
        credential_id: u64,
        endpoint: &str,
        http_status: Option<u16>,
        outcome: &str,
        error_body: Option<&str>,
        started: Instant,
    ) {
        let Some(sink) = sink else { return };
        sink.on_attempt(TraceAttempt {
            attempt: attempt as u32,
            credential_id,
            endpoint: endpoint.to_string(),
            http_status,
            outcome: outcome.to_string(),
            error_snippet: error_body.and_then(truncate_snippet),
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// 从请求体中提取 conversationId（用于 session-sticky 调度）
    fn extract_conversation_id(request_body: &str) -> Option<String> {
        let json: serde_json::Value = serde_json::from_str(request_body).ok()?;
        json.get("conversationState")?
            .get("conversationId")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 2_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }

    /// 429 限流专用退避：比通用退避更长。
    ///
    /// 上游 429（SERVICE_REQUEST_RATE_EXCEEDED）是账号级速率配额耗尽，需要更长
    /// 时间恢复；用通用的 ≤2s 快速退避只会让请求在配额恢复前反复撞墙、持续触顶。
    /// 这里 base 1s、封顶 8s，给账号配额留出恢复窗口。
    fn retry_delay_throttle(attempt: usize) -> Duration {
        const BASE_MS: u64 = 1_000;
        const MAX_MS: u64 = 8_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ShardSet::pick 严格 round-robin 轮询 N 个 client(游标取模),保证并发被均匀摊到各分片。
    #[test]
    fn shard_set_round_robins() {
        let mk = || build_client(None, 30, TlsBackend::Rustls).unwrap();
        let shard = ShardSet::new(vec![mk(), mk(), mk()]);
        // 连续 pick 的游标序列应为 0,1,2,0,1,2... 用 cursor 前后差验证严格递增取模。
        let start = shard.cursor.load(Ordering::Relaxed);
        for _ in 0..7 {
            let _ = shard.pick();
        }
        let end = shard.cursor.load(Ordering::Relaxed);
        assert_eq!(end - start, 7, "每次 pick 游标 +1(round-robin 依据)");
        // 单分片集也能正常工作(关闭分片 = 退化为单 client)。
        let one = ShardSet::new(vec![mk()]);
        let _ = one.pick();
        let _ = one.pick();
    }

    /// http_shard_count env var 覆盖 + clamp 边界。
    #[test]
    fn shard_count_default_and_clamp() {
        // SAFETY: 测试进程内串行读写 env; 每个 case 独立。
        // 默认(未设 env)= 4。
        // SAFETY: env mutation in tests is allowed on this crate/toolchain.
        unsafe { std::env::remove_var("KIRO_RS_HTTP_SHARDS"); }
        assert_eq!(http_shard_count(), 4);
        unsafe { std::env::set_var("KIRO_RS_HTTP_SHARDS", "8"); }
        assert_eq!(http_shard_count(), 8);
        // clamp 上限 16。
        unsafe { std::env::set_var("KIRO_RS_HTTP_SHARDS", "100"); }
        assert_eq!(http_shard_count(), 16);
        // clamp 下限 1(0 也是 1)。
        unsafe { std::env::set_var("KIRO_RS_HTTP_SHARDS", "0"); }
        assert_eq!(http_shard_count(), 1);
        // 非法值 → 默认 4。
        unsafe { std::env::set_var("KIRO_RS_HTTP_SHARDS", "not_a_number"); }
        assert_eq!(http_shard_count(), 4);
        unsafe { std::env::remove_var("KIRO_RS_HTTP_SHARDS"); }
    }
}
