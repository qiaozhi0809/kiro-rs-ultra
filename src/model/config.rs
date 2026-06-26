use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    Rustls,
    NativeTls,
}

impl Default for TlsBackend {
    fn default() -> Self {
        Self::Rustls
    }
}

/// 错误冷却策略（全局默认）。
///
/// 替代旧的 `account_throttle_cooldown_secs` 单字段语义——改为"窗口计数"：
/// 在 `error_window_secs` 内累计错误次数 ≥ `error_threshold` 才触发冷却，
/// 冷却时长 `cooldown_secs`。`disable_window_secs` 内累计触发 N 次冷却
/// 后整号自动 disable，避免"长期慢号"反复短冷却循环。
///
/// 凭据可通过 `cooldown_override` 字段独立覆盖任一子字段。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorCooldownPolicy {
    /// 错误窗口长度（秒）。默认 60。
    #[serde(default = "default_error_window_secs")]
    pub error_window_secs: u32,
    /// 触发冷却的错误次数阈值。默认 5。
    #[serde(default = "default_error_threshold")]
    pub error_threshold: u32,
    /// 冷却时长（秒）。默认 600（10 分钟）。
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u32,
    /// `disable_window_secs` 内累计触发冷却 N 次后整号 disable。默认 3。
    #[serde(default = "default_auto_disable_after_trips")]
    pub auto_disable_after_trips: u32,
    /// 累计触发计数的窗口长度（秒）。默认 3600（1 小时）。
    #[serde(default = "default_disable_window_secs")]
    pub disable_window_secs: u32,
}

fn default_error_window_secs() -> u32 { 60 }
fn default_error_threshold() -> u32 { 5 }
fn default_cooldown_secs() -> u32 { 600 }
fn default_auto_disable_after_trips() -> u32 { 3 }
fn default_disable_window_secs() -> u32 { 3600 }

impl Default for ErrorCooldownPolicy {
    fn default() -> Self {
        Self {
            error_window_secs: default_error_window_secs(),
            error_threshold: default_error_threshold(),
            cooldown_secs: default_cooldown_secs(),
            auto_disable_after_trips: default_auto_disable_after_trips(),
            disable_window_secs: default_disable_window_secs(),
        }
    }
}

/// 缓存命中（session-sticky 调度）强度档位。
///
/// "缓存"本质是 session-sticky：同一 conversation 粘到同一账号 → 上游 prompt cache 复用率高。
/// 三档区分粘的"积极程度"：
/// - `Off` 无缓存：完全不传 sticky_id，纯负载均衡（cache 命中低，但调度最均匀）。
/// - `Low` 低命中：传 sticky_id，命中且账号未满并发才用；满了让步换号（= 升级前现状）。
/// - `High` 高命中：sticky 命中可突破到常规上限 ×2 强粘同号（cache 命中最高；软顶防爆）。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CacheMode {
    Off,
    Low,
    High,
}

impl Default for CacheMode {
    fn default() -> Self {
        Self::Low
    }
}

/// KNA 应用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    /// OAuth 回调公网地址（远程部署时配置）。
    ///
    /// 留空：Social 登录在服务端本机启动临时回调端口（`http://127.0.0.1:{port}`），
    /// 仅本机浏览器可达。
    /// 配置后（如 `https://example.com/api/admin/auth/callback`）：OAuth `redirect_uri`
    /// 改用此地址，浏览器授权后落到 `{callbackBaseUrl}/oauth/callback`，
    /// 由本服务的公网回调路由接收 `code` 并自动完成登录，适配 Docker / VPS / Render 等远程部署。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_base_url: Option<String>,

    #[serde(default = "default_region")]
    pub region: String,

    /// Auth Region（用于 Token 刷新），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_region: Option<String>,

    /// API Region（用于 API 请求），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_region: Option<String>,

    #[serde(default = "default_kiro_version")]
    pub kiro_version: String,

    #[serde(default)]
    pub machine_id: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_system_version")]
    pub system_version: String,

    #[serde(default = "default_node_version")]
    pub node_version: String,

    #[serde(default = "default_tls_backend")]
    pub tls_backend: TlsBackend,

    /// 外部 count_tokens API 地址（可选）
    #[serde(default)]
    pub count_tokens_api_url: Option<String>,

    /// count_tokens API 密钥（可选）
    #[serde(default)]
    pub count_tokens_api_key: Option<String>,

    /// count_tokens API 认证类型（可选，"x-api-key" 或 "bearer"，默认 "x-api-key"）
    #[serde(default = "default_count_tokens_auth_type")]
    pub count_tokens_auth_type: String,

    /// HTTP 代理地址（可选）
    /// 支持格式: http://host:port, https://host:port, socks5://host:port
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// 代理认证用户名（可选）
    #[serde(default)]
    pub proxy_username: Option<String>,

    /// 代理认证密码（可选）
    #[serde(default)]
    pub proxy_password: Option<String>,

    /// Admin API 密钥（可选，启用 Admin API 功能）
    #[serde(default)]
    pub admin_api_key: Option<String>,

    /// 上一次成功更新前正在运行的版本号，用于在前端展示「回退到 vX.Y.Z」按钮。
    /// 实际回退动作通过 `<exe>.backup` 文件完成，无需访问网络。
    #[serde(default)]
    pub update_previous_version: Option<String>,

    /// GitHub Personal Access Token（可选）。设置后 GitHub Releases 接口会带上
    /// `Authorization: Bearer <token>`，把限流从匿名 60/h 提到认证 5000/h。
    /// 仅需 `public_repo` 读取权限即可。
    #[serde(default)]
    pub github_token: Option<String>,

    /// 上一次成功完成在线更新的时间（RFC3339）。前端用于显示「上次更新于 …」。
    #[serde(default)]
    pub update_last_applied_at: Option<String>,

    /// 是否启用无人值守自动更新。开启后服务会在每天的 `update_auto_apply_time`
    /// 时刻检查 GitHub Releases，发现新版本即自动下载二进制并替换重启。
    #[serde(default)]
    pub update_auto_apply: bool,

    /// 自动更新的每日触发时间（本地时区，`HH:MM` 24 小时制）。
    /// 默认 03:00 凌晨执行，对在线服务影响最小。
    #[serde(default = "default_update_auto_apply_time")]
    pub update_auto_apply_time: String,

    /// 负载均衡模式（"priority" 或 "balanced"）
    #[serde(default = "default_load_balancing_mode")]
    pub load_balancing_mode: String,

    /// 账号级 429 风控触发时是否对当前凭据进入冷却并故障转移（默认 true）。
    ///
    /// 关闭后：429 + suspicious activity 仍按普通瞬态错误重试，不切换凭据。
    /// 开启后：识别到 suspicious activity 字符串时，把当前凭据冷却 `account_throttle_cooldown_secs` 秒，
    /// 立即切换到下一个可用凭据。
    #[serde(default = "default_account_throttle_failover")]
    pub account_throttle_failover: bool,

    /// 账号级风控冷却时长（秒，默认 1800 = 30 分钟）。
    #[serde(default = "default_account_throttle_cooldown_secs")]
    pub account_throttle_cooldown_secs: u64,

    /// 是否开启非流式响应的 thinking 块提取（默认 true）
    ///
    /// 启用后，非流式响应中的 `<thinking>...</thinking>` 标签会被解析为
    /// 独立的 `{"type": "thinking", ...}` 内容块,与流式响应行为一致。
    #[serde(default = "default_extract_thinking")]
    pub extract_thinking: bool,

    /// 默认端点名称（凭据未显式指定 endpoint 时使用，默认 "ide"）
    #[serde(default = "default_endpoint")]
    pub default_endpoint: String,

    /// 是否启用请求链路追踪（写 traces.db）。默认 true。
    ///
    /// 关闭后：不再写入 trace 记录、不走 TraceSink，但 `GET /api/admin/traces`
    /// 仍可查询历史已存记录。适合隐私敏感或磁盘紧张的场景。
    #[serde(default = "default_trace_enabled")]
    pub trace_enabled: bool,

    /// 请求链路追踪记录保留天数（默认 7）。后台任务每天清理超期记录。
    #[serde(default = "default_trace_retention_days")]
    pub trace_retention_days: u32,

    /// 请求用量日志（usage_log.*.jsonl + 聚合桶）保留天数（默认 31）。
    #[serde(default = "default_usage_log_retention_days")]
    pub usage_log_retention_days: u32,

    /// 每账号默认并发上限（同时进行中的请求数）。默认 10。
    ///
    /// 凭据未显式设置 `concurrency_limit` 时回退到此值。调度时若账号进行中
    /// 请求数已达上限，则跳过它选择下一个可用账号（满则跳过，不排队）。
    #[serde(default = "default_concurrency_limit")]
    pub default_concurrency_limit: u32,

    /// 全局默认缓存命中档（无分组覆盖时生效）。默认 `Low`（= 升级前现状行为）。
    ///
    /// 详细语义见 [`CacheMode`]。每个 `Group` 可通过 `cacheMode` 字段单独覆盖。
    #[serde(default = "default_cache_mode")]
    pub cache_mode_default: CacheMode,

    /// runtime → ide 自动降级开关（默认 true，= 升级前行为）。
    ///
    /// 关闭后 runtime 起点请求遇错不再降级到 ide，由账号正常重试逻辑接管。
    /// 起点 = ide 的请求不受此开关影响（ide 没有下家端点）。
    #[serde(default = "default_runtime_fallback_enabled")]
    pub runtime_fallback_enabled: bool,

    /// 错误冷却策略（计数 + 窗口）。
    ///
    /// 替代旧的"单次 429 即冷却 N 秒"——改为"M 分钟内 N 次错误才触发；
    /// 累计触发 K 次自动 disable"。凭据可通过 `cooldown_override` 字段覆盖
    /// 任意子字段。详见 `ErrorCooldownPolicy` 注释。
    #[serde(default)]
    pub error_cooldown_policy: ErrorCooldownPolicy,

    /// 全局上下文压缩阈值（0.5 ~ 1.0）。
    ///
    /// 当上游 `ContextUsage` 事件报 percentage ≥ 该阈值时，代理把响应的
    /// `stop_reason` 改写为 `model_context_window_exceeded`，让客户端
    /// （如 Claude Code）触发 auto-compact / 摘要历史，在真正撞 1M / 200K
    /// 砸 400 之前给客户端留缓冲。
    ///
    /// 每个 `Group` 可通过 `compactThreshold` 字段单独覆盖（适合不同分组
    /// 用不同模型 / 上下文窗口的场景）。
    #[serde(default = "default_context_compact_threshold")]
    pub context_compact_threshold_default: f32,

    /// 端点特定的配置
    ///
    /// 键为端点名（如 "ide" / "cli"），值为该端点自由定义的参数对象。
    /// 未在此表出现的端点沿用实现内置默认值。
    #[serde(default)]
    pub endpoints: HashMap<String, serde_json::Value>,

    /// 空响应自动重试次数（仅 buffered 流式路径生效）。
    ///
    /// 上游 Kiro 在大上下文下会偶发返回"空响应流"——零 output、无 content 块、
    /// stop_reason 兜底成 `end_turn`。客户端（如 Claude Code）见 `end_turn` 即停，
    /// 用户被迫手动"继续"。buffered 路径在把事件吐给客户端前已全缓冲，可在检测到
    /// 纯空响应时透明地重发上游、丢弃空结果，客户端无感知。
    ///
    /// `max_tokens` / `model_context_window_exceeded` 是合法终止，绝不重试。
    /// 默认 2；设 0 关闭该兜底。
    #[serde(default = "default_empty_response_retries")]
    pub empty_response_retries: u32,

    /// 配置文件路径（运行时元数据，不写入 JSON）
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_kiro_version() -> String {
    // Kiro 上游会按 UA 里的版本号做风控：低版本号触发 429 的阈值明显更低
    // （比如 0.7.x 三次内必中），因此 fallback 必须跟当前发布的最新 IDE 版本对齐。
    // 实际运行时通常被 `kiro_version::effective()` 用最新版本覆盖，这里只在
    // 元数据拉取失败时兜底。
    "0.12.333".to_string()
}

fn default_system_version() -> String {
    "macos".to_string()
}

fn default_node_version() -> String {
    "22.22.0".to_string()
}

fn default_count_tokens_auth_type() -> String {
    "x-api-key".to_string()
}

fn default_tls_backend() -> TlsBackend {
    TlsBackend::Rustls
}

fn default_load_balancing_mode() -> String {
    "priority".to_string()
}

fn default_account_throttle_failover() -> bool {
    true
}

fn default_account_throttle_cooldown_secs() -> u64 {
    30 * 60
}

fn default_update_auto_apply_time() -> String {
    "03:00".to_string()
}

fn default_extract_thinking() -> bool {
    true
}

fn default_endpoint() -> String {
    crate::kiro::endpoint::ide::IDE_ENDPOINT_NAME.to_string()
}

fn default_trace_enabled() -> bool {
    true
}

fn default_trace_retention_days() -> u32 {
    7
}

fn default_usage_log_retention_days() -> u32 {
    31
}

fn default_concurrency_limit() -> u32 {
    10
}

fn default_cache_mode() -> CacheMode {
    CacheMode::Low
}

fn default_runtime_fallback_enabled() -> bool {
    true
}

/// 默认上下文压缩阈值：context_usage ≥ 95% 时主动触发 compact。
/// 设 < 1.0 是为了在上游真砸 400 之前给客户端留缓冲做摘要。
fn default_context_compact_threshold() -> f32 {
    0.95
}

fn default_empty_response_retries() -> u32 {
    2
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            callback_base_url: None,
            region: default_region(),
            auth_region: None,
            api_region: None,
            kiro_version: default_kiro_version(),
            machine_id: None,
            api_key: None,
            system_version: default_system_version(),
            node_version: default_node_version(),
            tls_backend: default_tls_backend(),
            count_tokens_api_url: None,
            count_tokens_api_key: None,
            count_tokens_auth_type: default_count_tokens_auth_type(),
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            admin_api_key: None,
            update_previous_version: None,
            github_token: None,
            update_last_applied_at: None,
            update_auto_apply: false,
            update_auto_apply_time: default_update_auto_apply_time(),
            load_balancing_mode: default_load_balancing_mode(),
            account_throttle_failover: default_account_throttle_failover(),
            account_throttle_cooldown_secs: default_account_throttle_cooldown_secs(),
            extract_thinking: default_extract_thinking(),
            default_endpoint: default_endpoint(),
            trace_enabled: default_trace_enabled(),
            trace_retention_days: default_trace_retention_days(),
            usage_log_retention_days: default_usage_log_retention_days(),
            default_concurrency_limit: default_concurrency_limit(),
            cache_mode_default: default_cache_mode(),
            runtime_fallback_enabled: default_runtime_fallback_enabled(),
            error_cooldown_policy: ErrorCooldownPolicy::default(),
            context_compact_threshold_default: default_context_compact_threshold(),
            endpoints: HashMap::new(),
            empty_response_retries: default_empty_response_retries(),
            config_path: None,
        }
    }
}

impl Config {
    /// 获取默认配置文件路径
    pub fn default_config_path() -> &'static str {
        "config.json"
    }

    /// 获取有效的 Auth Region（用于 Token 刷新）
    /// 优先使用 auth_region，未配置时回退到 region
    pub fn effective_auth_region(&self) -> &str {
        self.auth_region.as_deref().unwrap_or(&self.region)
    }

    /// 获取有效的 API Region（用于 API 请求）
    /// 优先使用 api_region，未配置时回退到 region
    pub fn effective_api_region(&self) -> &str {
        self.api_region.as_deref().unwrap_or(&self.region)
    }

    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            // 配置文件不存在，返回默认配置
            let mut config = Self::default();
            config.config_path = Some(path.to_path_buf());
            return Ok(config);
        }

        let content = fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&content)?;
        config.config_path = Some(path.to_path_buf());

        // 用户手工把字符串字段清空（如 `"updateAutoApplyTime": ""`）时，serde 默认值不会
        // 介入；这里把"看起来像空"的关键字段回退到默认值，避免后续业务用到
        // 空字符串导致难以诊断的错误。
        if config.update_auto_apply_time.trim().is_empty() {
            config.update_auto_apply_time = default_update_auto_apply_time();
        }

        Ok(config)
    }

    /// 获取配置文件路径（如果有）
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// 将当前配置写回原始配置文件
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self
            .config_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("配置文件路径未知，无法保存配置"))?;

        let content = serde_json::to_string_pretty(self).context("序列化配置失败")?;
        fs::write(path, content)
            .with_context(|| format!("写入配置文件失败: {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_response_retries_defaults_to_2() {
        // 默认结构体与"配置缺省该字段"两条路径都应得到默认值 2。
        assert_eq!(Config::default().empty_response_retries, 2);
        let c: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(c.empty_response_retries, 2);
    }

    #[test]
    fn empty_response_retries_zero_disables() {
        // 显式 0 表示关闭兜底，必须原样读出（不被默认值覆盖）。
        let c: Config = serde_json::from_str(r#"{"emptyResponseRetries":0}"#).unwrap();
        assert_eq!(c.empty_response_retries, 0);
    }
}
