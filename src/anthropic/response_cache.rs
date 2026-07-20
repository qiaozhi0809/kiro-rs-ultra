//! 中转层「响应缓存」（无外部依赖，移植自对方 kiro.rs）
//!
//! 与 [`super::cache_metering`]（只**模拟** cache_creation/cache_read 的 token 计量）不同，
//! 本模块缓存**真实的响应体**：对同一请求（同会话、同 model、同 messages、同 tools、同 stream）
//! 命中时直接回放上次的完整响应，**完全跳过上游调用**——真省上游 credit + 降首字延迟。
//!
//! - 键 = `sha256(isolation_seed || model || stream || messages_json || tools_json)`。
//!   `isolation_seed` 复用 cache_metering 的口径（优先 metadata session，否则 key+对话根哈希）；
//!   **主 apiKey 无 session 时 isolation_seed 为 None → 本模块不缓存**（避免跨用户串响应）。
//! - 值 = 可直接下发的字节（JSON 或 SSE 事件流文本）+ content-type 标记。
//! - TTL：每条 `expires_at`，过期即 miss（lookup 顺手删 + 后台周期清理）。
//! - 容量：表满按访问序号 LRU 淘汰，不引入 `lru` crate。
//!
//! **只缓存「干净的终态文本响应」**：空响应（output=0）/ tool_use / 出错 / 中途断流 / 非 `end_turn`
//! 一律不写入（详见 handler 侧判定）。尤其**空响应绝不缓存**——否则会与本项目的空响应透明重试
//! 兜底冲突：把偶发空响应固化、命中期内每次回放，等于复活「被迫点继续」的 bug。

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::types::MessagesRequest;

/// 默认 TTL（秒）。
pub const DEFAULT_TTL_SECS: u64 = 180;
/// 默认条目容量上限。每条值可能是数十 KB 响应体，故默认远小于 cache_metering。
pub const DEFAULT_CAPACITY: usize = 1024;
/// 容量下限（clamp），避免配置成过小值导致频繁淘汰。
const MIN_CAPACITY: usize = 16;

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 单条缓存的响应。
#[derive(Clone)]
pub struct CachedResponse {
    /// 可直接写入 HTTP body 的完整字节（JSON 响应体 或 SSE 事件流文本）。
    pub body: Vec<u8>,
    /// true = `text/event-stream`（流式回放）；false = `application/json`（非流式）。
    pub is_sse: bool,
    /// 过期时间戳（unix 秒）。
    expires_at: u64,
    /// 上次访问的单调序号（LRU 淘汰用）。
    last_seq: u64,
}

impl CachedResponse {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

struct Inner {
    entries: HashMap<String, CachedResponse>,
    /// 单调递增的访问序号发生器（每次 put / 命中的 get 自增）。
    seq: u64,
}

/// 进程内响应体缓存（单层 LRU + TTL）。
pub struct ResponseCache {
    inner: Mutex<Inner>,
    capacity: usize,
    /// 全局默认开关（运行时可经 Admin API 改）。per-key 覆盖优先于此值。
    default_enabled: AtomicBool,
    /// 全局默认 TTL 秒（运行时可经 Admin API 改）。per-key ttl>0 时覆盖此值。
    default_ttl_secs: AtomicU64,
}

impl ResponseCache {
    /// 创建空缓存。`capacity` clamp 到 `>= MIN_CAPACITY`。
    pub fn new(capacity: usize, default_enabled: bool, default_ttl_secs: u64) -> Self {
        let ttl = if default_ttl_secs == 0 {
            DEFAULT_TTL_SECS
        } else {
            default_ttl_secs
        };
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                seq: 0,
            }),
            capacity: capacity.max(MIN_CAPACITY),
            default_enabled: AtomicBool::new(default_enabled),
            default_ttl_secs: AtomicU64::new(ttl),
        }
    }

    /// 计算缓存键：`Some(hex(sha256(...)))`；`isolation_seed` 为 None（共享主 Key 无 session）
    /// 时返回 `None` 表示**本请求不缓存**。在请求转换/裁剪**之前**用原始 payload 计算。
    pub fn compute_key(req: &MessagesRequest, key_id: u64) -> Option<String> {
        let seed = super::cache_metering::isolation_seed(req, key_id)?;
        let messages_json = serde_json::to_string(&req.messages).unwrap_or_default();
        let tools_json = serde_json::to_string(&req.tools).unwrap_or_default();

        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(b"\x00");
        h.update(req.model.as_bytes());
        h.update(b"\x00");
        h.update(if req.stream { b"s\x00" } else { b"j\x00" });
        h.update(messages_json.as_bytes());
        h.update(b"\x00");
        h.update(tools_json.as_bytes());
        Some(hex::encode(h.finalize()))
    }

    /// 查询。命中且未过期 → 返回克隆并刷新访问序号；过期 → 顺手删除并返回 None。
    pub fn get(&self, key: &str) -> Option<CachedResponse> {
        let now = now_secs();
        let mut inner = self.inner.lock();
        let next_seq = inner.seq.wrapping_add(1);
        match inner.entries.get_mut(key) {
            Some(entry) if !entry.is_expired(now) => {
                entry.last_seq = next_seq;
                let cloned = entry.clone();
                inner.seq = next_seq;
                Some(cloned)
            }
            Some(_) => {
                inner.entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// 写入。`ttl_secs` 为 0 时退回 [`DEFAULT_TTL_SECS`]。写入后若超容量按访问序号淘汰最旧的若干条。
    pub fn put(&self, key: String, body: Vec<u8>, is_sse: bool, ttl_secs: u64) {
        let ttl = if ttl_secs == 0 { DEFAULT_TTL_SECS } else { ttl_secs };
        let now = now_secs();
        let mut inner = self.inner.lock();
        let next_seq = inner.seq.wrapping_add(1);
        inner.seq = next_seq;
        let entry = CachedResponse {
            body,
            is_sse,
            expires_at: now.saturating_add(ttl),
            last_seq: next_seq,
        };
        inner.entries.insert(key, entry);
        self.evict_over_capacity(&mut inner);
    }

    /// 容量超限时按访问序号升序淘汰最旧的若干条。
    fn evict_over_capacity(&self, inner: &mut Inner) {
        if inner.entries.len() <= self.capacity {
            return;
        }
        let drop_n = inner.entries.len() - self.capacity;
        let mut victims: Vec<(String, u64)> = inner
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), v.last_seq))
            .collect();
        victims.sort_by_key(|(_, seq)| *seq);
        for (k, _) in victims.into_iter().take(drop_n) {
            inner.entries.remove(&k);
        }
    }

    /// 删除已过期条目（后台周期任务调用）。
    pub fn evict_expired(&self) {
        let now = now_secs();
        let mut inner = self.inner.lock();
        inner.entries.retain(|_, v| !v.is_expired(now));
    }

    /// 启动后台周期任务：每 60s 清理过期条目。持 Weak，缓存被释放即自动退出。
    pub fn spawn_background(self: Arc<Self>) {
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(60);
            loop {
                tokio::time::sleep(interval).await;
                let Some(cache) = weak.upgrade() else { return };
                cache.evict_expired();
            }
        });
    }

    /// 全局默认开关（运行时值）。
    pub fn default_enabled(&self) -> bool {
        self.default_enabled.load(Ordering::Relaxed)
    }

    /// 全局默认 TTL 秒（运行时值）。
    #[allow(dead_code)]
    pub fn default_ttl_secs(&self) -> u64 {
        self.default_ttl_secs.load(Ordering::Relaxed)
    }

    /// 运行时更新全局默认开关（Admin API）。
    #[allow(dead_code)]
    pub fn set_default_enabled(&self, enabled: bool) {
        self.default_enabled.store(enabled, Ordering::Relaxed);
    }

    /// 运行时更新全局默认 TTL 秒（Admin API）。`secs=0` 退回默认。
    #[allow(dead_code)]
    pub fn set_default_ttl_secs(&self, secs: u64) {
        let ttl = if secs == 0 { DEFAULT_TTL_SECS } else { secs };
        self.default_ttl_secs.store(ttl, Ordering::Relaxed);
    }

    /// 解析「该 Key 生效的响应缓存配置」：per-key 覆盖优先，否则回退全局默认（运行时值）。
    /// 返回 `(enabled, ttl_secs)`；`enabled=false` 时调用方直接跳过查询/写入。
    pub fn effective_config(
        &self,
        key_enabled: Option<bool>,
        key_ttl_secs: Option<u32>,
    ) -> (bool, u64) {
        effective_cache_config(
            key_enabled,
            key_ttl_secs,
            self.default_enabled(),
            self.default_ttl_secs(),
        )
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }
}

/// 解析「该 Key 生效的响应缓存配置」：per-key 覆盖优先，否则回退全局默认。
/// 返回 `(enabled, ttl_secs)`。`enabled=false` 时调用方直接跳过缓存查询/写入。
pub fn effective_cache_config(
    key_enabled: Option<bool>,
    key_ttl_secs: Option<u32>,
    global_enabled: bool,
    global_ttl_secs: u64,
) -> (bool, u64) {
    let enabled = key_enabled.unwrap_or(global_enabled);
    let ttl = key_ttl_secs
        .map(|v| v as u64)
        .filter(|v| *v > 0)
        .unwrap_or(global_ttl_secs);
    (enabled, ttl)
}

/// 响应缓存的「写入句柄」：命中 miss 后传入 handler/context，待完整响应组装好再 `put`。
/// 只在「该请求响应缓存生效」时为 `Some(..)`，否则 None（零开销跳过）。
#[derive(Clone)]
pub struct ResponseCacheStore {
    cache: SharedResponseCache,
    key: String,
    ttl_secs: u64,
}

impl ResponseCacheStore {
    /// 写入一段干净响应体。`is_sse=true` 表示 body 是 SSE 事件流文本。
    pub fn put(&self, body: Vec<u8>, is_sse: bool) {
        self.cache.put(self.key.clone(), body, is_sse, self.ttl_secs);
    }
}

/// 解析「该请求是否启用响应缓存」并构造 lookup/store 上下文。
///
/// 返回 `None` = 缓存未启用（无实例 / 该 Key 关 / isolation_seed 为 None 不可缓存）。
/// 返回 `Some((cache, key, ttl))` = 启用：用 `cache.get(&key)` 查、miss 后用 `ttl` 写。
pub fn resolve_response_cache(
    cache: Option<&SharedResponseCache>,
    payload: &MessagesRequest,
    key_id: u64,
    key_enabled: Option<bool>,
    key_ttl_secs: Option<u32>,
) -> Option<(SharedResponseCache, String, u64)> {
    let cache = cache?;
    let (enabled, ttl) = cache.effective_config(key_enabled, key_ttl_secs);
    if !enabled {
        return None;
    }
    let key = ResponseCache::compute_key(payload, key_id)?;
    Some((cache.clone(), key, ttl))
}

/// 构造 store 句柄（供 handler 在 miss 后写入用）。
pub fn make_store(cache: SharedResponseCache, key: String, ttl_secs: u64) -> ResponseCacheStore {
    ResponseCacheStore { cache, key, ttl_secs }
}

/// 命中时构造回放响应：按 `is_sse` 还原 content-type，body 原样写出。
pub fn build_cached_response(cached: CachedResponse) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    if cached.is_sse {
        axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::CONNECTION, "keep-alive")
            .body(axum::body::Body::from(cached.body))
            .unwrap()
    } else {
        axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(cached.body))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::types::{Message, Metadata, MessagesRequest};

    fn req_with(model: &str, text: &str) -> MessagesRequest {
        MessagesRequest {
            model: model.to_string(),
            max_tokens: 32,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::Value::String(text.to_string()),
            }],
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: Some(Metadata {
                user_id: Some("user_x_account__session_sess1".to_string()),
            }),
        }
    }

    #[test]
    fn put_get_roundtrip() {
        let cache = ResponseCache::new(64, true, 180);
        cache.put("k1".to_string(), b"hello".to_vec(), false, 180);
        let got = cache.get("k1").expect("should hit");
        assert_eq!(got.body, b"hello");
        assert!(!got.is_sse);
    }

    #[test]
    fn miss_on_unknown_key() {
        let cache = ResponseCache::new(64, true, 180);
        assert!(cache.get("nope").is_none());
    }

    #[test]
    fn expired_entry_is_evicted_on_get() {
        let cache = ResponseCache::new(64, true, 180);
        cache.put("k1".to_string(), b"x".to_vec(), false, 1);
        {
            let mut inner = cache.inner.lock();
            inner.entries.get_mut("k1").unwrap().expires_at = 0;
        }
        assert!(cache.get("k1").is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn lru_evicts_least_recently_hit() {
        let cache = ResponseCache::new(MIN_CAPACITY, true, 180);
        for i in 0..MIN_CAPACITY {
            cache.put(format!("k{i}"), vec![i as u8], false, 180);
        }
        assert!(cache.get("k0").is_some());
        cache.put("overflow".to_string(), vec![1], false, 180);
        assert_eq!(cache.len(), MIN_CAPACITY);
        assert!(cache.get("k0").is_some(), "recently-hit key must survive");
    }

    #[test]
    fn same_request_same_key() {
        let a = ResponseCache::compute_key(&req_with("claude-opus-4-8", "hi"), 1);
        let b = ResponseCache::compute_key(&req_with("claude-opus-4-8", "hi"), 1);
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn stream_flag_changes_cache_key() {
        let mut non_stream = req_with("claude-opus-4-8", "hi");
        non_stream.stream = false;
        let mut stream = req_with("claude-opus-4-8", "hi");
        stream.stream = true;
        assert_ne!(
            ResponseCache::compute_key(&non_stream, 1),
            ResponseCache::compute_key(&stream, 1),
        );
    }

    #[test]
    fn master_key_no_session_not_cacheable() {
        // 主 Key（key_id=0）无 session → isolation_seed None → compute_key None（不缓存）。
        let mut req = req_with("claude-opus-4-8", "hi");
        req.metadata = None;
        assert!(ResponseCache::compute_key(&req, 0).is_none(), "共享主 Key 无 session 不应缓存");
    }

    #[test]
    fn effective_config_per_key_overrides_global() {
        assert_eq!(effective_cache_config(Some(false), None, true, 180), (false, 180));
        assert_eq!(effective_cache_config(Some(true), Some(60), false, 180), (true, 60));
        assert_eq!(effective_cache_config(None, None, true, 200), (true, 200));
        assert_eq!(effective_cache_config(Some(true), Some(0), true, 180), (true, 180));
    }

    #[test]
    fn resolve_skips_when_disabled() {
        let cache: SharedResponseCache = Arc::new(ResponseCache::new(64, false, 180));
        // 全局关 + per-key 无覆盖 → None。
        assert!(resolve_response_cache(Some(&cache), &req_with("m", "hi"), 1, None, None).is_none());
        // per-key 开 → Some。
        assert!(resolve_response_cache(Some(&cache), &req_with("m", "hi"), 1, Some(true), None).is_some());
    }
}


/// `Arc<ResponseCache>` 别名。
pub type SharedResponseCache = Arc<ResponseCache>;
