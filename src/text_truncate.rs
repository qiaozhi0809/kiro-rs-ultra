//! 入站单字段文本截断（移植自对方 kiro.rs）
//!
//! 在请求离开 converter **之前**、本地 CPU 上截断超大文本字段,使上游 AWS Q
//! (`q.us-east-1.amazonaws.com`) 永远看不到大到会被 `CONTENT_LENGTH_EXCEEDS_THRESHOLD`
//! (400) 拒绝的字段。为什么需要这一步:
//!
//! 1. AWS Q 有硬性**单字段**大小上限。单个超大字段——最常见是 `toolResult.content[0].text`
//!    (读大文件 / 命令大输出 / 粘贴大 blob,~700KB 就够)——会触发 400,整个请求失败。
//!    图片字段的等价限制见 [`crate::image_resize`]。
//! 2. 截断在请求转换期跑,**早于** provider 获取账号并发槽。故此守卫零并发成本:
//!    既不占槽也不触发凭据 failover——只是把字段缩小,让首次尝试就成功。
//!
//! 设计原则(与 `KIRO_RS_IMAGE_*` 家族共享约定):
//! - 已在上限内的字段原样透传(不重分配,owned `String` 原样返回)。
//! - 超限字段从**中间**切,保留头 + 尾(头信息量比中间大,尾保留最新/收尾内容),中间插可见标记。
//! - UTF-8 安全:切点吸附到字符边界,绝不劈开码点。
//! - 每次截断发一条 `warn!`,记录字段名与前后字节数。
//! - 全部由 `KIRO_RS_TEXT_*` env 变量驱动;禁用即恢复旧行为。

use tracing::warn;

/// 默认单字段字节上限。调到刚好低于 ~700KB 的 AWS Q 单字段触发线,故正常流量几乎不触发,
/// 只在会 400 的边缘才介入。想要更宽安全边际可调低(如 500000);确认真实上限更高才调高。
const DEFAULT_MAX_FIELD_BYTES: usize = 680_000;
/// 从头部保留的预算占比(其余减去标记后从尾部保留)。
const HEAD_RATIO: f64 = 0.7;

/// 入站文本字段截断配置。
#[derive(Debug, Clone, Copy)]
pub struct TextLimitConfig {
    pub enabled: bool,
    pub max_field_bytes: usize,
}

impl TextLimitConfig {
    /// 从 `KIRO_RS_TEXT_*` env 变量读取,缺省用默认值。
    ///
    /// - `KIRO_RS_TEXT_TRUNCATE` — `0/false/no/off` 禁用截断(默认启用)
    /// - `KIRO_RS_TEXT_MAX_FIELD_BYTES` — 单字段字节上限(默认 680000)
    pub fn from_env() -> Self {
        let enabled = !matches!(
            std::env::var("KIRO_RS_TEXT_TRUNCATE")
                .unwrap_or_else(|_| "1".to_string())
                .to_ascii_lowercase()
                .as_str(),
            "0" | "false" | "no" | "off"
        );
        let max_field_bytes = std::env::var("KIRO_RS_TEXT_MAX_FIELD_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_MAX_FIELD_BYTES);
        Self {
            enabled,
            max_field_bytes,
        }
    }
}

/// `<= idx` 的最大字符边界(绝不劈开 UTF-8 码点)。
fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// `>= idx` 的最小字符边界(绝不劈开 UTF-8 码点)。
fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

/// 把单个文本字段截到 `cfg.max_field_bytes`,保留头 + 尾、中间插标记。
///
/// 取得所有权;禁用或字段已在上限内时原样返回(快路径不分配)。`label` 只喂告警日志。
pub fn truncate_field(cfg: &TextLimitConfig, label: &str, text: String) -> String {
    if !cfg.enabled || text.len() <= cfg.max_field_bytes {
        return text;
    }

    let original_bytes = text.len();
    let max = cfg.max_field_bytes;

    // 为标记预留空间,使最终输出仍在 `max` 之下。
    let head_budget = (max as f64 * HEAD_RATIO) as usize;
    let head_end = floor_char_boundary(&text, head_budget);

    let removed_estimate = original_bytes.saturating_sub(max);
    let marker = format!("\n\n…[kiro-rs truncated ~{} bytes]…\n\n", removed_estimate);

    // 尾部预算 = 上限减去头部与标记后剩余。
    let tail_budget = max.saturating_sub(head_end).saturating_sub(marker.len());
    let tail_start = ceil_char_boundary(&text, original_bytes.saturating_sub(tail_budget));
    // 防御退化情况:tail_start 落在 head_end 之前。
    let tail_start = tail_start.max(head_end);

    let mut out = String::with_capacity(head_end + marker.len() + (original_bytes - tail_start));
    out.push_str(&text[..head_end]);
    out.push_str(&marker);
    out.push_str(&text[tail_start..]);

    warn!(
        target: "kiro_rs::text_truncate",
        field = label,
        original_bytes = original_bytes,
        final_bytes = out.len(),
        max_field_bytes = max,
        "文本字段超单字段上限,已截断中间以避免 CONTENT_LENGTH_EXCEEDS_THRESHOLD"
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max: usize) -> TextLimitConfig {
        TextLimitConfig { enabled: true, max_field_bytes: max }
    }

    #[test]
    fn passthrough_when_under_cap() {
        let s = "hello world".to_string();
        assert_eq!(truncate_field(&cfg(1000), "t", s.clone()), s);
    }

    #[test]
    fn passthrough_when_disabled() {
        let c = TextLimitConfig { enabled: false, max_field_bytes: 10 };
        let s = "a".repeat(1000);
        assert_eq!(truncate_field(&c, "t", s.clone()), s);
    }

    #[test]
    fn truncates_and_stays_within_cap() {
        let s = "a".repeat(1_000_000);
        let out = truncate_field(&cfg(500_000), "t", s);
        assert!(out.len() <= 500_000, "len was {}", out.len());
        assert!(out.contains("kiro-rs truncated"));
        assert!(out.starts_with('a') && out.ends_with('a'));
    }

    #[test]
    fn never_splits_utf8_codepoint() {
        // 三字节字符,朴素字节切片会 panic。
        let s = "中".repeat(400_000);
        let out = truncate_field(&cfg(300_000), "t", s);
        assert!(out.len() <= 300_000);
        assert!(out.contains('中'));
    }
}

