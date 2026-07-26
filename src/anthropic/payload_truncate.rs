//! 整体 payload 大小守卫（移植自对方 kiro.rs）:通过丢弃最旧历史把序列化后的 Kiro 请求
//! 压到上限内,操作对象是**转换前的 Anthropic 请求**,使 converter 的 tool_use/tool_result
//! 配对清理永远**最后**跑,保证吐出的 payload 一定合法。
//!
//! 为什么在转换前(v0.6.25 的教训):`converter::convert_request` 跑三道配对清理(移除孤儿
//! tool_result、孤儿 tool_use、非相邻 tool_use),满足上游"tool_use 与 tool_result 必须正确
//! 配对且有序"的规则。裁剪**已转换**的 Kiro 历史(v0.6.25 的做法)会劈开已配对的轮次且之后
//! 无清理 → 上游 400 "Invalid message sequence"。裁剪 **Anthropic** 消息再转换,让清理修掉裁出
//! 的孤儿。这里永远不用关心配对。
//!
//! `image_resize`(逐图)与 `text_truncate`(逐字段)封顶单个字段;本模块是缺失的**整包**层,
//! 应对数百个在限额内的轮次累加撑爆 AWS Q `CONTENT_LENGTH_EXCEEDS_THRESHOLD` 的情形。
//!
//! 保留:`system`(独立请求字段,不在 `messages` 内,不动)、最近若干轮(>= [`MIN_RECENT_TURNS`])、
//! 当前消息(`messages` 末条,恒保留)。裁掉处插一个占位符。
//!
//! 由 `KIRO_RS_MAX_PAYLOAD_BYTES` 驱动(0 禁用),共享 `KIRO_RS_*` env 约定。

use serde_json::Value;
use tracing::warn;

use super::converter::{ConversionError, ConversionResult, convert_request_with_mode};
use super::types::{Message, MessagesRequest};
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::model::config::ToolCompatibilityMode;

/// 默认整包字节上限。
///
/// **历史坑**: 老默认 640KB 是按 200K token 窗口标定的（对齐当年实测的 ~685KB 单字段
/// 失败线）。搬到 Claude 5 系（opus-5 / sonnet-5 / fable-5，`get_context_window_size`
/// 报 1_000_000）上就变成"1M 窗口的 ~20% 就开始砍"——真实症状是**断线重连时**
/// Claude Code 重发全量历史，那一发正好是本次会话最大的 payload，直接被砍到 6 条 +
/// 占位符，用户侧表现为"重连后完全没记忆"。
///
/// 3.5MB ≈ 用本项目 token 估算口径覆盖 1M 窗口的常见负载；上游真放不下时也会先返回
/// `CONTENT_LENGTH_EXCEEDS_THRESHOLD`，被 `map_provider_error_with_context` 改写为
/// 200 + `model_context_window_exceeded`，客户端 auto-compact 兜住，绝不会因为放宽
/// 这个上限而回退成 400。
///
/// `0` 禁用。要恢复旧行为改小即可。
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 3_500_000;

/// 恒保留的最近 `messages` 条数（含当前消息）。
///
/// 6 是老值，本意是"总归留一点最新上下文"，但真触发裁剪时会把长会话塌成 6 条 + 占位符——
/// 相当于强制失忆。20 让裁剪介入时仍能保住最近一段有意义的对话，兜底但不粗暴。
const MIN_RECENT_TURNS: usize = 20;

/// 裁剪迭代硬上限(每次一次重转换);安全边界,正常 1-2 次即够。
const MAX_TRIM_ITERS: usize = 12;

/// 裁掉旧消息处插入的占位符（作为一个 user 轮）。
const TRUNCATION_PLACEHOLDER: &str = "[Earlier conversation history was truncated to fit the model's input limit. \
Older messages and tool activity have been omitted.]";

/// 整包截断配置。`max_bytes == 0` 禁用。
#[derive(Debug, Clone, Copy)]
pub struct PayloadLimitConfig {
    pub max_bytes: usize,
}

impl PayloadLimitConfig {
    /// 读 `KIRO_RS_MAX_PAYLOAD_BYTES`(0 禁用),未设时用默认上限。
    pub fn from_env() -> Self {
        let max_bytes = std::env::var("KIRO_RS_MAX_PAYLOAD_BYTES")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_MAX_PAYLOAD_BYTES);
        Self { max_bytes }
    }
}

/// `ConversionResult` 会产出的 Kiro wire body 的序列化字节数(与 handlers 实际发送、上游实际
/// 度量的一致)。序列化失败 → 0(视为"放得下")。
fn converted_payload_bytes(result: &ConversionResult) -> usize {
    let probe = KiroRequest {
        conversation_state: result.conversation_state.clone(),
        profile_arn: None,
        additional_model_request_fields: result.additional_model_request_fields.clone(),
    };
    serde_json::to_string(&probe).map(|s| s.len()).unwrap_or(0)
}

/// 单条 Anthropic 消息的序列化字节数——该轮转换后贡献的廉价 per-turn 代理值。用于**单趟**定位
/// 裁剪量(按观测的 Anthropic→Kiro 膨胀比缩放),而非每丢一条就重转换重测。失败 → 0。
fn anthropic_msg_bytes(msg: &Message) -> usize {
    serde_json::to_string(msg).map(|s| s.len()).unwrap_or(0)
}

/// 是否为纯 tool_result 轮(`content` 数组只含 `tool_result` 块)。这种轮绝不能成为新的最旧保留
/// 轮:它配对的 `tool_use` 在被丢区,converter 会剥掉这个孤儿,该轮什么也不贡献。一起丢掉,使
/// 保留窗口从真正的 user/assistant 轮开头。
fn is_pure_tool_result(msg: &Message) -> bool {
    match &msg.content {
        Value::Array(arr) => {
            !arr.is_empty()
                && arr
                    .iter()
                    .all(|b| b.get("type").and_then(|v| v.as_str()) == Some("tool_result"))
        }
        _ => false,
    }
}

/// 丢弃 `drop_count` 条最旧消息,然后持续推进裁点直到新的最旧保留轮不是纯 tool_result(避免窗口
/// 头留孤儿 tool_result)。恒保留至少 [`MIN_RECENT_TURNS`](含当前/末条)。裁点处插一个占位符。
/// 原地改 `messages`。有丢弃返回 true。
fn drop_oldest_turns(messages: &mut Vec<Message>, drop_count: usize) -> bool {
    let n = messages.len();
    if n <= MIN_RECENT_TURNS || drop_count == 0 {
        return false;
    }
    let max_drop = n - MIN_RECENT_TURNS;
    let mut cut = drop_count.min(max_drop);
    while cut < max_drop && is_pure_tool_result(&messages[cut]) {
        cut += 1;
    }
    if cut == 0 {
        return false;
    }
    let placeholder = Message {
        role: "user".to_string(),
        content: Value::String(TRUNCATION_PLACEHOLDER.to_string()),
    };
    let tail = messages.split_off(cut);
    messages.clear();
    messages.push(placeholder);
    messages.extend(tail);
    true
}

/// 转换 `payload`,裁掉**最旧 Anthropic 历史**直到转换后的 Kiro payload 落进 `cfg.max_bytes`。
/// converter(带配对清理)每趟都跑,故返回的 `ConversionResult` 一定配对合法。禁用(`max_bytes==0`)
/// 或已在预算内时不裁——此时恰好等于一次 `convert_request_with_mode`。
///
/// `mode` 透传给 converter(与项目其余转换路径同一口径)。
pub fn convert_within_limit(
    payload: &mut MessagesRequest,
    cfg: &PayloadLimitConfig,
    mode: ToolCompatibilityMode,
) -> Result<ConversionResult, ConversionError> {
    convert_within_limit_counted(payload, cfg, mode).map(|(result, _)| result)
}

/// 内部实现,额外暴露 `convert_request` 调用次数,供"≤2 次转换"测试守卫用。
fn convert_within_limit_counted(
    payload: &mut MessagesRequest,
    cfg: &PayloadLimitConfig,
    mode: ToolCompatibilityMode,
) -> Result<(ConversionResult, usize), ConversionError> {
    let mut conversions = 1;
    let mut result = convert_request_with_mode(payload, mode)?;
    if cfg.max_bytes == 0 {
        return Ok((result, conversions));
    }
    let before = converted_payload_bytes(&result);
    if before <= cfg.max_bytes {
        return Ok((result, conversions));
    }

    // 单趟定位:不每丢一条就重转换重测,而是按 per-message 字节数(乘以观测的 Anthropic→Kiro
    // 膨胀比)一次估出裁剪量,丢掉那么多最旧轮,再**重转换一次**核验(并让配对清理跑)。仅当估
    // 少了才进入下面的有界修正循环——正常不进。
    let msg_bytes: Vec<usize> = payload.messages.iter().map(anthropic_msg_bytes).collect();
    let anthropic_total: usize = msg_bytes.iter().sum::<usize>().max(1);
    let over_converted = before - cfg.max_bytes;
    let over_anthropic =
        ((over_converted as u128 * anthropic_total as u128) / before.max(1) as u128) as usize;
    let trimmable = payload.messages.len().saturating_sub(MIN_RECENT_TURNS);
    let mut acc = 0usize;
    let mut est = 0usize;
    for &b in msg_bytes.iter().take(trimmable) {
        if acc >= over_anthropic {
            break;
        }
        acc += b;
        est += 1;
    }
    est = est.max(1);

    if drop_oldest_turns(&mut payload.messages, est) {
        result = convert_request_with_mode(payload, mode)?;
        conversions += 1;
    }

    // 有界修正：若单趟估计仍超（各轮大小不均），继续裁。
    //
    // **原实现的坑**（老默认 MIN=6 时被掩盖，抬到 MIN=20 才暴露）：`drop_oldest_turns`
    // 会在裁点插回一个占位符，所以「丢 1 条」净减 0 条消息——每次调用后 messages.len()
    // 不变。老循环每轮只请求丢 1 条，进入这里几乎不推进。此时唯一的进展来自「占位符
    // 比被替换的旧消息略小」，微不足道，直到触碰 MAX_TRIM_ITERS 上限。
    //
    // 正确做法：按仍超字节比例算出一次要跨过去的"旧轮数"，让 split_off 真的把这些内容
    // 从保留区移走；每轮实打实缩小 payload。仍超且 len 已到 MIN_RECENT_TURNS 时停手——
    // 后续要么客户端 auto-compact，要么上游返回 CONTENT_LENGTH_EXCEEDS_THRESHOLD 被
    // 改写成 200 + model_context_window_exceeded，都比在这里死循环强。
    let mut iters = 0;
    while iters < MAX_TRIM_ITERS {
        let cur = converted_payload_bytes(&result);
        if cur <= cfg.max_bytes {
            break;
        }
        // 已经缩到最小保留窗口：停手（配合 map_provider_error_with_context 兜底）。
        if payload.messages.len() <= MIN_RECENT_TURNS + 1 {
            break;
        }
        let over = cur - cfg.max_bytes;
        let avg = (cur / payload.messages.len().max(1)).max(1);
        // 保留区: MIN_RECENT_TURNS。首条如果已是占位符则也不能再裁。
        // trimmable = 从 index=1 起到 len-MIN_RECENT_TURNS。
        let trimmable = payload.messages.len().saturating_sub(MIN_RECENT_TURNS).max(1);
        let want = (over / avg + 1).min(trimmable);
        let before_len = payload.messages.len();
        if !drop_oldest_turns(&mut payload.messages, want) {
            break;
        }
        // 无进展兜底：说明占位符与新裁点重合了、insert-back 抵消了减量。停。
        if payload.messages.len() >= before_len {
            break;
        }
        result = convert_request_with_mode(payload, mode)?;
        conversions += 1;
        iters += 1;
    }

    let after = converted_payload_bytes(&result);
    warn!(
        before_bytes = before,
        after_bytes = after,
        max_bytes = cfg.max_bytes,
        remaining_messages = payload.messages.len(),
        conversions,
        "整体 payload 超字节上限,已丢弃最旧历史(单趟定位丢弃轮数,转换前裁剪,配对清理在转换时兜底)"
    );
    Ok((result, conversions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(bytes: usize) -> PayloadLimitConfig {
        PayloadLimitConfig { max_bytes: bytes }
    }
    fn user_text(s: &str) -> Message {
        Message { role: "user".to_string(), content: json!(s) }
    }
    fn assistant_text(s: &str) -> Message {
        Message { role: "assistant".to_string(), content: json!(s) }
    }

    fn big_req(turns: usize, per_turn_bytes: usize) -> MessagesRequest {
        let blob = "x".repeat(per_turn_bytes);
        let mut messages = Vec::new();
        for i in 0..turns {
            if i % 2 == 0 {
                messages.push(user_text(&format!("{blob}-u{i}")));
            } else {
                messages.push(assistant_text(&format!("{blob}-a{i}")));
            }
        }
        MessagesRequest {
            model: "claude-sonnet-4-5-20250929".to_string(),
            max_tokens: 32,
            messages,
            stream: false,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,
            metadata: None,
        }
    }

    #[test]
    fn disabled_is_single_conversion_noop() {
        let mut req = big_req(40, 20_000);
        let n_before = req.messages.len();
        let (_r, conversions) =
            convert_within_limit_counted(&mut req, &cfg(0), ToolCompatibilityMode::default()).unwrap();
        assert_eq!(conversions, 1, "禁用时只应转换一次");
        assert_eq!(req.messages.len(), n_before, "禁用时不应裁剪");
    }

    #[test]
    fn under_budget_is_noop() {
        let mut req = big_req(6, 100);
        let n_before = req.messages.len();
        convert_within_limit(&mut req, &cfg(10_000_000), ToolCompatibilityMode::default()).unwrap();
        assert_eq!(req.messages.len(), n_before, "预算充足不应裁剪");
    }

    #[test]
    fn over_budget_trims_oldest_and_keeps_recent() {
        // 40 轮大历史,收紧上限 → 必须裁剪,但保留最近 MIN_RECENT_TURNS 与当前消息。
        let mut req = big_req(40, 20_000);
        let last_before = req.messages.last().unwrap().clone();
        convert_within_limit(&mut req, &cfg(200_000), ToolCompatibilityMode::default()).unwrap();
        assert!(req.messages.len() < 40, "应裁掉部分历史");
        assert!(req.messages.len() >= MIN_RECENT_TURNS, "至少保留最近窗口");
        assert_eq!(
            req.messages.last().unwrap().content,
            last_before.content,
            "当前消息(末条)必须原样保留"
        );
        // 裁点插了占位符。
        assert!(
            req.messages.iter().any(|m| matches!(&m.content, Value::String(s) if s.contains("truncated"))),
            "应插入截断占位符"
        );
    }

    #[test]
    fn trims_in_bounded_conversions() {
        // 单趟定位:即便大历史,转换次数也应很小(远小于逐条丢的轮数)。
        let mut req = big_req(60, 20_000);
        let (_r, conversions) =
            convert_within_limit_counted(&mut req, &cfg(200_000), ToolCompatibilityMode::default()).unwrap();
        assert!(conversions <= 4, "单趟定位应把转换次数压到很小,实测 {conversions}");
    }
}

