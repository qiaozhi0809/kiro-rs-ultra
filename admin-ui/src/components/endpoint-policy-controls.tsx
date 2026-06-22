import { useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { useEndpointPolicy, useSetEndpointPolicy } from "@/hooks/use-credentials";
import { extractErrorMessage } from "@/lib/utils";

/**
 * 端点策略三件套（凭据列表标题旁）：
 * 1. 分布徽章（只读）：显示当前每个端点上挂着几个可用凭据
 * 2. 起点端点分段控件：默认起点（ide / runtime 二选一），运行时改 + 持久化
 * 3. runtime → ide 自动降级开关：Switch
 *
 * 三者各管各的，互不依赖。分布徽章会随凭据增删/disabled/起点切换自动刷新。
 */
export function EndpointPolicyControls() {
  const { data: policy, isLoading } = useEndpointPolicy();
  const setPolicy = useSetEndpointPolicy();
  const [savingDefault, setSavingDefault] = useState(false);
  const [savingFallback, setSavingFallback] = useState(false);

  if (isLoading || !policy) {
    return (
      <span className="text-xs text-muted-foreground">端点：加载中…</span>
    );
  }

  const onChangeDefault = async (next: "ide" | "runtime") => {
    if (next === policy.defaultEndpoint) return;
    setSavingDefault(true);
    try {
      await setPolicy.mutateAsync({ defaultEndpoint: next });
      toast.success(`默认起点已切换为：${next}`);
    } catch (e) {
      toast.error(extractErrorMessage(e));
    } finally {
      setSavingDefault(false);
    }
  };

  const onToggleFallback = async (next: boolean) => {
    setSavingFallback(true);
    try {
      await setPolicy.mutateAsync({ runtimeFallbackEnabled: next });
      toast.success(next ? "已启用 runtime→ide 降级" : "已禁用 runtime→ide 降级");
    } catch (e) {
      toast.error(extractErrorMessage(e));
    } finally {
      setSavingFallback(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* 1. 分布徽章 */}
      <Badge
        variant="outline"
        className="gap-1.5 font-mono text-[11px]"
        title="当前每个端点上挂着几个未禁用的凭据（按凭据级 endpoint 字段；未指定者归默认起点）"
      >
        {policy.distribution.length === 0
          ? "端点：—"
          : policy.distribution
              .map((d) => `${d.endpoint}(${d.count})`)
              .join(" · ")}
      </Badge>

      {/* 2. 起点分段控件（ide / runtime） */}
      <div
        className="inline-flex h-7 items-center rounded-full border border-border bg-card/60 p-0.5 backdrop-blur"
        title="未单独配 endpoint 的凭据默认从哪个端点起点；运行时切换 + 持久化"
      >
        <button
          type="button"
          onClick={() => onChangeDefault("ide")}
          disabled={savingDefault}
          aria-pressed={policy.defaultEndpoint === "ide"}
          className={`inline-flex h-6 items-center rounded-full px-2.5 text-[11px] transition-colors ${
            policy.defaultEndpoint === "ide"
              ? "bg-background text-foreground shadow-apple-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          ide
        </button>
        <button
          type="button"
          onClick={() => onChangeDefault("runtime")}
          disabled={savingDefault}
          aria-pressed={policy.defaultEndpoint === "runtime"}
          className={`inline-flex h-6 items-center rounded-full px-2.5 text-[11px] transition-colors ${
            policy.defaultEndpoint === "runtime"
              ? "bg-background text-foreground shadow-apple-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          runtime
        </button>
      </div>

      {/* 3. runtime → ide 降级开关 */}
      <label
        className="inline-flex h-7 items-center gap-1.5 rounded-full border border-border bg-card/60 px-2.5 text-[11px] backdrop-blur"
        title="runtime 端点失败时是否自动降级到 ide。起点为 ide 时此开关无效（ide 无下家）"
      >
        <span className="text-muted-foreground">降级</span>
        <Switch
          checked={policy.runtimeFallbackEnabled}
          disabled={savingFallback}
          onCheckedChange={onToggleFallback}
          className="scale-75"
        />
      </label>
    </div>
  );
}
