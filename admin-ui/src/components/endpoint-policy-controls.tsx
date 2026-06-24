import { useState, useEffect } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  useEndpointPolicy,
  useSetEndpointPolicy,
  useErrorCooldownPolicy,
  useSetErrorCooldownPolicy,
} from "@/hooks/use-credentials";
import { extractErrorMessage } from "@/lib/utils";

/**
 * 端点策略三件套（凭据列表标题旁）：
 * 1. 分布徽章（只读）：显示当前每个端点上挂着几个可用凭据
 * 2. 起点端点分段控件：默认起点（ide / runtime 二选一），运行时改 + 持久化
 * 3. runtime → ide 自动降级开关：Switch
 * 4. 错误冷却策略入口（按钮 → Dialog）：5 字段全局策略
 */
export function EndpointPolicyControls() {
  const { data: policy, isLoading } = useEndpointPolicy();
  const setPolicy = useSetEndpointPolicy();
  const [savingDefault, setSavingDefault] = useState(false);
  const [savingFallback, setSavingFallback] = useState(false);
  const [cooldownDialogOpen, setCooldownDialogOpen] = useState(false);

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

      {/* 4. 全局错误冷却策略（点开 Dialog 编辑 5 字段） */}
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-7 rounded-full px-2.5 text-[11px]"
        onClick={() => setCooldownDialogOpen(true)}
        title="错误窗口计数 + 累计触发自动 disable 策略（凭据可独立覆盖）"
      >
        冷却策略…
      </Button>

      <CooldownPolicyDialog
        open={cooldownDialogOpen}
        onOpenChange={setCooldownDialogOpen}
      />
    </div>
  );
}

/** 全局错误冷却策略编辑 Dialog */
function CooldownPolicyDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const { data: policy, isLoading } = useErrorCooldownPolicy();
  const setPolicy = useSetErrorCooldownPolicy();

  const [windowSecs, setWindowSecs] = useState("");
  const [threshold, setThreshold] = useState("");
  const [cooldownSecs, setCooldownSecs] = useState("");
  const [autoDisable, setAutoDisable] = useState("");
  const [disableWindow, setDisableWindow] = useState("");

  // 打开 Dialog 时回填当前值
  useEffect(() => {
    if (open && policy) {
      setWindowSecs(String(policy.errorWindowSecs));
      setThreshold(String(policy.errorThreshold));
      setCooldownSecs(String(policy.cooldownSecs));
      setAutoDisable(String(policy.autoDisableAfterTrips));
      setDisableWindow(String(policy.disableWindowSecs));
    }
  }, [open, policy]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy) return;
    const parse = (s: string) => {
      const n = parseInt(s.trim(), 10);
      return Number.isFinite(n) && n > 0 ? n : undefined;
    };
    const patch = {
      errorWindowSecs: parse(windowSecs),
      errorThreshold: parse(threshold),
      cooldownSecs: parse(cooldownSecs),
      autoDisableAfterTrips: parse(autoDisable),
      disableWindowSecs: parse(disableWindow),
    };
    try {
      await setPolicy.mutateAsync(patch);
      toast.success("错误冷却策略已更新");
      onOpenChange(false);
    } catch (err) {
      toast.error(extractErrorMessage(err));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>全局错误冷却策略</DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          {isLoading || !policy ? (
            <p className="py-6 text-center text-sm text-muted-foreground">加载中…</p>
          ) : (
            <div className="space-y-4 py-2">
              <p className="text-[12px] text-muted-foreground">
                上游 429/5xx 错误的冷却规则。凭据可在编辑面板里独立覆盖任一字段。
              </p>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">错误窗口（秒）</label>
                  <Input
                    type="number"
                    min={1}
                    value={windowSecs}
                    onChange={(e) => setWindowSecs(e.target.value)}
                    disabled={setPolicy.isPending}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">触发阈值（次）</label>
                  <Input
                    type="number"
                    min={1}
                    value={threshold}
                    onChange={(e) => setThreshold(e.target.value)}
                    disabled={setPolicy.isPending}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">冷却时长（秒）</label>
                  <Input
                    type="number"
                    min={1}
                    value={cooldownSecs}
                    onChange={(e) => setCooldownSecs(e.target.value)}
                    disabled={setPolicy.isPending}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-muted-foreground">自动 disable 阈值</label>
                  <Input
                    type="number"
                    min={1}
                    value={autoDisable}
                    onChange={(e) => setAutoDisable(e.target.value)}
                    disabled={setPolicy.isPending}
                  />
                </div>
                <div className="col-span-2 space-y-1">
                  <label className="text-xs text-muted-foreground">disable 计数窗口（秒）</label>
                  <Input
                    type="number"
                    min={1}
                    value={disableWindow}
                    onChange={(e) => setDisableWindow(e.target.value)}
                    disabled={setPolicy.isPending}
                  />
                </div>
              </div>

              <p className="text-[11px] text-muted-foreground">
                语义：「{windowSecs || "?"}s 内累计 {threshold || "?"} 次错误」→ 冷却 {cooldownSecs || "?"}s；
                「{disableWindow || "?"}s 内累计触发 {autoDisable || "?"} 次冷却」→ 整号自动 disable。
              </p>
            </div>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={setPolicy.isPending}
            >
              取消
            </Button>
            <Button type="submit" disabled={setPolicy.isPending || !policy}>
              {setPolicy.isPending ? "保存中..." : "保存"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
