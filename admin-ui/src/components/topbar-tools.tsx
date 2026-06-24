import { forwardRef, useEffect, useState, type ComponentPropsWithoutRef } from 'react'
import {
  Activity, RefreshCw, UploadCloud, Settings, Key, Wand2, Eye, EyeOff, Copy,
  MoreHorizontal, ShieldAlert, ShieldCheck,
} from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { storage } from '@/lib/storage'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from '@/components/ui/dialog'
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent,
  DropdownMenuItem, DropdownMenuLabel,
} from '@/components/ui/dropdown-menu'
import {
  useLoadBalancingMode, useSetLoadBalancingMode,
  useAccountThrottleConfig, useSetAccountThrottleConfig,
  useErrorCooldownPolicy, useSetErrorCooldownPolicy,
} from '@/hooks/use-credentials'
import { useUpdateCheck } from '@/hooks/use-update-check'
import { updateAdminKey } from '@/api/credentials'
import { extractErrorMessage, generateApiKey } from '@/lib/utils'
import { ImageUpdateDialog } from '@/components/image-update-dialog'

/**
 * 顶栏右侧通用工具栏：负载均衡切换、刷新、在线更新、设置（Key 管理）。
 *
 * 与原 Dashboard 中的工具按钮等价，但全局 Tab 都可访问。刷新按钮会失效
 * 凭据/客户端 Key/统计三类查询，覆盖三个 Tab 的主要数据源。
 */
interface TopbarToolsProps {
  compact?: boolean
}

export function TopbarTools({ compact = false }: TopbarToolsProps) {
  const queryClient = useQueryClient()
  const { data: loadBalancingData, isLoading: isLoadingMode } = useLoadBalancingMode()
  const { mutate: setLoadBalancingMode, isPending: isSettingMode } = useSetLoadBalancingMode()
  const { data: throttleConfig, isLoading: isLoadingThrottle } = useAccountThrottleConfig()
  const { mutate: setThrottleConfig, isPending: isSettingThrottle } = useSetAccountThrottleConfig()
  const { data: updateCheck } = useUpdateCheck()

  const [imageUpdateOpen, setImageUpdateOpen] = useState(false)
  const [keyDialogOpen, setKeyDialogOpen] = useState(false)
  const [newKey, setNewKey] = useState('')
  const [showPlain, setShowPlain] = useState(false)
  const [updating, setUpdating] = useState(false)

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['credentials'] })
    queryClient.invalidateQueries({ queryKey: ['client-keys'] })
    queryClient.invalidateQueries({ queryKey: ['stats'] })
    toast.success('已刷新')
  }

  const handleToggleLoadBalancing = () => {
    const cur = loadBalancingData?.mode || 'priority'
    const next = cur === 'priority' ? 'balanced' : 'priority'
    setLoadBalancingMode(next, {
      onSuccess: () => toast.success(`已切换到${next === 'priority' ? '优先级模式' : '均衡负载模式'}`),
      onError: (err) => toast.error(`切换失败: ${extractErrorMessage(err)}`),
    })
  }

  const handleToggleFailover = () => {
    const cur = throttleConfig?.failover ?? true
    const next = !cur
    setThrottleConfig({ failover: next }, {
      onSuccess: () => toast.success(next ? '已开启账号级风控故障转移' : '已关闭账号级风控故障转移'),
      onError: (err) => toast.error(`切换失败: ${extractErrorMessage(err)}`),
    })
  }

  const openKeyDialog = () => {
    setNewKey('')
    setShowPlain(false)
    setKeyDialogOpen(true)
  }

  const handleUpdateKey = async (e: React.FormEvent) => {
    e.preventDefault()
    const key = newKey.trim()
    if (!key) {
      toast.error('新登录API密钥不能为空')
      return
    }
    setUpdating(true)
    try {
      await updateAdminKey({ newKey: key })
      storage.setApiKey(key)
      toast.success('登录API密钥已更新，已自动切换到新 Key')
      setKeyDialogOpen(false)
      setNewKey('')
    } catch (err) {
      toast.error(`更新失败: ${extractErrorMessage(err)}`)
    } finally {
      setUpdating(false)
    }
  }

  const controls = {
    handleRefresh,
    handleToggleFailover,
    handleToggleLoadBalancing,
    isLoadingMode,
    isLoadingThrottle,
    isSettingMode,
    isSettingThrottle,
    loadBalancingMode: loadBalancingData?.mode,
    openImageUpdate: () => setImageUpdateOpen(true),
    openKeyDialog,
    throttleConfig,
    updateCheck,
    updateCooldown: (secs: number) =>
      setThrottleConfig({ cooldownSecs: secs }, {
        onSuccess: () =>
          toast.success(`冷却时长已设为 ${Math.round(secs / 60)} 分钟`),
        onError: (err) => toast.error(`保存失败: ${extractErrorMessage(err)}`),
      }),
  }

  return (
    <>
      {compact ? <CompactTools controls={controls} /> : <FullTools controls={controls} />}
      <ImageUpdateDialog open={imageUpdateOpen} onOpenChange={setImageUpdateOpen} />

      <Dialog
        open={keyDialogOpen}
        onOpenChange={(open) => { if (!updating) setKeyDialogOpen(open) }}
      >
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Key className="h-4 w-4" />
              修改登录API密钥
            </DialogTitle>
            <DialogDescription>
              用于登录此管理面板。修改后将自动更新本地存储的 Key，无需重新登录。
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleUpdateKey} className="space-y-4 py-2">
            <div className="relative">
              <Input
                type={showPlain ? 'text' : 'password'}
                placeholder="输入或生成新的登录API密钥"
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                disabled={updating}
                autoFocus
                className="pr-20 font-mono text-[13px]"
              />
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-1.5">
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="pointer-events-auto h-7 w-7"
                  onClick={() => setShowPlain((v) => !v)}
                  disabled={updating}
                  title={showPlain ? '隐藏' : '显示'}
                >
                  {showPlain ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="pointer-events-auto h-7 w-7"
                  onClick={async () => {
                    if (!newKey.trim()) {
                      toast.error('请先输入或生成 Key 再复制')
                      return
                    }
                    try {
                      await navigator.clipboard.writeText(newKey)
                      toast.success('已复制到剪贴板')
                    } catch {
                      toast.error('复制失败，请手动选择文本')
                    }
                  }}
                  disabled={updating}
                  title="复制"
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
            <div className="flex items-center justify-between gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  const key = generateApiKey('sk-admin-')
                  setNewKey(key)
                  setShowPlain(true)
                }}
                disabled={updating}
              >
                <Wand2 className="h-3.5 w-3.5" />生成随机 Key
              </Button>
              <p className="text-[11px] text-muted-foreground">
                建议生成后立即复制保存，确认更新后即生效。
              </p>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setKeyDialogOpen(false)} disabled={updating}>
                取消
              </Button>
              <Button type="submit" disabled={updating || !newKey.trim()}>
                {updating ? '更新中…' : '确认更新'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}

interface ToolControls {
  handleRefresh: () => void
  handleToggleFailover: () => void
  handleToggleLoadBalancing: () => void
  isLoadingMode: boolean
  isLoadingThrottle: boolean
  isSettingMode: boolean
  isSettingThrottle: boolean
  loadBalancingMode?: 'priority' | 'balanced'
  openImageUpdate: () => void
  openKeyDialog: () => void
  throttleConfig?: { failover: boolean; cooldownSecs: number }
  updateCheck?: { hasUpdate: boolean; latestVersion: string; currentVersion: string }
  updateCooldown: (secs: number) => void
}

function FullTools({ controls }: { controls: ToolControls }) {
  return (
    <>
      <LoadBalancingButton controls={controls} />
      <ThrottleConfigButton
        config={controls.throttleConfig}
        loading={controls.isLoadingThrottle}
        saving={controls.isSettingThrottle}
        onToggleFailover={controls.handleToggleFailover}
        onChangeCooldown={controls.updateCooldown}
      />
      <RefreshButton onRefresh={controls.handleRefresh} />
      <ImageUpdateButton controls={controls} />
      <KeySettingsMenu onOpenKeyDialog={controls.openKeyDialog} />
    </>
  )
}

function CompactTools({ controls }: { controls: ToolControls }) {
  const [healthOpen, setHealthOpen] = useState(false)
  const throttleProps = {
    config: controls.throttleConfig,
    loading: controls.isLoadingThrottle,
    saving: controls.isSettingThrottle,
    onToggleFailover: controls.handleToggleFailover,
    onChangeCooldown: controls.updateCooldown,
  }

  return (
    <>
      <ThrottleConfigButton
        {...throttleProps}
        hideTrigger
        externalOpen={healthOpen}
        onExternalOpenChange={setHealthOpen}
      />
      <DropdownMenu modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="icon" title="更多操作">
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel>系统操作</DropdownMenuLabel>
        <DropdownMenuItem
          disabled={controls.isLoadingMode || controls.isSettingMode}
          onSelect={controls.handleToggleLoadBalancing}
        >
          <Activity />
          {controls.isLoadingMode
            ? '负载均衡加载中'
            : controls.loadBalancingMode === 'priority'
              ? '切换到均衡负载'
              : '切换到优先级'}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={controls.handleRefresh}>
          <RefreshCw />刷新数据
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={controls.openImageUpdate}>
          <UploadCloud />镜像在线更新
        </DropdownMenuItem>
        <DropdownMenuItem
          onSelect={(e) => {
            e.preventDefault()
            setHealthOpen(true)
          }}
        >
          <ShieldCheck />账号健康度…
        </DropdownMenuItem>
        <DropdownMenuLabel>密钥管理</DropdownMenuLabel>
        <DropdownMenuItem onSelect={controls.openKeyDialog}>
          <Key />修改登录API密钥（管理面板登录）
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
    </>
  )
}

function LoadBalancingButton({ controls }: { controls: ToolControls }) {
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={controls.handleToggleLoadBalancing}
      disabled={controls.isLoadingMode || controls.isSettingMode}
      title="切换负载均衡模式"
    >
      <Activity className="h-3.5 w-3.5" />
      <span className="hidden md:inline">
        {controls.isLoadingMode
          ? '加载中…'
          : controls.loadBalancingMode === 'priority'
            ? '优先级'
            : '均衡负载'}
      </span>
    </Button>
  )
}

function RefreshButton({ onRefresh }: { onRefresh: () => void }) {
  return (
    <Button variant="ghost" size="icon" onClick={onRefresh} title="刷新">
      <RefreshCw className="h-4 w-4" />
    </Button>
  )
}

function ImageUpdateButton({ controls }: { controls: ToolControls }) {
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={controls.openImageUpdate}
      title={imageUpdateTitle(controls.updateCheck)}
      className="relative"
    >
      <UploadCloud className="h-4 w-4" />
      {controls.updateCheck?.hasUpdate && <UpdateDot />}
    </Button>
  )
}

function KeySettingsMenu({ onOpenKeyDialog }: { onOpenKeyDialog: () => void }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" title="设置">
          <Settings className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>密钥管理</DropdownMenuLabel>
        <DropdownMenuItem onSelect={onOpenKeyDialog}>
          <Key />修改登录API密钥（管理面板登录）
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function imageUpdateTitle(updateCheck: ToolControls['updateCheck']) {
  if (!updateCheck?.hasUpdate) return '镜像在线更新'
  return `发现新版本 v${updateCheck.latestVersion}（当前 v${updateCheck.currentVersion}）`
}

function UpdateDot() {
  return (
    <span className="absolute right-1 top-1 inline-flex h-2 w-2 items-center justify-center">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
      <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500" />
    </span>
  )
}

interface ThrottleConfigButtonProps {
  config?: { failover: boolean; cooldownSecs: number }
  loading: boolean
  saving: boolean
  onToggleFailover: () => void
  onChangeCooldown: (secs: number) => void
}

interface ThrottleState {
  cooldownMin: number
  cooldownSecs: number
  failover: boolean
}

interface ThrottleTriggerProps extends ComponentPropsWithoutRef<typeof Button> {
  loading: boolean
  saving: boolean
  state: ThrottleState
}

const DEFAULT_COOLDOWN_SECS = 30 * 60
const SECONDS_PER_MINUTE = 60

/**
 * 账号健康度（合并：故障转移开关 + 风控冷却策略 5 字段）
 *
 * 顶部按钮显示当前 failover 状态；点击开整个 Dialog：
 * - 第 1 行：连续失败下线（说明性，固定 3 次，不可改 — kiro-rs 历史兜底）
 * - 第 2 行：风控故障转移（开关 + 5 个冷却策略字段）
 *
 * 设计：把"故障转移开关"和"错误冷却策略"合并到一个面板，因为逻辑上是一套
 * （前者 = 总开关；后者 = 触发条件 + 时长 + 自动 disable 阈值）。
 */
function ThrottleConfigButton({
  config, loading, saving, onToggleFailover, onChangeCooldown: _onChangeCooldown,
  hideTrigger = false, externalOpen, onExternalOpenChange,
}: ThrottleConfigButtonProps & {
  hideTrigger?: boolean
  externalOpen?: boolean
  onExternalOpenChange?: (open: boolean) => void
}) {
  const [internalOpen, setInternalOpen] = useState(false)
  const open = externalOpen ?? internalOpen
  const setOpen = onExternalOpenChange ?? setInternalOpen
  const state = readThrottleState(config)
  const { data: policy } = useErrorCooldownPolicy()
  const { mutate: setPolicy, isPending: savingPolicy } = useSetErrorCooldownPolicy()

  // 五个字段的本地表单状态
  const [windowSecs, setWindowSecs] = useState('')
  const [threshold, setThreshold] = useState('')
  const [cooldownSecs, setCooldownSecs] = useState('')
  const [autoDisable, setAutoDisable] = useState('')
  const [disableWindow, setDisableWindow] = useState('')

  useEffect(() => {
    if (open && policy) {
      setWindowSecs(String(policy.errorWindowSecs))
      setThreshold(String(policy.errorThreshold))
      setCooldownSecs(String(policy.cooldownSecs))
      setAutoDisable(String(policy.autoDisableAfterTrips))
      setDisableWindow(String(policy.disableWindowSecs))
    }
  }, [open, policy])

  const busy = loading || saving || savingPolicy

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const parse = (s: string) => {
      const n = parseInt(s.trim(), 10)
      return Number.isFinite(n) && n > 0 ? n : undefined
    }
    setPolicy(
      {
        errorWindowSecs: parse(windowSecs),
        errorThreshold: parse(threshold),
        cooldownSecs: parse(cooldownSecs),
        autoDisableAfterTrips: parse(autoDisable),
        disableWindowSecs: parse(disableWindow),
      },
      {
        onSuccess: () => {
          toast.success('风控策略已更新')
          setOpen(false)
        },
        onError: (err) => toast.error(extractErrorMessage(err)),
      },
    )
  }

  return (
    <>
      {!hideTrigger && (
        <ThrottleTrigger
          loading={loading}
          saving={saving}
          state={state}
          onClick={() => setOpen(true)}
        />
      )}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>账号健康度</DialogTitle>
            <DialogDescription>
              坏号自动隔离 / 风控自动下线的两套机制
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit}>
            <div className="space-y-4 py-2">
              {/* ① 连续失败下线（说明，不可改） */}
              <div className="rounded-xl border border-border/60 bg-muted/30 p-3">
                <div className="text-sm font-medium">① 连续失败下线（兜底）</div>
                <p className="mt-1.5 text-xs text-muted-foreground">
                  任意 API 失败（认证 / 网络 / 5xx）连续 3 次 → 永久禁用
                  （任意成功重置计数）。这是 kiro-rs 历史兜底，写死不可改。
                  禁用原因 <code className="font-mono">TooManyFailures</code>，运维需手动恢复。
                </p>
              </div>

              {/* ② 风控故障转移 + 冷却策略 */}
              <div className="space-y-3 rounded-xl border border-border/60 bg-secondary/30 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">② 风控故障转移</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">
                      {state.failover ? '已启用' : '已关闭'}
                    </span>
                    <Switch
                      checked={state.failover}
                      disabled={busy}
                      onCheckedChange={onToggleFailover}
                      aria-label="启用风控故障转移"
                    />
                  </div>
                </div>

                <p className="text-xs text-muted-foreground">
                  AWS 风控（429 + suspicious activity）时切走坏号；下面是
                  「几次算坏 / 冷却多久 / 反复几次开除」的细则。关闭开关后这些参数不生效。
                </p>

                <div className={state.failover ? '' : 'opacity-50 pointer-events-none'}>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1">
                      <label className="text-[11px] text-muted-foreground">几次算坏：窗口（秒）</label>
                      <Input
                        type="number"
                        min={1}
                        value={windowSecs}
                        onChange={(e) => setWindowSecs(e.target.value)}
                        disabled={busy}
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] text-muted-foreground">几次算坏：次数</label>
                      <Input
                        type="number"
                        min={1}
                        value={threshold}
                        onChange={(e) => setThreshold(e.target.value)}
                        disabled={busy}
                      />
                    </div>
                    <div className="col-span-2 space-y-1">
                      <label className="text-[11px] text-muted-foreground">拉黑多久（秒）</label>
                      <Input
                        type="number"
                        min={1}
                        value={cooldownSecs}
                        onChange={(e) => setCooldownSecs(e.target.value)}
                        disabled={busy}
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] text-muted-foreground">开除：窗口（秒）</label>
                      <Input
                        type="number"
                        min={1}
                        value={disableWindow}
                        onChange={(e) => setDisableWindow(e.target.value)}
                        disabled={busy}
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] text-muted-foreground">开除：累计触发次数</label>
                      <Input
                        type="number"
                        min={1}
                        value={autoDisable}
                        onChange={(e) => setAutoDisable(e.target.value)}
                        disabled={busy}
                      />
                    </div>
                  </div>

                  <p className="mt-2 text-[11px] text-muted-foreground">
                    语义：「{windowSecs || '?'}s 内累计 {threshold || '?'} 次 AWS 风控」→ 拉黑 {cooldownSecs || '?'}s；
                    「{disableWindow || '?'}s 内累计被拉黑 {autoDisable || '?'} 次」→ 自动 disable
                    （原因 <code className="font-mono">AutoThrottled</code>）。凭据可独立覆盖。
                  </p>
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)} disabled={busy}>
                取消
              </Button>
              <Button type="submit" disabled={busy || !policy}>
                {savingPolicy ? '保存中...' : '保存'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}

const ThrottleTrigger = forwardRef<HTMLButtonElement, ThrottleTriggerProps>(
  function ThrottleTrigger({ loading, saving, state, onClick, ...props }, ref) {
    return (
      <Button
        {...props}
        ref={ref}
        variant="outline"
        size="sm"
        disabled={loading || saving}
        onClick={onClick}
        title={throttleTitle(loading, state)}
      >
        {state.failover ? (
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
        ) : (
          <ShieldAlert className="h-3.5 w-3.5 text-amber-500" />
        )}
        <span className="hidden md:inline">
          {throttleTriggerText(loading, state)}
        </span>
      </Button>
    )
  },
)

function readThrottleState(
  config: ThrottleConfigButtonProps['config'],
): ThrottleState {
  const cooldownSecs = config?.cooldownSecs ?? DEFAULT_COOLDOWN_SECS
  return {
    cooldownMin: secondsToMinutes(cooldownSecs),
    cooldownSecs,
    failover: config?.failover ?? true,
  }
}

function secondsToMinutes(seconds: number) {
  return Math.round(seconds / SECONDS_PER_MINUTE)
}

function throttleTitle(loading: boolean, state: ThrottleState) {
  if (loading) return '加载中…'
  if (!state.failover) return '账号级风控故障转移：关闭'
  return `账号级风控故障转移：开启（冷却 ${state.cooldownMin} 分钟）`
}

function throttleTriggerText(loading: boolean, state: ThrottleState) {
  if (loading) return '加载中…'
  if (!state.failover) return '不切换'
  return `健康度 · ${state.cooldownMin}m`
}
