import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { useQuery } from '@tanstack/react-query'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectGroup,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import {
  useUpdateCredential,
  useSetCredentialEndpointPolicy,
  useSetCredentialCooldownPolicy,
  useErrorCooldownPolicy,
} from '@/hooks/use-credentials'
import { useGroupOptions } from '@/hooks/use-groups'
import { getProxyPool } from '@/api/credentials'
import { extractErrorMessage, maskProxyUrl } from '@/lib/utils'
import { GroupMultiSelect } from '@/components/group-select'
import type { CredentialStatusItem } from '@/types/api'

interface EditCredentialDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  credential: CredentialStatusItem
}

/** 解析数字输入：空串 = undefined，无效 = undefined，否则正整数 */
function parseUInt(s: string): number | undefined {
  const v = s.trim()
  if (!v) return undefined
  const n = parseInt(v, 10)
  return Number.isFinite(n) && n > 0 ? n : undefined
}

export function EditCredentialDialog({
  open,
  onOpenChange,
  credential,
}: EditCredentialDialogProps) {
  const [email, setEmail] = useState(credential.email ?? '')
  const [proxyUrl, setProxyUrl] = useState(credential.proxyUrl ?? '')
  const [proxyUsername, setProxyUsername] = useState('')
  const [proxyPassword, setProxyPassword] = useState('')
  const [groups, setGroups] = useState<string[]>(credential.groups ?? [])
  const [sourceChannel, setSourceChannel] = useState(credential.sourceChannel ?? '')
  // 空串 = 用全局默认；数字 = 账号级覆盖
  const [concurrencyLimit, setConcurrencyLimit] = useState(
    credential.concurrencyLimitOverride != null
      ? String(credential.concurrencyLimitOverride)
      : '',
  )
  const [manualMode, setManualMode] = useState(false)

  // 端点策略覆盖：'auto' = 跟随全局；'ide'/'runtime' = 强制
  const [endpointMode, setEndpointMode] = useState<'auto' | 'ide' | 'runtime'>(
    credential.endpoint === 'ide' || credential.endpoint === 'runtime'
      ? (credential.endpoint as 'ide' | 'runtime')
      : 'auto',
  )
  // 凭据级 fallback：null = 跟随全局；'on'/'off' = 强制
  const [fallbackMode, setFallbackMode] = useState<'auto' | 'on' | 'off'>(
    credential.runtimeFallback === undefined
      ? 'auto'
      : credential.runtimeFallback
        ? 'on'
        : 'off',
  )

  // 凭据级冷却覆盖：5 个字段，空串 = 跟随全局
  const ov = credential.cooldownOverride
  const [cdWindow, setCdWindow] = useState(
    ov?.errorWindowSecs != null ? String(ov.errorWindowSecs) : '',
  )
  const [cdThreshold, setCdThreshold] = useState(
    ov?.errorThreshold != null ? String(ov.errorThreshold) : '',
  )
  const [cdSecs, setCdSecs] = useState(
    ov?.cooldownSecs != null ? String(ov.cooldownSecs) : '',
  )
  const [cdAutoDisable, setCdAutoDisable] = useState(
    ov?.autoDisableAfterTrips != null ? String(ov.autoDisableAfterTrips) : '',
  )
  const [cdDisableWindow, setCdDisableWindow] = useState(
    ov?.disableWindowSecs != null ? String(ov.disableWindowSecs) : '',
  )

  const groupOptions = useGroupOptions()
  const { data: globalCooldown } = useErrorCooldownPolicy()
  const setEndpointPolicy = useSetCredentialEndpointPolicy()
  const setCooldownPolicy = useSetCredentialCooldownPolicy()

  const { data: proxyPool } = useQuery({
    queryKey: ['proxy-pool'],
    queryFn: getProxyPool,
    enabled: open,
  })

  // 每次打开时重置表单为当前凭据值
  useEffect(() => {
    if (open) {
      setEmail(credential.email ?? '')
      setProxyUrl(credential.proxyUrl ?? '')
      setProxyUsername('')
      setProxyPassword('')
      setGroups(credential.groups ?? [])
      setSourceChannel(credential.sourceChannel ?? '')
      setConcurrencyLimit(
        credential.concurrencyLimitOverride != null
          ? String(credential.concurrencyLimitOverride)
          : '',
      )
      setManualMode(false)
      // 端点策略覆盖
      setEndpointMode(
        credential.endpoint === 'ide' || credential.endpoint === 'runtime'
          ? (credential.endpoint as 'ide' | 'runtime')
          : 'auto',
      )
      setFallbackMode(
        credential.runtimeFallback === undefined
          ? 'auto'
          : credential.runtimeFallback
            ? 'on'
            : 'off',
      )
      // 冷却覆盖
      const ov = credential.cooldownOverride
      setCdWindow(ov?.errorWindowSecs != null ? String(ov.errorWindowSecs) : '')
      setCdThreshold(ov?.errorThreshold != null ? String(ov.errorThreshold) : '')
      setCdSecs(ov?.cooldownSecs != null ? String(ov.cooldownSecs) : '')
      setCdAutoDisable(
        ov?.autoDisableAfterTrips != null ? String(ov.autoDisableAfterTrips) : '',
      )
      setCdDisableWindow(
        ov?.disableWindowSecs != null ? String(ov.disableWindowSecs) : '',
      )
    }
  }, [open, credential])

  const { mutate, isPending: isPendingBase } = useUpdateCredential()
  const isPending =
    isPendingBase || setEndpointPolicy.isPending || setCooldownPolicy.isPending

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // 1. 端点策略 PATCH（仅当与凭据当前值不同时才发）
    const currentEndpoint =
      credential.endpoint === 'ide' || credential.endpoint === 'runtime'
        ? credential.endpoint
        : null
    const newEndpoint: 'ide' | 'runtime' | null =
      endpointMode === 'auto' ? null : endpointMode
    const currentFallback =
      credential.runtimeFallback === undefined
        ? null
        : credential.runtimeFallback
    const newFallback: boolean | null =
      fallbackMode === 'auto' ? null : fallbackMode === 'on'

    const endpointChanged = currentEndpoint !== newEndpoint
    const fallbackChanged = currentFallback !== newFallback
    if (endpointChanged || fallbackChanged) {
      try {
        await setEndpointPolicy.mutateAsync({
          id: credential.id,
          patch: {
            ...(endpointChanged ? { endpoint: newEndpoint } : {}),
            ...(fallbackChanged ? { runtimeFallback: newFallback } : {}),
          },
        })
      } catch (err) {
        toast.error(`端点策略保存失败: ${extractErrorMessage(err)}`)
        return
      }
    }

    // 2. 冷却覆盖 PATCH（每字段独立比较：'' = null=跟随全局；具体数 = 强制）
    const cdPatch: {
      errorWindowSecs?: number | null
      errorThreshold?: number | null
      cooldownSecs?: number | null
      autoDisableAfterTrips?: number | null
      disableWindowSecs?: number | null
    } = {}
    const diffField = (
      key: keyof typeof cdPatch,
      raw: string,
      cur: number | undefined,
    ) => {
      const next = raw.trim() === '' ? null : parseUInt(raw)
      if (next === undefined && raw.trim() !== '') return // 无效输入忽略
      if (next === null && cur === undefined) return // 都是 null
      if (next != null && cur === next) return // 值相同
      cdPatch[key] = next as never
    }
    diffField('errorWindowSecs', cdWindow, ov?.errorWindowSecs)
    diffField('errorThreshold', cdThreshold, ov?.errorThreshold)
    diffField('cooldownSecs', cdSecs, ov?.cooldownSecs)
    diffField('autoDisableAfterTrips', cdAutoDisable, ov?.autoDisableAfterTrips)
    diffField('disableWindowSecs', cdDisableWindow, ov?.disableWindowSecs)

    if (Object.keys(cdPatch).length > 0) {
      try {
        await setCooldownPolicy.mutateAsync({ id: credential.id, patch: cdPatch })
      } catch (err) {
        toast.error(`冷却策略保存失败: ${extractErrorMessage(err)}`)
        return
      }
    }

    // 3. 基本信息更新（最后跑，避免凭据级 PATCH 失败时基本信息已落但策略没落）
    mutate(
      {
        id: credential.id,
        req: {
          email: email,
          proxyUrl: proxyUrl,
          proxyUsername: proxyUsername || undefined,
          proxyPassword: proxyPassword || undefined,
          groups: groups,
          sourceChannel: sourceChannel,
          // 空串 → 0（后端解释为清除覆盖，回退全局默认）；否则解析为数字
          concurrencyLimit:
            concurrencyLimit.trim() === ''
              ? 0
              : Math.max(0, parseInt(concurrencyLimit, 10) || 0),
        },
      },
      {
        onSuccess: (data) => {
          toast.success(data.message)
          onOpenChange(false)
        },
        onError: (error: unknown) => {
          toast.error(`更新失败: ${extractErrorMessage(error)}`)
        },
      }
    )
  }

  const enabledProxies = proxyPool?.proxies.filter(p => p.enabled) ?? []

  // 当前 proxyUrl 是否是自定义值（不匹配任何标准选项）
  const isCustomUrl = proxyUrl !== '' && proxyUrl !== 'direct' &&
    !enabledProxies.some(p => p.url === proxyUrl)

  // 显示手动输入框：明确进入手动模式，或当前值就是自定义值
  const showManualInput = manualMode || isCustomUrl

  const selectValue = showManualInput ? '__custom__' : proxyUrl

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            编辑凭据 #{credential.id}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="space-y-4 py-4">
            {/* 邮箱 */}
            <div className="space-y-2">
              <label htmlFor="email" className="text-sm font-medium">
                邮箱（用于显示标识）
              </label>
              <Input
                id="email"
                type="email"
                placeholder="例: user@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={isPending}
              />
              <p className="text-xs text-muted-foreground">
                留空则显示凭据 ID，清除请提交空值
              </p>
            </div>

            {/* 账号分组 */}
            <div className="space-y-2">
              <label className="text-sm font-medium">账号分组</label>
              <GroupMultiSelect
                value={groups}
                options={groupOptions}
                onChange={setGroups}
                disabled={isPending}
              />
              <p className="text-xs text-muted-foreground">
                绑定了某分组的客户端 Key 只会调度到含该分组的账号。不选表示不属于任何分组。
              </p>
            </div>

            {/* 账号来源渠道 */}
            <div className="space-y-2">
              <label htmlFor="sourceChannel" className="text-sm font-medium">
                账号来源渠道（备注）
              </label>
              <Input
                id="sourceChannel"
                placeholder="例: 官方, 转售商A, 采购平台X"
                value={sourceChannel}
                onChange={(e) => setSourceChannel(e.target.value)}
                disabled={isPending}
              />
              <p className="text-xs text-muted-foreground">
                纯备注，标记此账号的购买来源/渠道，便于追踪。留空表示清除。
              </p>
            </div>

            {/* 并发上限覆盖 */}
            <div className="space-y-2">
              <label htmlFor="concurrencyLimit" className="text-sm font-medium">
                并发上限（覆盖全局默认）
              </label>
              <Input
                id="concurrencyLimit"
                type="number"
                min={1}
                placeholder="留空 = 用全局默认"
                value={concurrencyLimit}
                onChange={(e) => setConcurrencyLimit(e.target.value)}
                disabled={isPending}
              />
              <p className="text-xs text-muted-foreground">
                该账号同时进行中的请求数上限。达上限的账号在调度时被跳过。留空使用全局默认。
              </p>
            </div>

            {/* 端点策略覆盖（凭据级 endpoint + runtime fallback） */}
            <div className="space-y-3 rounded-xl border border-border/60 bg-secondary/30 p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">端点策略覆盖</span>
                <span className="text-[11px] text-muted-foreground">
                  实时错误：{credential.throttleEventCount ?? 0} · 触发：{credential.tripCount ?? 0}
                </span>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">起点端点</label>
                <div className="inline-flex h-8 items-center rounded-full border border-border bg-card/60 p-0.5">
                  {(['auto', 'ide', 'runtime'] as const).map((v) => (
                    <button
                      key={v}
                      type="button"
                      onClick={() => setEndpointMode(v)}
                      disabled={isPending}
                      aria-pressed={endpointMode === v}
                      className={`inline-flex h-7 items-center rounded-full px-3 text-[12px] transition-colors ${
                        endpointMode === v
                          ? 'bg-background text-foreground shadow-apple-sm'
                          : 'text-muted-foreground hover:text-foreground'
                      }`}
                    >
                      {v === 'auto' ? '跟随全局' : v}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground">runtime → ide 降级</label>
                <div className="inline-flex h-8 items-center rounded-full border border-border bg-card/60 p-0.5">
                  {(['auto', 'on', 'off'] as const).map((v) => (
                    <button
                      key={v}
                      type="button"
                      onClick={() => setFallbackMode(v)}
                      disabled={isPending}
                      aria-pressed={fallbackMode === v}
                      className={`inline-flex h-7 items-center rounded-full px-3 text-[12px] transition-colors ${
                        fallbackMode === v
                          ? 'bg-background text-foreground shadow-apple-sm'
                          : 'text-muted-foreground hover:text-foreground'
                      }`}
                    >
                      {v === 'auto' ? '跟随全局' : v === 'on' ? '强制开' : '强制关'}
                    </button>
                  ))}
                </div>
                <p className="text-[11px] text-muted-foreground">
                  例：某号在 ide 端被风控但 runtime 健康，可设起点 = runtime + 降级 = 关。
                </p>
              </div>
            </div>

            {/* 错误冷却策略覆盖 */}
            <div className="space-y-3 rounded-xl border border-border/60 bg-secondary/30 p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">错误冷却策略覆盖</span>
                {globalCooldown && (
                  <span className="text-[11px] text-muted-foreground">
                    全局：{globalCooldown.errorWindowSecs}s/{globalCooldown.errorThreshold}次 → {globalCooldown.cooldownSecs}s
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <label className="text-[11px] text-muted-foreground">错误窗口（秒）</label>
                  <Input
                    type="number"
                    min={1}
                    placeholder={globalCooldown ? String(globalCooldown.errorWindowSecs) : '留空跟随全局'}
                    value={cdWindow}
                    onChange={(e) => setCdWindow(e.target.value)}
                    disabled={isPending}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] text-muted-foreground">错误次数阈值</label>
                  <Input
                    type="number"
                    min={1}
                    placeholder={globalCooldown ? String(globalCooldown.errorThreshold) : '留空跟随全局'}
                    value={cdThreshold}
                    onChange={(e) => setCdThreshold(e.target.value)}
                    disabled={isPending}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] text-muted-foreground">冷却时长（秒）</label>
                  <Input
                    type="number"
                    min={1}
                    placeholder={globalCooldown ? String(globalCooldown.cooldownSecs) : '留空跟随全局'}
                    value={cdSecs}
                    onChange={(e) => setCdSecs(e.target.value)}
                    disabled={isPending}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] text-muted-foreground">自动 disable 阈值</label>
                  <Input
                    type="number"
                    min={1}
                    placeholder={globalCooldown ? String(globalCooldown.autoDisableAfterTrips) : '留空跟随全局'}
                    value={cdAutoDisable}
                    onChange={(e) => setCdAutoDisable(e.target.value)}
                    disabled={isPending}
                  />
                </div>
                <div className="col-span-2 space-y-1">
                  <label className="text-[11px] text-muted-foreground">disable 窗口（秒）</label>
                  <Input
                    type="number"
                    min={1}
                    placeholder={globalCooldown ? String(globalCooldown.disableWindowSecs) : '留空跟随全局'}
                    value={cdDisableWindow}
                    onChange={(e) => setCdDisableWindow(e.target.value)}
                    disabled={isPending}
                  />
                </div>
              </div>
              <p className="text-[11px] text-muted-foreground">
                每字段独立：留空 = 跟随全局；填数字 = 仅本凭据强制覆盖。
              </p>
            </div>

            {/* 代理配置 */}
            <div className="space-y-2">
              <label className="text-sm font-medium">代理配置</label>

              {/* 下拉选择代理 */}
              <Select
                value={selectValue === '' ? '__global__' : selectValue}
                onValueChange={(val) => {
                  if (val === '__custom__') {
                    setManualMode(true)
                    // 保留当前 proxyUrl 作为初始值让用户编辑
                  } else {
                    setManualMode(false)
                    setProxyUrl(val === '__global__' ? '' : val)
                  }
                }}
                disabled={isPending}
              >
                <SelectTrigger className="h-10 rounded-xl px-3.5">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__global__">使用全局代理配置</SelectItem>
                  <SelectItem value="direct">直连（不使用代理）</SelectItem>
                  {enabledProxies.length > 0 && (
                    <SelectGroup>
                      <SelectLabel>代理池</SelectLabel>
                      {enabledProxies.map((p) => (
                        <SelectItem key={p.id} value={p.url}>
                          {p.label ? `${p.label} | ${maskProxyUrl(p.url)}` : maskProxyUrl(p.url)}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  )}
                  <SelectItem value="__custom__">手动输入...</SelectItem>
                </SelectContent>
              </Select>

              {/* 自定义 URL 手动输入框 */}
              {showManualInput && (
                <Input
                  placeholder='自定义代理 URL（如 socks5://user:pass@host:port）'
                  value={proxyUrl}
                  onChange={(e) => setProxyUrl(e.target.value)}
                  disabled={isPending}
                  className="font-mono text-sm"
                />
              )}

              {/* 代理认证（仅在需要时显示） */}
              <div className="grid grid-cols-2 gap-2">
                <Input
                  id="proxyUsername"
                  placeholder="代理用户名（留空不修改）"
                  value={proxyUsername}
                  onChange={(e) => setProxyUsername(e.target.value)}
                  disabled={isPending}
                />
                <Input
                  id="proxyPassword"
                  type="password"
                  placeholder="代理密码（留空不修改）"
                  value={proxyPassword}
                  onChange={(e) => setProxyPassword(e.target.value)}
                  disabled={isPending}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                用户名/密码留空表示不修改；代理 URL 已包含凭据时无需填写
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
            >
              取消
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending ? '保存中...' : '保存'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
