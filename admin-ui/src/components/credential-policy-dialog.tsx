import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  useSetCredentialEndpointPolicy,
  useSetCredentialCooldownPolicy,
  useErrorCooldownPolicy,
} from '@/hooks/use-credentials'
import { extractErrorMessage } from '@/lib/utils'
import type { CredentialStatusItem } from '@/types/api'

interface CredentialPolicyDialogProps {
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

/**
 * 凭据调度策略 Dialog（端点 + 错误冷却）
 *
 * 从「编辑」面板独立出来，避免主编辑表单过长。专门处理两个高级配置：
 * 1. 端点策略覆盖：起点端点（auto/ide/runtime）+ runtime→ide 降级（auto/on/off）
 * 2. 错误冷却策略覆盖：5 个数值字段，每字段独立"留空跟随全局"
 *
 * 入口：凭据卡片「更多操作」菜单 → 调度策略
 */
export function CredentialPolicyDialog({
  open,
  onOpenChange,
  credential,
}: CredentialPolicyDialogProps) {
  // 端点策略覆盖：'auto' = 跟随全局；'ide'/'runtime' = 强制
  const [endpointMode, setEndpointMode] = useState<'auto' | 'ide' | 'runtime'>('auto')
  // 凭据级 fallback：null = 跟随全局；'on'/'off' = 强制
  const [fallbackMode, setFallbackMode] = useState<'auto' | 'on' | 'off'>('auto')

  // 凭据级冷却覆盖：5 个字段，空串 = 跟随全局
  const [cdWindow, setCdWindow] = useState('')
  const [cdThreshold, setCdThreshold] = useState('')
  const [cdSecs, setCdSecs] = useState('')
  const [cdAutoDisable, setCdAutoDisable] = useState('')
  const [cdDisableWindow, setCdDisableWindow] = useState('')

  const { data: globalCooldown } = useErrorCooldownPolicy()
  const setEndpointPolicy = useSetCredentialEndpointPolicy()
  const setCooldownPolicy = useSetCredentialCooldownPolicy()

  // 每次打开时回填当前值
  useEffect(() => {
    if (open) {
      // 注意：credential.endpoint 始终是 effective endpoint（已 unwrap_or 全局默认）。
      // 我们只能通过它推断"是否覆盖"——但准确值得看 raw cooldown_override；
      // 端点级别 raw 字段没单独透出（运维通过此 UI 显式 set 而非读旧 raw）。
      // 这里采用"打开 = auto"的保守策略，由用户主动选择强制。
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

  const isPending = setEndpointPolicy.isPending || setCooldownPolicy.isPending

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // 1. 端点策略 PATCH（仅与凭据当前值不同时才发）
    const currentEndpoint =
      credential.endpoint === 'ide' || credential.endpoint === 'runtime'
        ? credential.endpoint
        : null
    const newEndpoint: 'ide' | 'runtime' | null =
      endpointMode === 'auto' ? null : endpointMode
    const currentFallback =
      credential.runtimeFallback === undefined ? null : credential.runtimeFallback
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

    // 2. 冷却覆盖 PATCH（每字段独立 diff）
    const ov = credential.cooldownOverride
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
      if (next != null && cur === next) return
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

    if (!endpointChanged && !fallbackChanged && Object.keys(cdPatch).length === 0) {
      toast.info('无更改')
      onOpenChange(false)
      return
    }

    toast.success(`凭据 #${credential.id} 调度策略已更新`)
    onOpenChange(false)
  }

  const handleResetAll = async () => {
    try {
      // 端点：重置为跟随全局
      await setEndpointPolicy.mutateAsync({
        id: credential.id,
        patch: { endpoint: null, runtimeFallback: null },
      })
      // 冷却：clearAll
      await setCooldownPolicy.mutateAsync({
        id: credential.id,
        patch: { clearAll: true },
      })
      toast.success(`凭据 #${credential.id} 已重置为跟随全局`)
      onOpenChange(false)
    } catch (err) {
      toast.error(`重置失败: ${extractErrorMessage(err)}`)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>凭据 #{credential.id} 调度策略</DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="space-y-4 py-2">
            <p className="text-[12px] text-muted-foreground">
              当前实时错误：{credential.throttleEventCount ?? 0} ·
              触发：{credential.tripCount ?? 0}
            </p>

            {/* 端点策略覆盖 */}
            <div className="space-y-3 rounded-xl border border-border/60 bg-secondary/30 p-3">
              <span className="text-sm font-medium">端点策略覆盖</span>

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
                    全局：{globalCooldown.errorWindowSecs}s/{globalCooldown.errorThreshold}次 →{' '}
                    {globalCooldown.cooldownSecs}s
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <label className="text-[11px] text-muted-foreground">错误窗口（秒）</label>
                  <Input
                    type="number"
                    min={1}
                    placeholder={
                      globalCooldown ? String(globalCooldown.errorWindowSecs) : '留空跟随全局'
                    }
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
                    placeholder={
                      globalCooldown ? String(globalCooldown.errorThreshold) : '留空跟随全局'
                    }
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
                    placeholder={
                      globalCooldown ? String(globalCooldown.cooldownSecs) : '留空跟随全局'
                    }
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
                    placeholder={
                      globalCooldown
                        ? String(globalCooldown.autoDisableAfterTrips)
                        : '留空跟随全局'
                    }
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
                    placeholder={
                      globalCooldown ? String(globalCooldown.disableWindowSecs) : '留空跟随全局'
                    }
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
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={handleResetAll}
              disabled={isPending}
              title="清空所有凭据级覆盖，恢复跟随全局策略"
            >
              重置为全局
            </Button>
            <div className="flex-1" />
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
