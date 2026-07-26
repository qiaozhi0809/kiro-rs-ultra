import { useState } from 'react'
import { toast } from 'sonner'
import {
  Plus, KeyRound, Trash2, Copy, Eye, EyeOff, Power, RotateCcw, Pencil, RefreshCw,
} from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem,
} from '@/components/ui/dropdown-menu'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from '@/components/ui/dialog'
import {
  useClientKeys, useCreateClientKey, useDeleteClientKey,
  useSetClientKeyDisabled, useResetClientKeyStats, useUpdateClientKey,
  useRotateClientKey,
} from '@/hooks/use-client-keys'
import { useGroupOptions } from '@/hooks/use-groups'
import { GroupSingleSelect } from '@/components/group-select'
import type { ClientKeyItem, CreateClientKeyResponse } from '@/types/api'
import { extractErrorMessage } from '@/lib/utils'
import { useConfirm } from '@/components/ui/confirm-dialog'

function formatTokens(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K'
  return n.toString()
}

function formatRelative(ts?: string): string {
  if (!ts) return '从未使用'
  const t = new Date(ts).getTime()
  const diff = Date.now() - t
  if (diff < 60_000) return '刚刚'
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)} 分钟前`
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)} 小时前`
  return `${Math.floor(diff / 86400_000)} 天前`
}

export function ClientKeysPage() {
  const { data, isLoading } = useClientKeys()
  // 已注册分组列表（来自 groups.json 注册表，与凭据的 groups 字段解耦）
  const groupOptions = useGroupOptions()
  const createKey = useCreateClientKey()
  const deleteKey = useDeleteClientKey()
  const setDisabled = useSetClientKeyDisabled()
  const resetStats = useResetClientKeyStats()
  const updateKey = useUpdateClientKey()
  const rotateKey = useRotateClientKey()
  const confirm = useConfirm()

  const [createOpen, setCreateOpen] = useState(false)
  const [createName, setCreateName] = useState('')
  const [createDesc, setCreateDesc] = useState('')
  const [createGroup, setCreateGroup] = useState('')
  const [createdKey, setCreatedKey] = useState<CreateClientKeyResponse | null>(null)
  const [showCreatedPlain, setShowCreatedPlain] = useState(true)

  const [editOpen, setEditOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<ClientKeyItem | null>(null)
  const [editName, setEditName] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editGroup, setEditGroup] = useState('')
  // 检测安全计费（R 阻尼 + multiplier 护栏，恒 sum==total，非超报）
  const [editReadRatio, setEditReadRatio] = useState('') // 空 = 用默认 1.0（不挪）
  const [editMultiplierCap, setEditMultiplierCap] = useState('') // 空 = 用默认 1.25
  const [editBillingMode, setEditBillingMode] = useState(false) // 默认关
  const [editCreationRatio, setEditCreationRatio] = useState('') // 空 = 用默认 0.03
  // prompt 过滤三开关
  const [editSimplifyCc, setEditSimplifyCc] = useState(false)
  const [editStripBoundary, setEditStripBoundary] = useState(false)
  const [editStripEnv, setEditStripEnv] = useState(false)
  // 响应缓存
  const [editRespCache, setEditRespCache] = useState(false)
  const [editRespCacheTtl, setEditRespCacheTtl] = useState('') // 空 = 跟随全局

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    const name = createName.trim()
    if (!name) {
      toast.error('请填写名称')
      return
    }
    try {
      const res = await createKey.mutateAsync({
        name,
        description: createDesc.trim() || undefined,
        group: createGroup.trim() || undefined,
      })
      setCreatedKey(res)
      setCreateOpen(false)
      setCreateName('')
      setCreateDesc('')
      setCreateGroup('')
      setShowCreatedPlain(true)
    } catch (err) {
      toast.error('创建失败：' + extractErrorMessage(err))
    }
  }

  const handleDelete = async (item: ClientKeyItem) => {
    if (
      !(await confirm({
        title: '确认删除 Key',
        description: `确认删除 Key "${item.name}"？此操作无法撤销。`,
        confirmText: '确认删除',
        destructive: true,
      }))
    )
      return
    try {
      await deleteKey.mutateAsync(item.id)
      toast.success(`已删除 Key #${item.id}`)
    } catch (err) {
      toast.error('删除失败：' + extractErrorMessage(err))
    }
  }

  const handleToggleDisabled = async (item: ClientKeyItem) => {
    try {
      await setDisabled.mutateAsync({ id: item.id, disabled: !item.disabled })
      toast.success(item.disabled ? '已启用' : '已禁用')
    } catch (err) {
      toast.error('操作失败：' + extractErrorMessage(err))
    }
  }

  const handleReset = async (item: ClientKeyItem) => {
    if (
      !(await confirm({
        title: '重置统计',
        description: `重置 Key "${item.name}" 的累计统计？`,
        confirmText: '重置',
      }))
    )
      return
    try {
      await resetStats.mutateAsync(item.id)
      toast.success('统计已重置')
    } catch (err) {
      toast.error('重置失败：' + extractErrorMessage(err))
    }
  }

  const handleRotate = async (item: ClientKeyItem) => {
    const systemHint = item.isSystem
      ? '这是系统密钥（config.json apiKey），重新生成后会同步更新 config.json 的 apiKey。'
      : ''
    if (
      !(await confirm({
        title: '重新生成 Key',
        description: `重新生成 Key "${item.name}"？旧明文将立即失效，使用旧明文的下游需要换上新明文才能继续调用。Key 的名称、描述、绑定分组与累计统计保留不变。${systemHint ? ' ' + systemHint : ''}`,
        confirmText: '重新生成',
        destructive: true,
      }))
    )
      return
    try {
      const res = await rotateKey.mutateAsync(item.id)
      setCreatedKey(res)
      setShowCreatedPlain(true)
      // 系统密钥轮换后本地存储的 apiKey 已失效，提示用户用新明文重新登录
      if (item.isSystem) {
        toast.info('系统密钥已更新，若你正用该密钥登录管理面板，请用新明文重新登录')
      }
    } catch (err) {
      toast.error('重新生成失败：' + extractErrorMessage(err))
    }
  }

  const startEdit = (item: ClientKeyItem) => {
    setEditTarget(item)
    setEditName(item.name)
    setEditDesc(item.description ?? '')
    setEditGroup(item.group ?? '')
    setEditReadRatio(item.cacheReadRatio != null ? String(item.cacheReadRatio) : '')
    setEditMultiplierCap(item.cacheMultiplierCap != null ? String(item.cacheMultiplierCap) : '')
    setEditBillingMode(item.cacheBillingMode ?? false)
    setEditCreationRatio(item.cacheCreationRatio != null ? String(item.cacheCreationRatio) : '')
    setEditSimplifyCc(item.simplifyCcPrompt ?? false)
    setEditStripBoundary(item.stripBoundaryMarkers ?? false)
    setEditStripEnv(item.stripEnvNoise ?? false)
    setEditRespCache(item.responseCacheEnabled ?? false)
    setEditRespCacheTtl(item.responseCacheTtlSecs != null ? String(item.responseCacheTtlSecs) : '')
    setEditOpen(true)
  }

  const handleEditSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editTarget) return
    try {
      // R / 护栏：空串表示回默认（后端 clamp）。
      const ratioNum = editReadRatio.trim() === '' ? undefined : Number(editReadRatio)
      const capNum = editMultiplierCap.trim() === '' ? undefined : Number(editMultiplierCap)
      const creationRatioNum = editCreationRatio.trim() === '' ? undefined : Number(editCreationRatio)
      await updateKey.mutateAsync({
        id: editTarget.id,
        req: {
          name: editName.trim(),
          description: editDesc.trim(),
          group: editGroup.trim(),
          cacheReadRatio:
            ratioNum != null && Number.isFinite(ratioNum) ? ratioNum : undefined,
          cacheMultiplierCap:
            capNum != null && Number.isFinite(capNum) ? capNum : undefined,
          cacheBillingMode: editBillingMode,
          cacheCreationRatio:
            creationRatioNum != null && Number.isFinite(creationRatioNum) ? creationRatioNum : undefined,
          simplifyCcPrompt: editSimplifyCc,
          stripBoundaryMarkers: editStripBoundary,
          stripEnvNoise: editStripEnv,
          responseCacheEnabled: editRespCache,
          responseCacheTtlSecs:
            editRespCache && editRespCacheTtl.trim() !== '' && Number.isFinite(Number(editRespCacheTtl))
              ? Math.trunc(Number(editRespCacheTtl))
              : undefined,
        },
      })
      toast.success('已更新')
      setEditOpen(false)
    } catch (err) {
      toast.error('更新失败：' + extractErrorMessage(err))
    }
  }

  const copyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      toast.success('已复制')
    } catch {
      toast.error('复制失败')
    }
  }

  return (
    <div>
      <div className="mb-6 flex items-end justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight leading-tight">客户端 Key</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            分发给下游用户/项目的访问密钥。每把 Key 独立计数与禁用，泄露后只需替换一把。
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)} size="sm">
          <Plus className="h-3.5 w-3.5" />新建 Key
        </Button>
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="py-16 text-center text-sm text-muted-foreground">
            加载中…
          </CardContent>
        </Card>
      ) : !data || data.keys.length === 0 ? (
        <Card>
          <CardContent className="py-16 text-center">
            <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-secondary text-muted-foreground">
              <KeyRound className="h-5 w-5" />
            </div>
            <p className="text-sm text-muted-foreground">还没有客户端 Key，点击右上角"新建 Key"开始</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full min-w-[920px] text-sm">
              <thead className="text-[12px] text-muted-foreground border-b border-border/60">
                <tr className="whitespace-nowrap">
                  <th className="text-left font-medium px-4 py-3">ID</th>
                  <th className="text-left font-medium px-4 py-3">名称</th>
                  <th className="text-left font-medium px-4 py-3">Key</th>
                  <th className="text-left font-medium px-4 py-3">分组</th>
                  <th className="text-left font-medium px-4 py-3">状态</th>
                  <th className="text-right font-medium px-4 py-3">总调用</th>
                  <th className="text-right font-medium px-4 py-3">输入</th>
                  <th className="text-right font-medium px-4 py-3">输出</th>
                  <th className="text-left font-medium px-4 py-3">最后使用</th>
                  <th className="text-right font-medium px-4 py-3">操作</th>
                </tr>
              </thead>
              <tbody>
                {data.keys.map((k) => (
                  <tr key={k.id} className="border-t border-border/40 whitespace-nowrap">
                    <td className="px-4 py-3 font-mono text-[12px] text-muted-foreground tabular-nums">
                      #{k.id}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className="max-w-[220px] truncate font-medium">{k.name}</span>
                        {k.isSystem && (
                          <Badge variant="secondary" title="由 config.json apiKey 导入，不可删除 / 不可轮换">
                            系统
                          </Badge>
                        )}
                      </div>
                      {k.description && (
                        <div className="max-w-[220px] truncate text-[11px] text-muted-foreground">
                          {k.description}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <button
                            type="button"
                            className="rounded px-1 py-0.5 font-mono text-[12px] text-muted-foreground hover:bg-accent/60 focus:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                            title="点击展开 Key 操作"
                          >
                            {k.maskedKey}
                          </button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="start">
                          <DropdownMenuItem onSelect={() => handleRotate(k)}>
                            <RefreshCw className="h-3.5 w-3.5" />
                            重新生成 Key（旧 Key 立即失效）
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </td>
                    <td className="px-4 py-3">
                      {k.group ? (
                        <Badge variant="outline">{k.group}</Badge>
                      ) : (
                        <span className="text-[12px] text-muted-foreground">全部账号</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {k.disabled ? (
                        <Badge variant="destructive">已禁用</Badge>
                      ) : (
                        <Badge variant="success">启用</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">{k.totalCalls}</td>
                    <td className="px-4 py-3 text-right tabular-nums">{formatTokens(k.totalInputTokens)}</td>
                    <td className="px-4 py-3 text-right tabular-nums">{formatTokens(k.totalOutputTokens)}</td>
                    <td className="px-4 py-3 text-[12px] text-muted-foreground">
                      {formatRelative(k.lastUsedAt)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7"
                          onClick={() => startEdit(k)}
                          title="改名"
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7"
                          onClick={() => handleToggleDisabled(k)}
                          title={k.disabled ? '启用' : '禁用'}
                        >
                          <Power className={`h-3.5 w-3.5 ${k.disabled ? 'text-emerald-500' : 'text-amber-500'}`} />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-7 w-7"
                          onClick={() => handleReset(k)}
                          title="重置统计"
                        >
                          <RotateCcw className="h-3.5 w-3.5" />
                        </Button>
                        {!k.isSystem && (
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-7 w-7"
                            onClick={() => handleDelete(k)}
                            title="删除"
                          >
                            <Trash2 className="h-3.5 w-3.5 text-destructive" />
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      {/* 新建对话框 */}
      <Dialog open={createOpen} onOpenChange={(o) => !createKey.isPending && setCreateOpen(o)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>新建客户端 Key</DialogTitle>
            <DialogDescription>
              创建后明文 Key 仅显示一次，请立即复制保存到安全位置。
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 py-2">
            <div>
              <label className="text-[12px] text-muted-foreground">名称 *</label>
              <Input
                placeholder="VS Code 本机 / 团队 A 等"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                disabled={createKey.isPending}
                autoFocus
              />
            </div>
            <div>
              <label className="text-[12px] text-muted-foreground">描述（可选）</label>
              <Input
                placeholder="可选备注，如绑定的项目、负责人等"
                value={createDesc}
                onChange={(e) => setCreateDesc(e.target.value)}
                disabled={createKey.isPending}
              />
            </div>
            <div>
              <label className="text-[12px] text-muted-foreground">绑定分组（可选）</label>
              <GroupSingleSelect
                value={createGroup}
                options={groupOptions}
                onChange={setCreateGroup}
                disabled={createKey.isPending}
                noneLabel="（不绑定，可用全部账号）"
              />
              <p className="mt-1 text-[11px] text-muted-foreground">
                绑定后该 Key 仅会使用含此分组的账号（严格隔离，分组内无可用账号时请求会失败）。
              </p>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setCreateOpen(false)} disabled={createKey.isPending}>
                取消
              </Button>
              <Button type="submit" disabled={createKey.isPending || !createName.trim()}>
                {createKey.isPending ? '创建中…' : '创建'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* 创建后明文展示对话框 */}
      <Dialog open={!!createdKey} onOpenChange={(o) => { if (!o) setCreatedKey(null) }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-emerald-500" />
              Key 已生成
            </DialogTitle>
            <DialogDescription>
              这是 Key "{createdKey?.name}" 的明文。<strong>关闭对话框后将无法再查看</strong>，请立即复制。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="relative">
              <Input
                readOnly
                type={showCreatedPlain ? 'text' : 'password'}
                value={createdKey?.key ?? ''}
                className="pr-20 font-mono text-[13px]"
              />
              <div className="absolute inset-y-0 right-0 flex items-center pr-1">
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="h-7 w-7"
                  onClick={() => setShowCreatedPlain((v) => !v)}
                  title={showCreatedPlain ? '隐藏' : '显示'}
                >
                  {showCreatedPlain ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="h-7 w-7"
                  onClick={() => createdKey && copyText(createdKey.key)}
                  title="复制"
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
            <p className="text-[11px] text-muted-foreground">
              客户端调用 <code>/v1/messages</code> 时，把它放在 <code>x-api-key</code> 或 <code>Authorization: Bearer</code> 头中。
            </p>
          </div>
          <DialogFooter>
            <Button onClick={() => setCreatedKey(null)}>我已保存好</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 编辑对话框 */}
      <Dialog open={editOpen} onOpenChange={(o) => !updateKey.isPending && setEditOpen(o)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>编辑 Key</DialogTitle>
            <DialogDescription>修改名称与描述（不影响 Key 值与统计）</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleEditSave} className="space-y-3 py-2">
            <div>
              <label className="text-[12px] text-muted-foreground">名称</label>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            <div>
              <label className="text-[12px] text-muted-foreground">描述</label>
              <Input value={editDesc} onChange={(e) => setEditDesc(e.target.value)} />
            </div>
            <div>
              <label className="text-[12px] text-muted-foreground">绑定分组</label>
              <GroupSingleSelect
                value={editGroup}
                options={groupOptions}
                onChange={setEditGroup}
                disabled={updateKey.isPending}
                noneLabel="（不绑定，可用全部账号）"
              />
              <p className="mt-1 text-[11px] text-muted-foreground">
                绑定后仅调度该分组内账号（严格隔离）。选「不绑定」表示解除绑定。
              </p>
            </div>

            {/* 检测安全计费（R 阻尼 + multiplier 护栏，sum 恒==total，非超报） */}
            <div className="rounded-lg border border-border/60 p-3">
              <div>
                <label className="text-[13px] font-medium">检测安全计费</label>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  上报恒 == 真实用量（不超报）。R&lt;1 把便宜的 read 挪回 input 出 margin，护栏保证 multiplier 永不越上限。
                </p>
              </div>
              {/* 利润档滑块（复用 R）：命中率≈R，multiplier≈1−0.9R；越左命中越高利润越低 */}
              {(() => {
                const rParsed = editReadRatio.trim() === '' ? 1.0 : parseFloat(editReadRatio)
                const rv = Number.isFinite(rParsed) ? Math.min(1, Math.max(0, rParsed)) : 1.0
                const capParsed = editMultiplierCap.trim() === '' ? 1.25 : parseFloat(editMultiplierCap)
                const cap = Number.isFinite(capParsed) ? Math.min(1.25, Math.max(0.1, capParsed)) : 1.25
                const hit = Math.round(rv * 100)
                const mult = Math.min(cap, 1 - 0.9 * rv)
                const band: [string, string] = mult <= 1.0
                  ? ['正常', 'text-emerald-600']
                  : mult <= 1.25
                  ? ['临界', 'text-amber-600']
                  : ['异常', 'text-red-600']
                return (
                  <div className="mt-3">
                    <div className="mb-1 flex items-center justify-between">
                      <div className="text-sm">利润档（read 留存 R）</div>
                      <span className="text-[11px] text-muted-foreground">
                        {editReadRatio.trim() === '' ? '默认 1.0' : `R=${rv.toFixed(2)}`}
                      </span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={1}
                      step={0.05}
                      value={rv}
                      onChange={(e) => setEditReadRatio(e.target.value)}
                      disabled={updateKey.isPending}
                      className="w-full accent-primary disabled:opacity-50"
                    />
                    <div className="mt-1 flex items-center justify-between text-[11px] text-muted-foreground">
                      <span>← 命中率高·利润低</span>
                      <span>利润高·命中率低 →</span>
                    </div>
                    <div className="mt-2 flex items-center gap-3 rounded bg-muted/60 px-2 py-1 text-[11px]">
                      <span>预计命中率 <b>{hit}%</b></span>
                      <span>multiplier <b>{mult.toFixed(2)}×</b></span>
                      <span>检测带 <b className={band[1]}>{band[0]}</b></span>
                    </div>
                  </div>
                )
              })()}
              <div className="mt-3">
                <label className="text-[11px] text-muted-foreground">护栏上限 (0.1~1.25)</label>
                <Input
                  type="number"
                  step="0.05"
                  min="0.1"
                  max="1.25"
                  placeholder="默认 1.25"
                  value={editMultiplierCap}
                  onChange={(e) => setEditMultiplierCap(e.target.value)}
                  disabled={updateKey.isPending}
                  className="mt-1 h-8 w-32"
                />
                <p className="mt-2 text-[11px] text-muted-foreground">
                  R 越低 margin 越高、命中率显示越低；护栏兜底 weighted/total ≤ 上限。留空用默认值（纯真实形状）。
                </p>
              </div>
            </div>

            {/* prompt 过滤（省 prefill） */}
            <div className="rounded-lg border border-border/60 p-3 space-y-2.5">
              <div>
                <label className="text-[13px] font-medium">Prompt 过滤</label>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  转换前裁剪客户端 system，省 prefill token。
                </p>
              </div>
              <div className="flex items-center justify-between">
                <div className="pr-3">
                  <span className="text-[12px]">简化 Claude Code 提示</span>
                  <p className="text-[11px] text-muted-foreground">命中 CC 内置 system 时整段换成极小 backend prompt（激进，丢 CC 引导）。</p>
                </div>
                <Switch checked={editSimplifyCc} onCheckedChange={setEditSimplifyCc} disabled={updateKey.isPending} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[12px]">删除边界标记行</span>
                <Switch checked={editStripBoundary} onCheckedChange={setEditStripBoundary} disabled={updateKey.isPending} />
              </div>
              <div className="flex items-center justify-between">
                <div className="pr-3">
                  <span className="text-[12px]">删除环境噪声</span>
                  <p className="text-[11px] text-muted-foreground"># Environment / # auto memory 段、gitStatus、cutoff 等行。</p>
                </div>
                <Switch checked={editStripEnv} onCheckedChange={setEditStripEnv} disabled={updateKey.isPending} />
              </div>
            </div>

            {/* 真实响应缓存 */}
            <div className="rounded-lg border border-border/60 p-3">
              <div className="flex items-center justify-between">
                <div className="pr-3">
                  <label className="text-[13px] font-medium">响应缓存</label>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                    同请求（同会话/model/messages/tools）命中直接回放，跳过上游。只缓存干净 end_turn 响应。
                  </p>
                </div>
                <Switch checked={editRespCache} onCheckedChange={setEditRespCache} disabled={updateKey.isPending} />
              </div>
              {editRespCache && (
                <div className="mt-3">
                  <label className="text-[11px] text-muted-foreground">TTL（秒）</label>
                  <Input
                    type="number"
                    step="1"
                    min="1"
                    placeholder="默认跟随全局（180）"
                    value={editRespCacheTtl}
                    onChange={(e) => setEditRespCacheTtl(e.target.value)}
                    disabled={updateKey.isPending}
                  />
                  <p className="mt-1 text-[11px] text-muted-foreground">留空跟随全局默认。</p>
                </div>
              )}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setEditOpen(false)}>取消</Button>
              <Button type="submit" disabled={updateKey.isPending}>
                {updateKey.isPending ? '保存中…' : '保存'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
