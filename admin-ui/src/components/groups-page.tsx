import { useState } from 'react'
import { toast } from 'sonner'
import {
  Plus, FolderTree, Trash2, Pencil, Users, KeyRound, RefreshCw,
} from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from '@/components/ui/dialog'
import {
  Select, SelectTrigger, SelectValue, SelectContent, SelectItem,
} from '@/components/ui/select'
import {
  useGroups, useCreateGroup, useUpdateGroup, useDeleteGroup,
} from '@/hooks/use-groups'
import { useConfirm } from '@/components/ui/confirm-dialog'
import { extractErrorMessage } from '@/lib/utils'
import type { CacheMode, GroupItem } from '@/types/api'

/**
 * 分组管理页：CRUD 已注册分组。
 *
 * 设计要点：
 * - 分组是独立实体，凭据 / 客户端 Key 通过名字引用
 * - 改名走级联（后端自动同步所有引用）
 * - 删除默认拒绝有引用的，二次确认才允许 force 级联清理
 * - 列表展示每个分组当前被多少个凭据 / Key 引用，删除前清楚知道影响
 * - 缓存档（cacheMode）三档可选：off / low / high；不选 = 继承全局默认
 */

/** 编辑表单内 cacheMode 控件状态（'__inherit__' 仅用于 UI，提交时映射为 'inherit'） */
type CacheModeFormValue = CacheMode | '__inherit__'

const CACHE_MODE_LABEL: Record<CacheMode, string> = {
  off: '无缓存',
  low: '低命中',
  high: '高命中',
}

export function GroupsPage() {
  const { data, isLoading, isFetching, refetch } = useGroups()
  const createGroup = useCreateGroup()
  const updateGroup = useUpdateGroup()
  const deleteGroup = useDeleteGroup()
  const confirm = useConfirm()

  const [createOpen, setCreateOpen] = useState(false)
  const [createName, setCreateName] = useState('')
  const [createDesc, setCreateDesc] = useState('')
  const [createCache, setCreateCache] = useState<CacheModeFormValue>('__inherit__')
  /** 创建表单的 compact 阈值：'__inherit__' = 继承全局；否则是 0.5-1.0 的字符串（百分比形式输入） */
  const [createCompact, setCreateCompact] = useState<string>('__inherit__')

  const [editOpen, setEditOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<GroupItem | null>(null)
  const [editNewName, setEditNewName] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editCache, setEditCache] = useState<CacheModeFormValue>('__inherit__')
  const [editCompact, setEditCompact] = useState<string>('__inherit__')

  const groups = data?.groups ?? []

  const openCreate = () => {
    setCreateName('')
    setCreateDesc('')
    setCreateCache('__inherit__')
    setCreateCompact('__inherit__')
    setCreateOpen(true)
  }

  const parseCompactInput = (raw: string): { value?: number; error?: string } => {
    if (raw === '__inherit__' || raw.trim() === '') return {}
    const n = Number(raw)
    if (!Number.isFinite(n)) return { error: '请输入有效数字（百分比，50-100）' }
    const ratio = n > 1 ? n / 100 : n
    if (ratio < 0.5 || ratio > 1.0) return { error: '阈值必须在 50% ~ 100% 之间' }
    return { value: ratio }
  }

  const handleCreate = async () => {
    const name = createName.trim()
    if (!name) {
      toast.error('分组名不能为空')
      return
    }
    const compact = parseCompactInput(createCompact)
    if (compact.error) {
      toast.error(compact.error)
      return
    }
    try {
      await createGroup.mutateAsync({
        name,
        description: createDesc.trim() || undefined,
        cacheMode: createCache === '__inherit__' ? undefined : createCache,
        compactThreshold: compact.value,
      })
      toast.success(`已创建分组：${name}`)
      setCreateOpen(false)
    } catch (e) {
      toast.error(extractErrorMessage(e))
    }
  }

  const openEdit = (g: GroupItem) => {
    setEditTarget(g)
    setEditNewName(g.name)
    setEditDesc(g.description ?? '')
    setEditCache(g.cacheMode ?? '__inherit__')
    setEditCompact(
      g.compactThreshold == null ? '__inherit__' : String(Math.round(g.compactThreshold * 100)),
    )
    setEditOpen(true)
  }

  const handleEdit = async () => {
    if (!editTarget) return
    const newName = editNewName.trim()
    if (!newName) {
      toast.error('分组名不能为空')
      return
    }
    // 只有当 UI 值与原值不同才下发 cacheMode 字段，避免误清空
    const originalCache: CacheModeFormValue = editTarget.cacheMode ?? '__inherit__'
    const cacheChanged = editCache !== originalCache
    const cacheModePatch = !cacheChanged
      ? undefined
      : editCache === '__inherit__'
        ? 'inherit'
        : editCache
    // compactThreshold 同理：只在变化时下发
    const originalCompact =
      editTarget.compactThreshold == null
        ? '__inherit__'
        : String(Math.round(editTarget.compactThreshold * 100))
    const compactChanged = editCompact !== originalCompact
    let compactPatch: { compactThreshold?: number; compactThresholdInherit?: boolean } = {}
    if (compactChanged) {
      if (editCompact === '__inherit__') {
        compactPatch = { compactThresholdInherit: true }
      } else {
        const parsed = parseCompactInput(editCompact)
        if (parsed.error) {
          toast.error(parsed.error)
          return
        }
        if (parsed.value != null) compactPatch = { compactThreshold: parsed.value }
      }
    }
    try {
      await updateGroup.mutateAsync({
        name: editTarget.name,
        req: {
          newName: newName !== editTarget.name ? newName : undefined,
          description: editDesc, // 空字符串 → 后端清空
          cacheMode: cacheModePatch,
          ...compactPatch,
        },
      })
      const renamed = newName !== editTarget.name
      toast.success(renamed ? `已改名：${editTarget.name} → ${newName}` : '已更新')
      setEditOpen(false)
    } catch (e) {
      toast.error(extractErrorMessage(e))
    }
  }

  const handleDelete = async (g: GroupItem) => {
    const refs = g.credentialCount + g.clientKeyCount
    // 无引用：单层确认；有引用：二次确认 + force
    if (refs === 0) {
      const ok = await confirm({
        title: `删除分组 ${g.name}？`,
        description: '该分组当前无任何引用，可以安全删除。',
        confirmText: '删除',
        destructive: true,
      })
      if (!ok) return
      try {
        await deleteGroup.mutateAsync({ name: g.name })
        toast.success(`分组 ${g.name} 已删除`)
      } catch (e) {
        toast.error(extractErrorMessage(e))
      }
    } else {
      const ok = await confirm({
        title: `强制删除分组 ${g.name}？`,
        description: `该分组当前被 ${g.credentialCount} 个凭据 + ${g.clientKeyCount} 把客户端 Key 引用。继续将级联清理这些引用（凭据从 groups 列表移除该分组；客户端 Key 解除绑定）。此操作不可撤销。`,
        confirmText: '强制删除',
        destructive: true,
      })
      if (!ok) return
      try {
        await deleteGroup.mutateAsync({ name: g.name, force: true })
        toast.success(`分组 ${g.name} 已删除，已清理 ${refs} 个引用`)
      } catch (e) {
        toast.error(extractErrorMessage(e))
      }
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <FolderTree className="h-4 w-4" />
            分组管理
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            分组是凭据 / 客户端 Key 共享的独立实体；改名 / 删除会级联同步。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
            刷新
          </Button>
          <Button size="sm" onClick={openCreate}>
            <Plus className="h-3.5 w-3.5" />
            新建分组
          </Button>
        </div>
      </div>

      {isLoading ? (
        <Card><CardContent className="py-8 text-sm text-center text-muted-foreground">加载中…</CardContent></Card>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-sm text-center text-muted-foreground space-y-2">
            <FolderTree className="h-8 w-8 mx-auto opacity-40" />
            <p>暂无分组。点上方「新建分组」开始。</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {groups.map((g) => (
            <Card key={g.name}>
              <CardContent className="p-4 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="font-medium truncate">{g.name}</div>
                    {g.description && (
                      <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{g.description}</p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => openEdit(g)} title="编辑">
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7 text-destructive hover:text-destructive"
                      onClick={() => handleDelete(g)}
                      title="删除"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <Badge variant="secondary" className="gap-1">
                    <Users className="h-3 w-3" />
                    {g.credentialCount} 凭据
                  </Badge>
                  <Badge variant="secondary" className="gap-1">
                    <KeyRound className="h-3 w-3" />
                    {g.clientKeyCount} Key
                  </Badge>
                  {g.cacheMode ? (
                    <Badge variant="outline" title="本组覆盖的缓存档">
                      缓存：{CACHE_MODE_LABEL[g.cacheMode]}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-muted-foreground" title="未覆盖；使用全局默认 cacheModeDefault">
                      缓存：默认
                    </Badge>
                  )}
                  {g.compactThreshold != null ? (
                    <Badge variant="outline" title="本组覆盖的压缩阈值">
                      压缩：{Math.round(g.compactThreshold * 100)}%
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-muted-foreground" title="未覆盖；使用全局默认 contextCompactThresholdDefault">
                      压缩：默认
                    </Badge>
                  )}
                </div>

                <p className="text-[11px] text-muted-foreground">
                  创建于 {new Date(g.createdAt).toLocaleString()}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* 新建分组弹框 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建分组</DialogTitle>
            <DialogDescription>
              注册后即可在凭据 / 客户端 Key 中选择该分组。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">分组名 *</label>
              <Input
                placeholder="例如：客户A、生产、备用池"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                disabled={createGroup.isPending}
                autoFocus
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">备注（可选）</label>
              <Input
                placeholder="用途说明，方便后续辨认"
                value={createDesc}
                onChange={(e) => setCreateDesc(e.target.value)}
                disabled={createGroup.isPending}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">缓存档</label>
              <Select
                value={createCache}
                onValueChange={(v) => setCreateCache(v as CacheModeFormValue)}
                disabled={createGroup.isPending}
              >
                <SelectTrigger className="h-10">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__inherit__">跟随全局默认</SelectItem>
                  <SelectItem value="off">无缓存（off）</SelectItem>
                  <SelectItem value="low">低命中（low）</SelectItem>
                  <SelectItem value="high">高命中（high）</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                同会话粘同账号的强度。高命中突破并发上限 ×2 强粘（适合高活跃组）；低命中满则让步换号；无缓存不粘。
              </p>
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">上下文压缩阈值</label>
              <div className="flex items-center gap-2">
                <Input
                  type="text"
                  inputMode="numeric"
                  className="h-9 max-w-[140px]"
                  placeholder="跟随全局（默认 95）"
                  value={createCompact === '__inherit__' ? '' : createCompact}
                  onChange={(e) => {
                    const v = e.target.value.trim()
                    setCreateCompact(v === '' ? '__inherit__' : v)
                  }}
                  disabled={createGroup.isPending}
                />
                <span className="text-sm text-muted-foreground">%</span>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setCreateCompact('__inherit__')}
                  disabled={createGroup.isPending || createCompact === '__inherit__'}
                  className="text-xs"
                >
                  跟随全局
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                上下文使用率达到此百分比时主动让客户端 auto-compact（50–100，默认 95）。设低一点能更早做摘要、避开 400。
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)} disabled={createGroup.isPending}>
              取消
            </Button>
            <Button onClick={handleCreate} disabled={createGroup.isPending || !createName.trim()}>
              {createGroup.isPending ? '创建中…' : '创建'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 编辑分组弹框 */}
      <Dialog open={editOpen} onOpenChange={setEditOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>编辑分组：{editTarget?.name}</DialogTitle>
            <DialogDescription>
              改名会级联同步所有引用此分组的凭据与客户端 Key。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">分组名</label>
              <Input
                value={editNewName}
                onChange={(e) => setEditNewName(e.target.value)}
                disabled={updateGroup.isPending}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">备注</label>
              <Input
                placeholder="（清空备注请留空）"
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                disabled={updateGroup.isPending}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">缓存档</label>
              <Select
                value={editCache}
                onValueChange={(v) => setEditCache(v as CacheModeFormValue)}
                disabled={updateGroup.isPending}
              >
                <SelectTrigger className="h-10">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__inherit__">跟随全局默认</SelectItem>
                  <SelectItem value="off">无缓存（off）</SelectItem>
                  <SelectItem value="low">低命中（low）</SelectItem>
                  <SelectItem value="high">高命中（high）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">上下文压缩阈值</label>
              <div className="flex items-center gap-2">
                <Input
                  type="text"
                  inputMode="numeric"
                  className="h-9 max-w-[140px]"
                  placeholder="跟随全局（默认 95）"
                  value={editCompact === '__inherit__' ? '' : editCompact}
                  onChange={(e) => {
                    const v = e.target.value.trim()
                    setEditCompact(v === '' ? '__inherit__' : v)
                  }}
                  disabled={updateGroup.isPending}
                />
                <span className="text-sm text-muted-foreground">%</span>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setEditCompact('__inherit__')}
                  disabled={updateGroup.isPending || editCompact === '__inherit__'}
                  className="text-xs"
                >
                  跟随全局
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                上下文使用率达到此百分比时主动让客户端 auto-compact（50–100，默认 95）。
              </p>
            </div>
            {editTarget && (editTarget.credentialCount > 0 || editTarget.clientKeyCount > 0) && (
              <p className="text-xs text-amber-600">
                当前被 {editTarget.credentialCount} 凭据 + {editTarget.clientKeyCount} 客户端 Key 引用，改名会自动同步。
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditOpen(false)} disabled={updateGroup.isPending}>
              取消
            </Button>
            <Button onClick={handleEdit} disabled={updateGroup.isPending || !editNewName.trim()}>
              {updateGroup.isPending ? '保存中…' : '保存'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
