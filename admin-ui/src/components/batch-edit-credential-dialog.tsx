import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { useQueryClient } from '@tanstack/react-query'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { GroupMultiSelect } from '@/components/group-select'
import { updateCredential, setCredentialPriority } from '@/api/credentials'
import type { CredentialStatusItem } from '@/types/api'

type GroupMode = 'replace' | 'add' | 'remove'

interface BatchEditCredentialDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** 选中的账号对象（add/remove 模式需读各自当前 groups） */
  credentials: CredentialStatusItem[]
  /** 现有分组选项（去重聚合） */
  groupOptions: string[]
  /** 完成后回调（清空选择等） */
  onDone: () => void
}

const MODE_LABELS: { value: GroupMode; label: string; desc: string }[] = [
  { value: 'replace', label: '替换', desc: '用所选分组覆盖各账号原有分组（不选=清除分组）' },
  { value: 'add', label: '追加', desc: '把所选分组并入各账号原有分组（去重）' },
  { value: 'remove', label: '移除', desc: '从各账号分组里移除所选分组' },
]

const PRIORITY_MAX = 9999

export function BatchEditCredentialDialog({
  open,
  onOpenChange,
  credentials,
  groupOptions,
  onDone,
}: BatchEditCredentialDialogProps) {
  const queryClient = useQueryClient()

  const [editGroups, setEditGroups] = useState(false)
  const [mode, setMode] = useState<GroupMode>('replace')
  const [groups, setGroups] = useState<string[]>([])

  const [editSource, setEditSource] = useState(false)
  const [sourceChannel, setSourceChannel] = useState('')

  const [editPriority, setEditPriority] = useState(false)
  const [priorityValue, setPriorityValue] = useState('0')

  const [editConcurrency, setEditConcurrency] = useState(false)
  const [concurrencyValue, setConcurrencyValue] = useState('')

  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState({ current: 0, total: 0 })

  useEffect(() => {
    if (open) {
      setEditGroups(false)
      setMode('replace')
      setGroups([])
      setEditSource(false)
      setSourceChannel('')
      setEditPriority(false)
      setPriorityValue('0')
      setEditConcurrency(false)
      setConcurrencyValue('')
      setRunning(false)
      setProgress({ current: 0, total: 0 })
    }
  }, [open])

  const computeGroups = (current: string[]): string[] => {
    if (mode === 'replace') return groups
    if (mode === 'add') return Array.from(new Set([...current, ...groups]))
    // remove
    return current.filter((g) => !groups.includes(g))
  }

  // 步进器：把当前输入值夹到 [0, PRIORITY_MAX] 后增减
  const stepPriority = (delta: number) => {
    const n = parseInt(priorityValue, 10)
    const base = Number.isFinite(n) ? n : 0
    setPriorityValue(String(Math.min(PRIORITY_MAX, Math.max(0, base + delta))))
  }
  const targetPriority = (): number | null => {
    const n = parseInt(priorityValue, 10)
    if (!Number.isFinite(n)) return null
    return Math.min(PRIORITY_MAX, Math.max(0, n))
  }

  const handleApply = async () => {
    if (!editGroups && !editSource && !editPriority && !editConcurrency) {
      toast.error('请至少开启一项要修改的字段')
      return
    }
    const prio = editPriority ? targetPriority() : null
    if (editPriority && prio === null) {
      toast.error('优先级数值无效')
      return
    }
    setRunning(true)
    setProgress({ current: 0, total: credentials.length })
    let ok = 0
    let fail = 0
    for (let i = 0; i < credentials.length; i++) {
      const c = credentials[i]
      const req: Record<string, unknown> = {}
      if (editGroups) req.groups = computeGroups(c.groups ?? [])
      if (editSource) req.sourceChannel = sourceChannel.trim()
      if (editConcurrency) {
        // 空串 → 0（清除覆盖，回退全局默认）；否则解析为数字
        req.concurrencyLimit =
          concurrencyValue.trim() === ''
            ? 0
            : Math.max(0, parseInt(concurrencyValue, 10) || 0)
      }
      try {
        if (Object.keys(req).length > 0) {
          await updateCredential(c.id, req)
        }
        if (prio !== null) {
          await setCredentialPriority(c.id, prio)
        }
        ok++
      } catch {
        fail++
      }
      setProgress({ current: i + 1, total: credentials.length })
    }
    await queryClient.invalidateQueries({ queryKey: ['credentials'] })
    setRunning(false)
    if (fail === 0) toast.success(`已更新 ${ok} 个账号`)
    else toast.warning(`成功 ${ok} 个，失败 ${fail} 个`)
    onOpenChange(false)
    onDone()
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !running && onOpenChange(o)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>批量编辑（{credentials.length} 个账号）</DialogTitle>
          <DialogDescription>
            仅修改下方开启的字段，未开启的字段保持不变。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5 py-2">
          {/* 分组区 */}
          <div className="space-y-3 rounded-xl border border-border/60 p-3">
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium">修改分组</span>
              <Switch checked={editGroups} onCheckedChange={setEditGroups} disabled={running} />
            </label>
            {editGroups && (
              <>
                <div className="flex gap-2">
                  {MODE_LABELS.map((m) => (
                    <Button
                      key={m.value}
                      type="button"
                      size="sm"
                      variant={mode === m.value ? 'default' : 'outline'}
                      onClick={() => setMode(m.value)}
                      disabled={running}
                    >
                      {m.label}
                    </Button>
                  ))}
                </div>
                <p className="text-[11px] text-muted-foreground">
                  {MODE_LABELS.find((m) => m.value === mode)?.desc}
                </p>
                <GroupMultiSelect
                  value={groups}
                  options={groupOptions}
                  onChange={setGroups}
                  disabled={running}
                />
              </>
            )}
          </div>

          {/* 来源渠道区 */}
          <div className="space-y-3 rounded-xl border border-border/60 p-3">
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium">修改来源渠道</span>
              <Switch checked={editSource} onCheckedChange={setEditSource} disabled={running} />
            </label>
            {editSource && (
              <>
                <Input
                  placeholder="应用到所有选中账号（留空 = 清除）"
                  value={sourceChannel}
                  onChange={(e) => setSourceChannel(e.target.value)}
                  disabled={running}
                />
                <p className="text-[11px] text-muted-foreground">纯备注，标记账号来源/渠道。</p>
              </>
            )}
          </div>

          {/* 优先级区 */}
          <div className="space-y-3 rounded-xl border border-border/60 p-3">
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium">修改优先级</span>
              <Switch checked={editPriority} onCheckedChange={setEditPriority} disabled={running} />
            </label>
            {editPriority && (
              <>
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    size="icon"
                    variant="outline"
                    onClick={() => stepPriority(-1)}
                    disabled={running}
                    aria-label="减小优先级"
                  >
                    −
                  </Button>
                  <Input
                    type="number"
                    min={0}
                    max={PRIORITY_MAX}
                    className="text-center"
                    value={priorityValue}
                    onChange={(e) => setPriorityValue(e.target.value)}
                    disabled={running}
                  />
                  <Button
                    type="button"
                    size="icon"
                    variant="outline"
                    onClick={() => stepPriority(1)}
                    disabled={running}
                    aria-label="增大优先级"
                  >
                    +
                  </Button>
                </div>
                <p className="text-[11px] text-muted-foreground">
                  把所有选中账号的优先级设为此值（数字越小越优先）。可用 −/+ 微调或直接输入。
                </p>
              </>
            )}
          </div>

          {/* 并发上限区 */}
          <div className="space-y-3 rounded-xl border border-border/60 p-3">
            <label className="flex items-center justify-between">
              <span className="text-sm font-medium">修改并发上限</span>
              <Switch
                checked={editConcurrency}
                onCheckedChange={setEditConcurrency}
                disabled={running}
              />
            </label>
            {editConcurrency && (
              <>
                <Input
                  type="number"
                  min={1}
                  placeholder="应用到所有选中账号（留空 = 用全局默认）"
                  value={concurrencyValue}
                  onChange={(e) => setConcurrencyValue(e.target.value)}
                  disabled={running}
                />
                <p className="text-[11px] text-muted-foreground">
                  各账号同时进行中的请求数上限。留空 = 清除覆盖回退全局默认。
                </p>
              </>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={running}>
            取消
          </Button>
          <Button type="button" onClick={handleApply} disabled={running}>
            {running ? `应用中… ${progress.current}/${progress.total}` : '应用'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
