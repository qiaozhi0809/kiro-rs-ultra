import { Sparkles, Crown, Zap, Gem, Tag } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SubscriptionBadgeProps {
  title?: string | null
  /** "sm" 用于卡片标题区紧凑展示；"md" 用于余额面板等突出位置 */
  size?: 'sm' | 'md'
  className?: string
}

export type Tier = 'free' | 'pro' | 'pro_plus' | 'power' | 'unknown'

interface TierStyle {
  /** 容器背景与文字颜色 */
  container: string
  /** 图标 */
  Icon: React.ComponentType<{ className?: string }>
  /** 大写标准化标题 */
  label: string
}

/** 根据订阅标题推断分级（供列表筛选复用） */
export function detectTier(title?: string | null): Tier {
  if (!title) return 'unknown'
  const upper = title.toUpperCase()
  if (upper.includes('POWER')) return 'power'
  if (upper.includes('PRO+') || upper.includes('PRO PLUS')) return 'pro_plus'
  if (upper.includes('PRO')) return 'pro'
  if (upper.includes('FREE')) return 'free'
  return 'unknown'
}

function getTierStyle(tier: Tier, original?: string | null): TierStyle {
  const fallback = original?.replace(/^KIRO\s+/i, '').trim() || '未知'
  switch (tier) {
    case 'power':
      // 钻紫渐变 — 顶级版，最强视觉
      return {
        Icon: Gem,
        label: 'POWER',
        container:
          'bg-gradient-to-br from-fuchsia-500 to-violet-600 text-white shadow-[0_2px_8px_-2px_rgba(168,85,247,0.5)] border-transparent',
      }
    case 'pro_plus':
      // 金色渐变 — Pro+ 高级身份
      return {
        Icon: Crown,
        label: 'PRO+',
        container:
          'bg-gradient-to-br from-amber-400 to-orange-500 text-white shadow-[0_2px_8px_-2px_rgba(245,158,11,0.5)] border-transparent',
      }
    case 'pro':
      // 苹果蓝渐变 — 标准 Pro
      return {
        Icon: Sparkles,
        label: 'PRO',
        container:
          'bg-gradient-to-br from-sky-500 to-blue-600 text-white shadow-[0_2px_8px_-2px_rgba(59,130,246,0.45)] border-transparent',
      }
    case 'free':
      // 中性灰 — 免费层弱化
      return {
        Icon: Zap,
        label: 'FREE',
        container:
          'bg-secondary text-muted-foreground border border-border/70',
      }
    default:
      return {
        Icon: Tag,
        label: fallback,
        container: 'bg-muted text-muted-foreground border border-border/70',
      }
  }
}

export function SubscriptionBadge({ title, size = 'sm', className }: SubscriptionBadgeProps) {
  const tier = detectTier(title)
  const { container, Icon, label } = getTierStyle(tier, title)

  const sizing =
    size === 'md'
      ? 'h-7 px-2.5 text-[12px] gap-1.5 [&_svg]:h-3.5 [&_svg]:w-3.5'
      : 'h-5 px-1.5 text-[10px] gap-1 [&_svg]:h-3 [&_svg]:w-3'

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full font-semibold uppercase tracking-wide',
        sizing,
        container,
        className
      )}
      title={title || undefined}
    >
      <Icon />
      <span>{label}</span>
    </span>
  )
}
