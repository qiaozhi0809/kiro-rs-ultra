const API_KEY_STORAGE_KEY = 'adminApiKey'
const CREDENTIAL_VIEW_KEY = 'credentialView'
const CREDENTIAL_PAGE_SIZE_KEY = 'credentialPageSize'
const CREDENTIAL_DENSITY_KEY = 'credentialDensity'

export type CredentialView = 'card' | 'list'
/** 卡片视图密度：compact = 只显优先级/失败/刷新失败/成功/并发；detailed = 含调度评分/压力/EWMA 等完整指标 */
export type CredentialDensity = 'compact' | 'detailed'

/** 每页数量：0 视为“全部”（不分页） */
const DEFAULT_PAGE_SIZE = 12

export const storage = {
  getApiKey: () => localStorage.getItem(API_KEY_STORAGE_KEY),
  setApiKey: (key: string) => localStorage.setItem(API_KEY_STORAGE_KEY, key),
  removeApiKey: () => localStorage.removeItem(API_KEY_STORAGE_KEY),

  // 凭据列表的展示形态（卡片 / 列表），默认卡片
  getCredentialView: (): CredentialView =>
    localStorage.getItem(CREDENTIAL_VIEW_KEY) === 'list' ? 'list' : 'card',
  setCredentialView: (view: CredentialView) =>
    localStorage.setItem(CREDENTIAL_VIEW_KEY, view),

  // 凭据列表每页数量（0 = 全部），默认 12
  getCredentialPageSize: (): number => {
    const raw = localStorage.getItem(CREDENTIAL_PAGE_SIZE_KEY)
    if (raw === null) return DEFAULT_PAGE_SIZE
    const n = Number(raw)
    return Number.isInteger(n) && n >= 0 ? n : DEFAULT_PAGE_SIZE
  },
  setCredentialPageSize: (size: number) =>
    localStorage.setItem(CREDENTIAL_PAGE_SIZE_KEY, String(size)),

  // 卡片密度（仅影响卡片视图；列表视图本来就紧凑），默认 compact
  getCredentialDensity: (): CredentialDensity =>
    localStorage.getItem(CREDENTIAL_DENSITY_KEY) === 'detailed' ? 'detailed' : 'compact',
  setCredentialDensity: (d: CredentialDensity) =>
    localStorage.setItem(CREDENTIAL_DENSITY_KEY, d),
}
