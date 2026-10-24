import type { Language } from './types'

export function baseName(path: string): string {
  const parts = path.split(/[\/]/)
  return parts[parts.length - 1] ?? path
}

export function isEnvFile(path: string): boolean {
  return /^\.env(\..+)?$/i.test(baseName(path))
}

/** .env.example / .env.sample / .env.template are meant to be committed. */
export function isEnvTemplate(path: string): boolean {
  return /^\.env\.(example|sample|template|dist|defaults)$/i.test(baseName(path))
}

export function detectLanguage(path: string): Language | null {
  const name = baseName(path).toLowerCase()
  if (isEnvFile(name)) return 'env'
  if (name === '.gitignore') return 'text'
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : ''
  switch (ext) {
    case 'js': case 'jsx': case 'mjs': case 'cjs': return 'javascript'
    case 'ts': case 'tsx': case 'mts': case 'cts': return 'typescript'
    case 'py': return 'python'
    case 'json': return 'json'
    case 'yaml': case 'yml': return 'yaml'
    case 'toml': return 'toml'
    case 'ini': case 'cfg': return 'ini'
    case 'sql': return 'sql'
    case 'sh': case 'bash': case 'zsh': return 'shell'
    default: return null
  }
}

export const LANGUAGE_LABEL: Record<Language, string> = {
  javascript: 'JavaScript', typescript: 'TypeScript', python: 'Python', env: 'dotenv', json: 'JSON',
  yaml: 'YAML', toml: 'TOML', ini: 'INI', sql: 'SQL', shell: 'Shell', text: 'Text',
}
