import type { SkippedFile, SourceFile } from './types'
import { detectLanguage } from './language'

export const MAX_BYTES = 1024 * 1024
const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', 'coverage', '__pycache__', '.venv', 'venv', '.turbo', '.cache', 'target', 'vendor'])

export interface IntakeResult { files: SourceFile[]; skipped: SkippedFile[] }

function inIgnoredDir(path: string): boolean {
  return path.split(/[\\/]/).slice(0, -1).some((seg) => IGNORED_DIRS.has(seg))
}

function looksBinary(text: string): boolean {
  return text.slice(0, 8000).includes('\u0000')
}

async function accept(file: File, path: string, out: IntakeResult): Promise<void> {
  if (inIgnoredDir(path)) return void out.skipped.push({ path, reason: 'ignored-dir' })
  if (!detectLanguage(path)) return void out.skipped.push({ path, reason: 'unsupported' })
  if (file.size > MAX_BYTES) return void out.skipped.push({ path, reason: 'too-large' })
  const content = await file.text()
  if (looksBinary(content)) return void out.skipped.push({ path, reason: 'binary' })
  out.files.push({ path, content: content.replace(/\r\n/g, '\n') })
}

/** Files from <input type=file> (with or without webkitdirectory). Read locally with File.text(); nothing is uploaded. */
export async function readFileList(list: FileList | File[]): Promise<IntakeResult> {
  const out: IntakeResult = { files: [], skipped: [] }
  for (const file of Array.from(list)) {
    await accept(file, file.webkitRelativePath || file.name, out)
  }
  return out
}

function entryFile(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => entry.file(resolve, reject))
}

function readAllEntries(dir: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> {
  const reader = dir.createReader()
  const all: FileSystemEntry[] = []
  return new Promise((resolve, reject) => {
    const next = () => reader.readEntries((batch) => {
      if (batch.length === 0) return resolve(all)
      all.push(...batch)
      next()
    }, reject)
    next()
  })
}

async function walk(entry: FileSystemEntry, out: IntakeResult): Promise<void> {
  const path = entry.fullPath.replace(/^\//, '')
  if (entry.isFile) {
    await accept(await entryFile(entry as FileSystemFileEntry), path, out)
  } else if (entry.isDirectory) {
    if (IGNORED_DIRS.has(entry.name)) return void out.skipped.push({ path: `${path}/`, reason: 'ignored-dir' })
    for (const child of await readAllEntries(entry as FileSystemDirectoryEntry)) await walk(child, out)
  }
}

/** Drag-and-drop of files and whole folders. */
export async function readDataTransfer(dt: DataTransfer): Promise<IntakeResult> {
  const entries = Array.from(dt.items)
    .map((item) => (item.kind === 'file' ? item.webkitGetAsEntry() : null))
    .filter((e): e is FileSystemEntry => e !== null)
  if (entries.length === 0) return readFileList(dt.files)
  const out: IntakeResult = { files: [], skipped: [] }
  for (const e of entries) await walk(e, out)
  return out
}

export function projectNameFrom(files: SourceFile[]): string {
  const first = files[0]?.path ?? 'untitled'
  const top = first.split(/[\\/]/)
  if (top.length > 1 && files.every((f) => f.path.startsWith(`${top[0]}/`))) return top[0]!
  return files.length === 1 ? top[top.length - 1]! : `${files.length} files`
}
