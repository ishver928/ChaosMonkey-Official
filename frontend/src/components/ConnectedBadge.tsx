import { Link2 } from 'lucide-react'
import { basename, type PluginProject } from '@/lib/plugin'

/** Small header badge shown only while a project is connected from Claude Code. */
export function ConnectedBadge({ project }: { project: PluginProject | null | undefined }) {
  if (!project?.connected || !project.project_path) return null
  return (
    <a
      href="#/connected"
      className="inline-flex items-center gap-1.5 rounded-full border-[1.5px] border-denim bg-surface px-3 py-1 text-[12px] font-bold text-denim no-underline hover:bg-powder"
      title={`Connected to Claude Code: ${project.project_path}`}
    >
      <Link2 size={13} aria-hidden="true" />
      <span>Connected project · {basename(project.project_path)}</span>
    </a>
  )
}
