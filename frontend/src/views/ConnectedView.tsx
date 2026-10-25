import { useEffect, useState } from 'react'
import { FolderGit2, ShieldCheck, Terminal } from 'lucide-react'
import { MonkeySwing, EmptyState } from '@/components/Brand'
import { getJson, MODE_LABEL, type Health, type PluginProject } from '@/lib/plugin'

/** Landing view when Claude Code enables ChaosMonkey: which project, privacy, what happens next. */
export function ConnectedView({ project }: { project: PluginProject | null | undefined }) {
  const [health, setHealth] = useState<Health | null>(null)

  useEffect(() => {
    getJson<Health>('/api/health').then(setHealth).catch(() => setHealth(null))
  }, [project?.project_path])

  if (project === undefined) {
    return <div className="mx-auto flex max-w-[1240px] justify-center px-[4vw] py-24"><MonkeySwing size={110} label="Connecting to ChaosMonkey" /></div>
  }

  if (!project?.connected || !project.project_path) {
    return (
      <div className="mx-auto max-w-[1240px] px-[4vw] py-24">
        <EmptyState
          title="No Claude Code project connected."
          body="Run /chaosmonkey:enable in Claude Code to connect a project. You can still scan code here directly."
          action={<a href="#/scan" className="btn btn-primary">Scan code here</a>}
        />
      </div>
    )
  }

  const privacyOk = health ? health.data_leaves_machine === false && health.privacy_ok : null
  const mode = MODE_LABEL[project.mode] ?? MODE_LABEL['detector-only']

  return (
    <div className="mx-auto max-w-[1100px] px-[4vw] pb-10 pt-12">
      <p className="eyebrow">Connected to Claude Code</p>
      <h1 className="mt-1 text-[clamp(34px,4.5vw,56px)] font-semibold tracking-[-0.03em]">Watching your project</h1>

      <section className="card card-shadow mt-8 grid gap-0 md:grid-cols-3" aria-label="Connection">
        <div className="border-b-2 border-line p-6 md:border-b-0 md:border-r-2">
          <p className="flex items-center gap-2 font-extrabold text-strong"><FolderGit2 size={16} aria-hidden="true" /> Project</p>
          <p className="mt-2 break-all font-mono text-[13px]">{project.project_path}</p>
        </div>
        <div className="border-b-2 border-line p-6 md:border-b-0 md:border-r-2">
          <p className="flex items-center gap-2 font-extrabold text-strong"><ShieldCheck size={16} aria-hidden="true" /> Privacy</p>
          <p className="mt-2 text-[14px]">
            {privacyOk === null ? 'Checking…' : privacyOk ? 'Local only. Nothing leaves this machine (data_leaves_machine = false).' : 'Privacy check failed: a non-local endpoint is configured.'}
          </p>
        </div>
        <div className="p-6">
          <p className="flex items-center gap-2 font-extrabold text-strong"><Terminal size={16} aria-hidden="true" /> Analysis mode</p>
          <p className="mt-2 text-[14px]"><strong>{mode.label}.</strong> {mode.detail}</p>
        </div>
      </section>

      <div className="mt-12 flex flex-col items-center text-center">
        <MonkeySwing size={110} label="Waiting for your code" />
        <p className="mt-4 font-display text-[24px] font-semibold text-strong">Waiting for your code to be generated.</p>
        <p className="mt-2 max-w-[56ch] text-[14.5px] text-muted">
          When Claude finishes changing the project it will ask whether to run a ChaosMonkey scan. Say yes and this tab jumps
          straight to the report, where you approve the fixes you want. Nothing is changed without your click.
        </p>
      </div>
    </div>
  )
}
