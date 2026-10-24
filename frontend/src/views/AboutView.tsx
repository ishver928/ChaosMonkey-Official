import { useState } from 'react'
import { Ban, Check, HardDrive, ShieldCheck } from 'lucide-react'
import { storageSnapshot } from '@/lib/storage'
import { CableDivider, Logo } from '@/components/Brand'
import { useBlockedCount } from '@/components/LocalStatus'

const NEVER = [
  ['Your code', 'Files are read with the browser’s File API and kept in memory. Closing the tab forgets them.'],
  ['Raw secrets and personal data', 'Masked before they reach the screen. “Reveal” holds a value in memory for 20 seconds; it is never written to storage or exports.'],
  ['Scan results', 'History keeps names, counts and masked snippets in localStorage on this device. There is no account and no sync.'],
  ['Analytics', 'None. No telemetry, error reporting, CDNs, web fonts or remote images. Fonts and icons ship inside the app.'],
] as const

const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' http://127.0.0.1:11434 http://localhost:11434; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'"

// A reserved .invalid hostname (RFC 2606) that can never resolve, used only to demonstrate the guard.
const PHONE_HOME = 'https://telemetry.chaosmonkey.invalid/collect'

export function AboutView() {
  const blocked = useBlockedCount()
  const [tested, setTested] = useState<'idle' | 'blocked' | 'leaked'>('idle')
  const snapshot = storageSnapshot()

  const tryPhoneHome = async () => {
    try {
      await fetch(PHONE_HOME, { method: 'POST', body: 'hello?' })
      setTested('leaked')
    } catch {
      setTested('blocked')
    }
  }

  return (
    <div className="mx-auto max-w-[1180px] px-[4vw] pt-14">
      <div className="grid items-center gap-10 lg:grid-cols-[1.3fr_.7fr]">
        <div>
          <p className="eyebrow">About & privacy</p>
          <h1 className="mt-1 text-[clamp(38px,5vw,62px)] font-semibold">Your code never leaves your machine.</h1>
          <p className="mt-4 max-w-2xl text-[17px] leading-relaxed">
            ChaosMonkey is a static site. Once the page loads there is nothing to talk to: no backend, no API keys, no cloud AI.
            A security tool that uploads your secrets to find your secrets would be a funny kind of chaos.
          </p>
        </div>
        <div className="card card-shadow p-6 text-center" aria-live="polite">
          <p className="eyebrow">Outbound requests blocked</p>
          <p className="mt-2 font-display text-[88px] font-semibold leading-none text-strong">{blocked}</p>
          <p className="mt-2 text-[13.5px]">{blocked === 0 ? 'Nothing has even tried to leave this tab.' : 'Each one was stopped before it left the browser.'}</p>
          <button type="button" className="btn btn-sm btn-quiet mt-4" onClick={tryPhoneHome}>Try to phone home</button>
          {tested === 'blocked' && <p className="mt-2 flex items-center justify-center gap-1 text-[12.5px] font-bold text-sage-ink"><Check size={14} aria-hidden="true" /> Blocked by the offline guard.</p>}
          {tested === 'leaked' && <p className="mt-2 text-[12.5px] font-bold text-coral-ink">That request went out. Please report this.</p>}
        </div>
      </div>

      <CableDivider className="my-12" knot={0.45} />

      <section className="grid gap-10 lg:grid-cols-[.8fr_1.2fr]">
        <div>
          <p className="eyebrow">How it works</p>
          <h2 className="mt-1 text-[38px]">Inspect, explain, fix.</h2>
        </div>
        <ol className="grid gap-6 md:grid-cols-3">
          {[
            ['01', 'Inspect', 'Your files go to a Web Worker that runs every enabled rule: provider key formats, Shannon entropy, Luhn checks, and structural checks for cookies, hashing and storage.'],
            ['02', 'Explain', 'Each finding gets a plain-English attack story from the built-in analyst, or from a local Ollama model if you have one. Either way, only masked code is used.'],
            ['03', 'Fix', 'A before/after patch generated from templates: env vars, bcrypt, HttpOnly cookies, redacted logs. Copy it, or export the whole report as Markdown, JSON or HTML.'],
          ].map(([n, t, d]) => (
            <li key={n}>
              <span className="grid h-7 w-9 place-items-center rounded-full border border-line bg-banana font-mono text-[11px] font-semibold text-on-accent">{n}</span>
              <h3 className="mt-3 text-[22px]">{t}</h3>
              <p className="mt-1.5 text-[14.5px]">{d}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="mt-16 border-y-2 border-line bg-butter px-6 py-12 md:px-10">
        <div className="grid gap-10 lg:grid-cols-[.8fr_1.2fr]">
          <div>
            <p className="eyebrow !text-strong">What never leaves this device</p>
            <h2 className="mt-1 text-[38px]">The short list is: everything.</h2>
          </div>
          <ul>
            {NEVER.map(([t, d]) => (
              <li key={t} className="grid grid-cols-[38px_1fr] gap-4 border-t border-[rgba(89,66,55,.45)] py-4 last:border-b">
                <span className="grid h-8 w-8 place-items-center rounded-full border border-line bg-surface text-strong"><Ban size={15} aria-hidden="true" /></span>
                <p className="text-[#594237]"><strong className="block font-display text-[18px] text-[#38291F]">{t}</strong>{d}</p>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="mt-16 grid gap-8 lg:grid-cols-2">
        <div className="card p-6">
          <div className="flex items-center gap-2"><ShieldCheck size={18} className="text-denim" aria-hidden="true" /><h2 className="text-[22px]">Four layers of “no”</h2></div>
          <ol className="prose-steps mt-4 space-y-3 text-[14px]">
            <li><strong className="text-strong">Offline guard.</strong> Loaded before anything else. It wraps fetch, XHR, sendBeacon, WebSocket and EventSource, and refuses any host that isn’t this origin or localhost.</li>
            <li><strong className="text-strong">Content-Security-Policy.</strong> Production builds ship a strict CSP, so the browser itself blocks other origins.</li>
            <li><strong className="text-strong">No external assets.</strong> Fonts, icons and images are bundled. The source is checked for external URLs before release.</li>
            <li><strong className="text-strong">Masked storage.</strong> Everything persisted goes through a scrubber that blanks anything still shaped like a credential.</li>
          </ol>
          <p className="mt-4 mono-label">CSP (production)</p>
          <pre className="code mt-1 whitespace-pre-wrap break-all rounded-md border border-[var(--color-rule)] p-3 text-[11px]">{CSP}</pre>
        </div>
        <div className="card p-6">
          <div className="flex items-center gap-2"><HardDrive size={18} className="text-denim" aria-hidden="true" /><h2 className="text-[22px]">What’s in localStorage right now</h2></div>
          <table className="mt-4 w-full text-left font-mono text-[12.5px]">
            <thead><tr className="border-b border-line"><th className="py-1.5 font-semibold">key</th><th className="py-1.5 text-right font-semibold">size</th></tr></thead>
            <tbody>
              {snapshot.map((s) => (
                <tr key={s.key} className="border-b border-[var(--color-rule)]"><td className="py-1.5">{s.key}</td><td className="py-1.5 text-right">{s.bytes ? `${(s.bytes / 1024).toFixed(1)} KB` : 'empty'}</td></tr>
              ))}
            </tbody>
          </table>
          <p className="mt-4 text-[13.5px]">Check it yourself: DevTools → Application → Local Storage. You’ll find masked snippets like <code className="masked font-mono text-[12px]">sk_live_••••••••a91f</code> and no file contents.</p>
          <div className="mt-6 flex items-center gap-3 rounded-md bg-bg p-4">
            <Logo size={48} alt="" className="border-2 border-line" />
            <p className="text-[13.5px]">Built at Cal Hacks 13.0. The badge is the event’s art; the monkey is doing its best.</p>
          </div>
        </div>
      </section>
    </div>
  )
}
