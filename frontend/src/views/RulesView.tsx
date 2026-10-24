import { useState } from 'react'
import { CheckCircle2, FlaskConical, XCircle } from 'lucide-react'
import { RULE_META } from '@/lib/rules'
import { CATEGORIES, CATEGORY_LABEL } from '@/lib/severity'
import { runSelfTest, type SelfTestCase } from '@/lib/selfTest'
import { CategoryIcon, SeverityBadge } from '@/components/Severity'

export function RulesView({ disabled, setDisabled }: { disabled: string[]; setDisabled: (ids: string[]) => void }) {
  const [results, setResults] = useState<SelfTestCase[] | null>(null)
  const [ms, setMs] = useState(0)
  const enabledCount = RULE_META.length - disabled.length

  const run = () => {
    const t = performance.now()
    setResults(runSelfTest())
    setMs(Math.round(performance.now() - t))
  }
  const passed = results?.filter((r) => r.pass).length ?? 0

  return (
    <div className="mx-auto max-w-[1240px] px-[4vw] pt-14">
      <div className="grid gap-10 lg:grid-cols-[1fr_380px]">
        <div>
          <p className="eyebrow">Rules</p>
          <h1 className="mt-1 text-[clamp(38px,5vw,58px)] font-semibold">Exactly what it checks.</h1>
          <p className="mt-3 max-w-2xl text-[16px]">
            Every detector is a plain, deterministic rule: regexes, entropy maths and a few structural checks. No black box, no network.
            Turn a rule off and it’s skipped on the next scan. <strong className="text-strong">{enabledCount} of {RULE_META.length}</strong> are on.
          </p>
        </div>

        <aside className="card card-shadow self-start p-5" aria-labelledby="selftest-title">
          <div className="flex items-center gap-2">
            <FlaskConical size={18} className="text-denim" aria-hidden="true" />
            <h2 id="selftest-title" className="text-[20px]">Self-test</h2>
          </div>
          <p className="mt-1.5 text-[13.5px]">Scans the bundled demo project and asserts {'≈'}30 expected findings, category coverage and that nothing raw leaks into snippets.</p>
          <button type="button" className="btn btn-primary btn-sm mt-3" onClick={run}>Run self-test</button>
          {results && (
            <div className="mt-4" aria-live="polite">
              <p className={`font-display text-[22px] ${passed === results.length ? 'text-sage-ink' : 'text-coral-ink'}`}>{passed}/{results.length} passed <span className="font-mono text-[11px] text-muted">in {ms} ms</span></p>
              <ul className="mt-2 max-h-56 space-y-1 overflow-y-auto pr-1 font-mono text-[11.5px]">
                {results.map((r) => (
                  <li key={r.name} className="flex items-start gap-1.5">
                    {r.pass ? <CheckCircle2 size={13} className="mt-0.5 shrink-0 text-sage-ink" aria-label="pass" /> : <XCircle size={13} className="mt-0.5 shrink-0 text-coral-ink" aria-label="fail" />}
                    <span>{r.name} <span className="text-muted">({r.detail})</span></span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="mt-3 font-mono text-[10.5px] text-muted">Also from a terminal: npm run selftest</p>
        </aside>
      </div>

      {CATEGORIES.map((c) => {
        const rules = RULE_META.filter((r) => r.category === c)
        return (
          <section key={c} className="mt-12" aria-labelledby={`cat-${c}`}>
            <div className="mb-3 flex items-center gap-2.5">
              <span className="grid h-8 w-8 place-items-center rounded-full border-[1.5px] border-line bg-surface"><CategoryIcon category={c} size={15} /></span>
              <h2 id={`cat-${c}`} className="text-[26px]">{CATEGORY_LABEL[c]}</h2>
              <span className="mono-label">{rules.length} rules</span>
            </div>
            <ul className="card divide-y divide-[var(--color-rule)]">
              {rules.map((r) => {
                const on = !disabled.includes(r.id)
                return (
                  <li key={r.id} className={`grid items-center gap-x-5 gap-y-1.5 px-5 py-4 md:grid-cols-[80px_1fr_110px_52px] ${on ? '' : 'opacity-55'}`}>
                    <span className="font-mono text-[12px] font-semibold text-muted">{r.id}</span>
                    <div>
                      <p className="font-extrabold text-strong">{r.title}{r.generic && <span className="ml-2 font-mono text-[10.5px] font-medium text-muted">heuristic · yields to specific rules</span>}</p>
                      <p className="mt-0.5 text-[13.5px]">{r.description}</p>
                    </div>
                    <span><SeverityBadge severity={r.severity} /></span>
                    <button
                      type="button" role="switch" aria-checked={on} className="toggle justify-self-end"
                      aria-label={`${on ? 'Disable' : 'Enable'} ${r.title}`}
                      onClick={() => setDisabled(on ? [...disabled, r.id] : disabled.filter((x) => x !== r.id))}
                    />
                  </li>
                )
              })}
            </ul>
          </section>
        )
      })}
    </div>
  )
}
