import { useEffect, useState } from 'react'
import { getBriefing, getLabs, getMetrics, setChaos, startScan } from './lib/api'
import { useRunStream } from './lib/useRunStream'

export default function App() {
  const [labs, setLabs] = useState<string[]>([])
  const [lab, setLab] = useState('')
  const [runId, setRunId] = useState<string | null>(null)
  const [chaos, setChaosRate] = useState(0)
  const [metrics, setMetrics] = useState<any>(null)
  const [briefing, setBriefing] = useState('')
  const [error, setError] = useState('')
  const { events, done } = useRunStream(runId)

  useEffect(() => {
    getLabs()
      .then((l) => { setLabs(l); if (l.length) setLab(l[0]) })
      .catch((e) => setError('Backend unreachable: ' + e.message))
  }, [])

  useEffect(() => {
    const t = setInterval(() => getMetrics().then(setMetrics).catch(() => {}), 3000)
    return () => clearInterval(t)
  }, [])

  const scan = async () => {
    setError(''); setBriefing('')
    try { setRunId((await startScan(lab)).run_id) }
    catch (e: any) { setError(e.message) }
  }

  const chaosTo = async (rate: number) => {
    try { await setChaos(rate); setChaosRate(rate) }
    catch (e: any) { setError(e.message) }
  }

  const voice = async () => {
    if (!runId) return
    try {
      const b = await getBriefing(runId)
      setBriefing(b.script)
      window.speechSynthesis.cancel()
      window.speechSynthesis.speak(new SpeechSynthesisUtterance(b.script))
    } catch (e: any) { setError(e.message) }
  }

  return (
    <div className="mx-auto max-w-6xl p-6 space-y-6">
      <h1 className="text-2xl font-bold">AegisMind AI</h1>

      <div className="flex flex-wrap items-center gap-3">
        <select className="rounded bg-slate-800 px-3 py-2" value={lab} onChange={(e) => setLab(e.target.value)}>
          {labs.map((l) => <option key={l}>{l}</option>)}
        </select>
        <button className="rounded bg-cyan-600 px-4 py-2 font-medium hover:bg-cyan-500" onClick={scan}>
          Scan
        </button>
        <button className="rounded bg-violet-600 px-4 py-2 font-medium hover:bg-violet-500 disabled:opacity-40"
                disabled={!runId || !done} onClick={voice}>
          Voice briefing
        </button>
        <div className="ml-auto flex items-center gap-2 text-sm">
          <span>Cloud failure:</span>
          {[0, 0.5, 1].map((r) => (
            <button key={r} onClick={() => chaosTo(r)}
                    className={`rounded px-3 py-1 ${chaos === r ? 'bg-red-600' : 'bg-slate-800'}`}>
              {r * 100}%
            </button>
          ))}
        </div>
      </div>

      {error && <div className="rounded bg-red-900/60 p-3 text-sm">{error}</div>}

      <div className="grid gap-6 md:grid-cols-3">
        <section className="md:col-span-2 space-y-2">
          <h2 className="font-semibold">
            Live trace {runId && <span className="text-slate-400 text-sm">({runId}{done ? ', finished' : ', running'})</span>}
          </h2>
          <div className="h-[28rem] overflow-auto rounded bg-slate-900 p-3 space-y-1 text-xs font-mono">
            {events.length === 0 && <div className="text-slate-500">No events yet. Press Scan.</div>}
            {events.map((ev) => (
              <pre key={ev.seq} className="whitespace-pre-wrap break-all">{JSON.stringify(ev)}</pre>
            ))}
          </div>
        </section>

        <section className="space-y-2">
          <h2 className="font-semibold">Gateway metrics</h2>
          <pre className="max-h-64 overflow-auto rounded bg-slate-900 p-3 text-xs">
            {metrics ? JSON.stringify(metrics, null, 2) : '...'}
          </pre>
          {briefing && (
            <>
              <h2 className="font-semibold">Briefing</h2>
              <p className="rounded bg-slate-900 p-3 text-sm">{briefing}</p>
            </>
          )}
        </section>
      </div>
    </div>
  )
}