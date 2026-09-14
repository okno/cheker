import { useCallback, useEffect, useState, type FormEvent } from 'react';
import {
  Activity,
  CheckCheck,
  ChevronDown,
  ChevronUp,
  Download,
  GitBranch,
  Info,
  LoaderCircle,
  RefreshCw,
  Save,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { Api, Notify } from './App';
import { dateTime, downloadJson, serialize, shortHash } from './api';
import type { AuditEvent, Monitor, Policy, Verification } from './types';
import { CardHeader, Empty, ErrorNotice, JsonView, label, Loading, PageHeading } from './ui';

export function AuditPage({ api }: { api: Api }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [busy, setBusy] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [type, setType] = useState('ALL');
  const [expanded, setExpanded] = useState<number | null>(null);
  const load = useCallback(async () => {
    setBusy(true);
    setError('');
    try {
      const [nextEvents, nextVerification] = await Promise.all([
        api<AuditEvent[]>('/audit'),
        api<Verification>('/audit/verify'),
      ]);
      setEvents(nextEvents);
      setVerification(nextVerification);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }, [api]);
  useEffect(() => {
    void load();
  }, [load]);
  async function verify() {
    setVerifying(true);
    setError('');
    try {
      setVerification(await api<Verification>('/audit/verify'));
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setVerifying(false);
    }
  }
  async function exportAudit() {
    setExporting(true);
    setError('');
    try {
      downloadJson(
        await api<unknown>('/audit/export'),
        `mcp-audit-${new Date().toISOString().slice(0, 10)}.json`,
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setExporting(false);
    }
  }
  const types = [...new Set(events.map((event) => event.event_type))].sort();
  const filtered = [...events]
    .sort((a, b) => b.sequence - a.sequence)
    .filter(
      (event) =>
        (type === 'ALL' || type === event.event_type) &&
        `${event.sequence} ${event.event_type} ${event.component_id} ${serialize(event.details)}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    );
  return (
    <>
      <PageHeading
        eyebrow="TRACCIABILITÀ VERIFICABILE"
        title="Registro audit"
        description="Ogni evento è collegato al precedente da un hash. Verifica la continuità del registro."
        action={
          <button className="button secondary" disabled={exporting} onClick={exportAudit}>
            {exporting ? <LoaderCircle size={17} className="spin" /> : <Download size={17} />}
            Esporta audit
          </button>
        }
      />
      <section className={`audit-integrity ${verification?.valid === false ? 'invalid' : ''}`}>
        <div className="audit-integrity-icon">
          {verification?.valid === false ? <ShieldAlert size={28} /> : <GitBranch size={28} />}
        </div>
        <div>
          <h2>
            {verification
              ? verification.valid
                ? 'La catena audit è integra'
                : 'Anomalia nella catena audit'
              : 'Verifica della catena'}
          </h2>
          <p>
            {verification
              ? verification.valid
                ? `${verification.checked} eventi verificati. Nessuna interruzione o modifica rilevata nella catena.`
                : verification.error || 'La verifica di integrità non è riuscita.'
              : 'La validità viene verificata dal backend sul registro persistente.'}
          </p>
          {verification?.head_hash && (
            <code title={verification.head_hash}>HEAD {shortHash(verification.head_hash)}</code>
          )}
        </div>
        <button className="button secondary" disabled={verifying || busy} onClick={verify}>
          {verifying ? <LoaderCircle size={16} className="spin" /> : <CheckCheck size={16} />}
          {verifying ? 'Verifica…' : 'Verifica integrità'}
        </button>
      </section>
      {error && <ErrorNotice message={error} retry={() => void load()} />}
      <section className="card">
        <div className="table-toolbar">
          <div className="input-icon search-input">
            <Search size={17} />
            <input
              aria-label="Cerca eventi audit"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Cerca un evento, un componente o un dettaglio…"
            />
          </div>
          <select
            aria-label="Filtra per tipo di evento"
            value={type}
            onChange={(e) => setType(e.target.value)}
          >
            <option value="ALL">Tutti gli eventi</option>
            {types.map((value) => (
              <option key={value} value={value}>
                {value.replaceAll('_', ' ')}
              </option>
            ))}
          </select>
          <button
            className="icon-button"
            disabled={busy}
            onClick={() => void load()}
            aria-label="Aggiorna audit"
          >
            <RefreshCw size={17} className={busy ? 'spin' : ''} />
          </button>
        </div>
        {busy && !events.length ? (
          <Loading />
        ) : filtered.length ? (
          <div className="audit-list">
            {filtered.map((event) => (
              <div
                className={`audit-row ${expanded === event.sequence ? 'expanded' : ''}`}
                key={event.sequence}
              >
                <button
                  className="audit-row-summary"
                  aria-expanded={expanded === event.sequence}
                  onClick={() => setExpanded(expanded === event.sequence ? null : event.sequence)}
                >
                  <span className="sequence">#{event.sequence}</span>
                  <span className="event-name">
                    <Activity size={15} />
                    <strong>{event.event_type.replaceAll('_', ' ')}</strong>
                  </span>
                  <code className="event-component">
                    {event.component_id ? shortHash(event.component_id) : 'Workspace'}
                  </code>
                  <time>{dateTime(event.timestamp)}</time>
                  {expanded === event.sequence ? (
                    <ChevronUp size={16} />
                  ) : (
                    <ChevronDown size={16} />
                  )}
                </button>
                {expanded === event.sequence && (
                  <div className="audit-details">
                    <div className="fingerprints">
                      <div>
                        <span>HASH PRECEDENTE</span>
                        <code>{event.previous_hash || 'Genesis'}</code>
                      </div>
                      <div>
                        <span>HASH EVENTO</span>
                        <code>{event.hash}</code>
                      </div>
                    </div>
                    <JsonView value={event.details} />
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <Empty
            icon={<GitBranch size={26} />}
            title={events.length ? 'Nessun evento corrispondente' : 'Nessun evento registrato'}
            text={
              events.length
                ? 'Modifica la ricerca o il filtro per vedere gli eventi.'
                : 'Le operazioni effettuate nel workspace alimentano questo registro.'
            }
          />
        )}
        <div className="table-footer">
          <span>
            {filtered.length} eventi visualizzati · ultimi {events.length} caricati
          </span>
          <span>Ordine: più recenti prima</span>
        </div>
      </section>
      <div className="notice info component-tip">
        <Info size={18} />
        <span>
          La verifica della catena rileva alterazioni nel registro disponibile. Proteggi
          separatamente il database, la chiave di firma e le copie esportate.
        </span>
      </div>
    </>
  );
}

const actions = ['ALLOW', 'WARN', 'REQUIRE_REAPPROVAL', 'QUARANTINE', 'BLOCK'];
const policyRows: {
  key: keyof Pick<
    Policy,
    'format_only_action' | 'semantic_change_action' | 'security_change_action' | 'unapproved_action'
  >;
  title: string;
  description: string;
  tag: string;
}[] = [
  {
    key: 'format_only_action',
    title: 'Modifica del solo formato',
    description:
      'Whitespace, ordine delle chiavi o rappresentazione: contenuto canonico invariato.',
    tag: 'FORMAT',
  },
  {
    key: 'semantic_change_action',
    title: 'Modifica semantica',
    description: 'Variazioni nel contenuto o nello schema del componente.',
    tag: 'SEMANTIC',
  },
  {
    key: 'security_change_action',
    title: 'Modifica rilevante per la sicurezza',
    description: 'Endpoint, comandi, argomenti, environment e capability.',
    tag: 'SECURITY',
  },
  {
    key: 'unapproved_action',
    title: 'Contenuto non approvato',
    description: 'Nuovi componenti che non dispongono di una baseline approvata.',
    tag: 'UNAPPROVED',
  },
];

export function PolicyPage({
  api,
  onChanged,
  notify,
}: {
  api: Api;
  onChanged: () => void;
  notify: Notify;
}) {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [saved, setSaved] = useState('');
  const [monitor, setMonitor] = useState<Monitor | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [monitorBusy, setMonitorBusy] = useState(false);
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [next, nextMonitor] = await Promise.all([
        api<Policy>('/policy'),
        api<Monitor>('/monitor'),
      ]);
      setPolicy(next);
      setSaved(JSON.stringify(next));
      setMonitor(nextMonitor);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setLoading(false);
    }
  }, [api]);
  useEffect(() => {
    void load();
  }, [load]);
  const dirty = !!policy && saved !== JSON.stringify(policy);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!policy) return;
    setError('');
    if (!(
      1 <= policy.scan_flag_score &&
      policy.scan_flag_score < policy.scan_quarantine_score &&
      policy.scan_quarantine_score < policy.scan_block_score &&
      policy.scan_block_score <= 100
    )) {
      setError('Le soglie devono rispettare: 1 ≤ segnalazione < quarantena < blocco ≤ 100.');
      return;
    }
    setSaving(true);
    try {
      const next = await api<Policy>('/policy', { method: 'PUT', body: JSON.stringify(policy) });
      setPolicy(next);
      setSaved(JSON.stringify(next));
      onChanged();
      notify(`Policy salvata: versione ${next.version}.`);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setSaving(false);
    }
  }
  async function toggleMonitor() {
    if (!monitor) return;
    setMonitorBusy(true);
    setError('');
    try {
      const next = await api<Monitor>('/monitor', {
        method: 'POST',
        body: JSON.stringify({ enabled: !monitor.running }),
      });
      setMonitor(next);
      onChanged();
      notify(
        next.running ? 'Monitor delle sorgenti attivato.' : 'Monitor delle sorgenti disattivato.',
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setMonitorBusy(false);
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="ENFORCEMENT E MONITORAGGIO"
        title="Policy e controlli"
        description="Definisci la risposta alle modifiche e le soglie di rischio dei documenti."
        action={
          policy && (
            <span className="policy-version">
              <Settings2 size={16} />
              Policy attiva <strong>v{policy.version}</strong>
            </span>
          )
        }
      />
      {error && <ErrorNotice message={error} retry={!policy ? () => void load() : undefined} />}
      {loading ? (
        <Loading />
      ) : (
        policy && (
          <div className="policy-layout">
            <form className="policy-form" onSubmit={save}>
              <section className="card">
                <CardHeader
                  title="Decisioni sulle modifiche"
                  subtitle="Le azioni vengono applicate dal gate di integrazione"
                />
                {policyRows.map((row) => (
                  <div className="policy-row" key={row.key}>
                    <div>
                      <span className="policy-tag">{row.tag}</span>
                      <label htmlFor={`policy-${row.key}`}>{row.title}</label>
                      <p>{row.description}</p>
                    </div>
                    <select
                      id={`policy-${row.key}`}
                      value={policy[row.key]}
                      onChange={(event) => setPolicy({ ...policy, [row.key]: event.target.value })}
                      disabled={saving}
                    >
                      {actions.map((action) => (
                        <option key={action} value={action}>
                          {label(action)}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}
              </section>
              <section className="card threshold-card">
                <CardHeader
                  title="Soglie del File Scanner"
                  subtitle="Punteggio di rischio da 0 a 100. Si applica l’azione più restrittiva raggiunta."
                />
                <div className="threshold-inputs">
                  {[
                    { key: 'scan_flag_score' as const, title: 'Segnalazione', color: 'blue' },
                    { key: 'scan_quarantine_score' as const, title: 'Quarantena', color: 'amber' },
                    { key: 'scan_block_score' as const, title: 'Blocco', color: 'red' },
                  ].map((item) => (
                    <label key={item.key} className={`threshold-input ${item.color}`}>
                      <span>
                        <i />
                        {item.title}
                      </span>
                      <div>
                        <input
                          type="number"
                          min={1}
                          max={100}
                          step={1}
                          required
                          value={policy[item.key]}
                          disabled={saving}
                          onChange={(event) =>
                            setPolicy({ ...policy, [item.key]: event.target.valueAsNumber })
                          }
                          aria-label={`Soglia ${item.title}`}
                        />
                        <small>/ 100</small>
                      </div>
                    </label>
                  ))}
                </div>
                <p className="threshold-note">
                  Segnalazione &lt; quarantena &lt; blocco. I limiti di estrazione possono imporre
                  un blocco indipendentemente dal punteggio.
                </p>
              </section>
              <div className="policy-save">
                <span>
                  {dirty ? 'Hai modifiche non salvate' : 'La configurazione è aggiornata'}
                </span>
                <div>
                  {dirty && (
                    <button
                      type="button"
                      className="button secondary"
                      disabled={saving}
                      onClick={() => setPolicy(JSON.parse(saved) as Policy)}
                    >
                      Annulla modifiche
                    </button>
                  )}
                  <button className="button primary" disabled={saving || !dirty}>
                    {saving ? <LoaderCircle size={17} className="spin" /> : <Save size={17} />}
                    {saving ? 'Salvataggio…' : 'Salva policy'}
                  </button>
                </div>
              </div>
            </form>
            <aside className="policy-side">
              <section className="card monitor-card">
                <CardHeader
                  title="Monitor delle sorgenti"
                  subtitle="Rilevamento delle modifiche locali"
                />
                <div className="monitor-control">
                  <div>
                    <Activity size={24} className={monitor?.running ? 'green' : 'muted'} />
                    <strong>{monitor?.running ? 'Monitor attivo' : 'Monitor inattivo'}</strong>
                    <span>
                      {monitor?.running
                        ? 'Le sorgenti registrate vengono osservate.'
                        : 'Attiva per osservare le sorgenti registrate.'}
                    </span>
                  </div>
                  <button
                    type="button"
                    className={`toggle ${monitor?.running ? 'checked' : ''}`}
                    role="switch"
                    aria-checked={!!monitor?.running}
                    aria-label="Monitor delle sorgenti"
                    disabled={monitorBusy || !monitor}
                    onClick={toggleMonitor}
                  >
                    <span />
                  </button>
                </div>
                {monitor?.paths?.length ? (
                  <div className="monitored-paths">
                    <h4>
                      {monitor.running ? 'Sorgenti osservate' : 'Sorgenti registrate'} ·{' '}
                      {monitor.paths.length}
                    </h4>
                    {monitor.paths.map((path, index) => (
                      <code key={`${path}-${index}`}>{path}</code>
                    ))}
                  </div>
                ) : (
                  <p className="padded muted">
                    Registra una sorgente dalla pagina Componenti MCP per popolare il monitor.
                  </p>
                )}
                {!!monitor?.errors?.length && (
                  <div className="padded">
                    <ErrorNotice
                      message={`Problemi del monitor: ${monitor.errors.map(serialize).join('; ')}`}
                    />
                  </div>
                )}
              </section>
              <section className="gate-explainer">
                <ShieldCheck size={26} />
                <h3>
                  Il gate prende la decisione.
                  <br />
                  Il client la applica.
                </h3>
                <p>
                  Integra il controllo prima di ogni utilizzo di un componente. La console non
                  intercetta le chiamate MCP in autonomia.
                </p>
                <code>POST /api/gate</code>
                <p>
                  La richiesta può vincolare ID, hash canonico e versione. Il backend rilegge la
                  sorgente prima della risposta.
                </p>
                <div className="notice info">
                  <Info size={17} />
                  <span>
                    La quarantena è logica. I file originali restano nella loro posizione.
                  </span>
                </div>
              </section>
            </aside>
          </div>
        )
      )}
    </>
  );
}
