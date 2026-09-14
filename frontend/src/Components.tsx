import { useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import {
  ArrowRight,
  Ban,
  Boxes,
  Check,
  CheckCheck,
  Clock3,
  Download,
  FileJson2,
  Fingerprint,
  FolderSearch,
  GitCompareArrows,
  Hash,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { Api, Notify } from './App';
import { dateTime, downloadJson, serialize, shortHash } from './api';
import type { Component, Finding } from './types';
import { Badge, Empty, ErrorNotice, JsonView, label, Loading, Modal, PageHeading } from './ui';

export function ComponentsPage({
  api,
  components,
  busy,
  refresh,
  select,
  discoverOpen,
  setDiscoverOpen,
  notify,
}: {
  api: Api;
  components: Component[];
  busy: boolean;
  refresh: () => void;
  select: (component: Component) => void;
  discoverOpen: boolean;
  setDiscoverOpen: (open: boolean) => void;
  notify: Notify;
}) {
  const [search, setSearch] = useState('');
  const [state, setState] = useState('ALL');
  const [path, setPath] = useState('');
  const [discovering, setDiscovering] = useState(false);
  const [error, setError] = useState('');
  const filtered = components.filter(
    (component) =>
      (state === 'ALL' || state === component.state) &&
      `${component.name} ${component.kind} ${component.source_path} ${component.canonical_hash}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  async function discover(event: FormEvent) {
    event.preventDefault();
    setDiscovering(true);
    setError('');
    try {
      const found = await api<Component[]>('/components/discover', {
        method: 'POST',
        body: JSON.stringify({ path: path.trim() }),
      });
      setDiscoverOpen(false);
      setPath('');
      refresh();
      notify(`${found.length} componenti analizzati dalla sorgente.`);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setDiscovering(false);
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="CONTENT-ADDRESSED TRUST"
        title="Componenti MCP"
        description="La fiducia appartiene al contenuto approvato, a una versione precisa."
        action={
          <button
            className="button primary"
            onClick={() => {
              setError('');
              setDiscoverOpen(true);
            }}
          >
            <FolderSearch size={17} />
            Scopri componenti
          </button>
        }
      />
      <section className="card">
        <div className="table-toolbar">
          <div className="input-icon search-input">
            <Search size={17} />
            <input
              aria-label="Cerca componenti"
              placeholder="Cerca nome, percorso o fingerprint…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            aria-label="Filtra per stato"
            value={state}
            onChange={(e) => setState(e.target.value)}
          >
            <option value="ALL">Tutti gli stati</option>
            {[
              'APPROVED',
              'PENDING_APPROVAL',
              'REAPPROVAL_REQUIRED',
              'BLOCKED',
              'QUARANTINED',
              'REVOKED',
            ].map((value) => (
              <option key={value} value={value}>
                {label(value)}
              </option>
            ))}
          </select>
          <button
            className="icon-button"
            onClick={refresh}
            disabled={busy}
            aria-label="Aggiorna componenti"
          >
            <RefreshCw size={17} className={busy ? 'spin' : ''} />
          </button>
        </div>
        {busy && !components.length ? (
          <Loading />
        ) : filtered.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Componente</th>
                  <th>Stato</th>
                  <th>Versione</th>
                  <th>Hash canonico</th>
                  <th>Ultima verifica</th>
                  <th>
                    <span className="sr-only">Dettagli</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((component) => (
                  <tr key={component.id}>
                    <td>
                      <button className="component-cell" onClick={() => select(component)}>
                        <span className="component-icon">
                          <Boxes size={19} />
                        </span>
                        <span>
                          <strong>{component.name}</strong>
                          <small title={component.source_path}>
                            {component.kind} · {component.source_path}
                          </small>
                        </span>
                      </button>
                    </td>
                    <td>
                      <Badge state={component.state} />
                    </td>
                    <td>
                      <span className="version-tag">v{component.version}</span>
                    </td>
                    <td>
                      <code className="hash-short" title={component.canonical_hash}>
                        {shortHash(component.canonical_hash)}
                      </code>
                    </td>
                    <td className="muted nowrap">{dateTime(component.updated_at)}</td>
                    <td>
                      <button
                        className="icon-button"
                        onClick={() => select(component)}
                        aria-label={`Esamina ${component.name}`}
                      >
                        <ArrowRight size={17} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            icon={<Boxes size={28} />}
            title={
              components.length
                ? 'Nessun componente corrispondente'
                : 'La tua baseline comincia qui'
            }
            text={
              components.length
                ? 'Prova un altro termine o seleziona tutti gli stati.'
                : 'Importa un file di configurazione MCP. Il contenuto verrà analizzato senza eseguire comandi.'
            }
            action={
              !components.length ? (
                <button className="button secondary" onClick={() => setDiscoverOpen(true)}>
                  <FolderSearch size={16} />
                  Seleziona una sorgente
                </button>
              ) : undefined
            }
          />
        )}
        <div className="table-footer">
          <span>
            {filtered.length} di {components.length} componenti
          </span>
          <span>
            <LockKeyhole size={12} /> Approvazioni associate all’hash SHA-256
          </span>
        </div>
      </section>
      <div className="notice info component-tip">
        <Fingerprint size={18} />
        <span>
          Se un componente cambia dopo l’approvazione, il gate rivaluta il nuovo contenuto. Il nome
          e il percorso da soli non determinano la fiducia.
        </span>
      </div>
      {discoverOpen && (
        <Modal
          title="Scopri componenti"
          description="Analizza file e configurazioni presenti su questo dispositivo."
          onClose={() => {
            if (!discovering) setDiscoverOpen(false);
          }}
        >
          <form className="modal-form" onSubmit={discover}>
            <label htmlFor="discovery-path">Percorso del file di configurazione</label>
            <input
              id="discovery-path"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/srv/mcp/config.json"
              required
              maxLength={4096}
              autoFocus
            />
            <p className="field-help">
              Usa un percorso assoluto accessibile al backend. Sono supportati JSON, JSON5, YAML,
              TOML e file .env. I comandi descritti nei file non vengono eseguiti.
            </p>
            <div className="notice info">
              <ShieldCheck size={18} />
              <span>
                I componenti scoperti vengono normalizzati, analizzati e registrati prima
                dell’approvazione.
              </span>
            </div>
            {error && <ErrorNotice message={error} />}
            <div className="modal-actions">
              <button
                type="button"
                className="button secondary"
                disabled={discovering}
                onClick={() => setDiscoverOpen(false)}
              >
                Annulla
              </button>
              <button className="button primary" disabled={discovering || !path.trim()}>
                {discovering ? (
                  <LoaderCircle size={16} className="spin" />
                ) : (
                  <FolderSearch size={16} />
                )}
                {discovering ? 'Analisi in corso…' : 'Analizza sorgente'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

export function Findings({ findings }: { findings: Finding[] }) {
  return findings.length ? (
    <div className="findings-list">
      {findings.map((finding, index) => (
        <details
          className="finding"
          key={`${finding.rule_id}-${index}`}
          open={findings.length < 4 || undefined}
        >
          <summary>
            <Badge state={finding.severity} />
            <strong>{finding.title}</strong>
            <span className="finding-rule">{finding.rule_id}</span>
          </summary>
          <div className="finding-body">
            <div className="finding-meta">
              <span>{label(finding.category)}</span>
              <span>Layer: {finding.layer || '—'}</span>
              {finding.location != null && <span>Posizione: {serialize(finding.location)}</span>}
              {finding.line != null && <span>Riga {finding.line}</span>}
              {finding.encoding && <span>Encoding: {finding.encoding}</span>}
            </div>
            <pre>{serialize(finding.evidence)}</pre>
          </div>
        </details>
      ))}
    </div>
  ) : (
    <div className="notice success">
      <CheckCheck size={19} />
      <span>Nessuna evidenza rilevata dalle regole applicate.</span>
    </div>
  );
}

type Action = 'approve' | 'revoke' | 'quarantine';
type GateDecision = {
  allowed: boolean;
  action: string;
  reason: string;
  component_id: string;
  canonical_hash: string;
  version: number;
};

// Poll timestamps alone do not change the content or trust being reviewed.
function reviewContext(component: Component, policyVersion?: number): string {
  const { updated_at: _updatedAt, ...context } = component;
  return JSON.stringify([context, policyVersion]);
}

export function ComponentDetail({
  component,
  policyVersion,
  api,
  onChanged,
  onClose,
  notify,
}: {
  component: Component;
  policyVersion?: number;
  api: Api;
  onChanged: (component?: Component) => void;
  onClose: () => void;
  notify: Notify;
}) {
  const [current, setCurrent] = useState(component);
  const [tab, setTab] = useState('summary');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [action, setAction] = useState<Action | null>(null);
  const [approver, setApprover] = useState('');
  const [note, setNote] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [history, setHistory] = useState<unknown[] | null>(null);
  const [gate, setGate] = useState<GateDecision | null>(null);
  const [approval, setApproval] = useState<unknown | null>(null);
  const [changedNotice, setChangedNotice] = useState(false);
  const context = useRef(reviewContext(component, policyVersion));
  const requestRevision = useRef(0);

  function acceptCurrent(next: Component, announce = false) {
    const nextContext = reviewContext(next, policyVersion);
    if (nextContext !== context.current) {
      context.current = nextContext;
      requestRevision.current++;
      setBusy(false);
      setGate(null);
      setHistory(null);
      setApproval(null);
      setAction(null);
      setApprover('');
      setNote('');
      setAcknowledged(false);
      setError('');
      setTab('summary');
      setChangedNotice(announce);
    }
    setCurrent(next);
  }

  useLayoutEffect(() => {
    acceptCurrent(component, true);
  }, [component, policyVersion]);
  useLayoutEffect(
    () => () => {
      requestRevision.current++;
    },
    [],
  );

  const endpoint = `/components/${encodeURIComponent(current.id)}`;
  async function refresh() {
    const revision = ++requestRevision.current;
    setBusy(true);
    setError('');
    try {
      const next = await api<Component>(`${endpoint}/refresh`, { method: 'POST' });
      if (revision !== requestRevision.current) return;
      acceptCurrent(next);
      setGate(null);
      setHistory(null);
      setApproval(null);
      onChanged(next);
      notify('Contenuto riletto e integrità rivalutata.');
    } catch (error) {
      if (revision === requestRevision.current) setError((error as Error).message);
    } finally {
      if (revision === requestRevision.current) setBusy(false);
    }
  }
  async function loadTab(next: string) {
    const revision = ++requestRevision.current;
    setTab(next);
    setError('');
    if (next !== 'history' && next !== 'approval') return;
    setBusy(true);
    try {
      const result = await api<unknown>(
        `${endpoint}/${next === 'history' ? 'history' : 'approval'}`,
      );
      if (revision !== requestRevision.current) return;
      if (next === 'history') setHistory(result as unknown[]);
      else setApproval(result);
    } catch (error) {
      if (revision === requestRevision.current) setError((error as Error).message);
    } finally {
      if (revision === requestRevision.current) setBusy(false);
    }
  }
  function startAction(next: Action) {
    setChangedNotice(false);
    setAction(next);
    setNote('');
    setAcknowledged(false);
    setError('');
  }
  async function submitAction(event: FormEvent) {
    event.preventDefault();
    if (!action) return;
    if (action === 'approve' && current.snapshot_valid !== true) {
      setError('Approvazione bloccata: l’integrità della copia registrata non è verificabile.');
      return;
    }
    const revision = ++requestRevision.current;
    setBusy(true);
    setError('');
    const payload =
      action === 'approve'
        ? {
            canonical_hash: current.canonical_hash,
            version: current.version,
            approver: approver.trim(),
            note: note.trim(),
          }
        : { reason: note.trim() };
    try {
      const next = await api<Component>(`${endpoint}/${action}`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      if (revision !== requestRevision.current) return;
      acceptCurrent(next);
      setAction(null);
      setHistory(null);
      setApproval(null);
      setGate(null);
      onChanged(next);
      notify(
        action === 'approve'
          ? `Versione ${next.version} approvata e firmata.`
          : action === 'quarantine'
            ? 'Componente messo in quarantena logica.'
            : 'Approvazione revocata.',
      );
    } catch (error) {
      if (revision === requestRevision.current) setError((error as Error).message);
    } finally {
      if (revision === requestRevision.current) setBusy(false);
    }
  }
  async function checkGate() {
    const revision = ++requestRevision.current;
    setBusy(true);
    setError('');
    setGate(null);
    try {
      const decision = await api<GateDecision>('/gate', {
        method: 'POST',
        body: JSON.stringify({
          component_id: current.id,
          canonical_hash: current.canonical_hash,
          version: current.version,
        }),
      });
      if (revision !== requestRevision.current) return;
      const next = await api<Component>(endpoint);
      if (revision !== requestRevision.current) return;
      acceptCurrent(next);
      if (
        decision.component_id === next.id &&
        decision.version === next.version &&
        decision.canonical_hash === next.canonical_hash &&
        (!decision.allowed || next.state === 'APPROVED')
      ) {
        setGate(decision);
      }
      setHistory(null);
      setApproval(null);
      onChanged(next);
    } catch (error) {
      if (revision === requestRevision.current) setError((error as Error).message);
    } finally {
      if (revision === requestRevision.current) setBusy(false);
    }
  }
  return (
    <Modal
      title={current.name}
      description={`${current.kind} · ${current.source_path}`}
      onClose={() => {
        if (!busy) onClose();
      }}
      wide
    >
      <div className="detail-overview">
        <div className="detail-status">
          <Badge state={current.state} />
          <span className="version-tag">Versione {current.version}</span>
          <span className="muted">{current.severity && <Badge state={current.severity} />}</span>
        </div>
        <div className="detail-action-row">
          <button
            className="button primary small"
            disabled={
              busy || !!action || current.state === 'APPROVED' || current.snapshot_valid !== true
            }
            onClick={() => startAction('approve')}
          >
            <ShieldCheck size={16} />
            Approva versione
          </button>
          <button className="button secondary small" disabled={busy || !!action} onClick={refresh}>
            <RefreshCw size={15} className={busy ? 'spin' : ''} />
            Rileggi sorgente
          </button>
          <button
            className="button secondary small"
            disabled={busy || !!action}
            onClick={() => startAction('quarantine')}
          >
            <ShieldAlert size={16} />
            Quarantena
          </button>
          <button
            className="button ghost-danger small"
            disabled={busy || !!action}
            onClick={() => startAction('revoke')}
          >
            <Ban size={15} />
            Revoca
          </button>
        </div>
      </div>
      {changedNotice && (
        <div className="notice info" role="status">
          <RefreshCw size={17} />
          <span>
            Contenuto o stato di fiducia aggiornati. Le conferme e le verifiche precedenti sono
            state azzerate: esamina la versione corrente.
          </span>
        </div>
      )}
      {current.snapshot_valid === false && (
        <ErrorNotice message="L’integrità della copia registrata non è verificabile. L’uso e l’approvazione sono bloccati; le evidenze originali sono conservate." />
      )}
      {action ? (
        <form className="approval-panel" onSubmit={submitAction}>
          <div className="approval-title">
            <div>
              <h3>
                {action === 'approve'
                  ? 'Approva questo contenuto'
                  : action === 'quarantine'
                    ? 'Quarantena del componente'
                    : 'Revoca la fiducia'}
              </h3>
              <p>
                {action === 'approve'
                  ? 'L’approvazione è vincolata alla versione e alla fingerprint mostrate qui.'
                  : action === 'quarantine'
                    ? 'Quarantena logica: il gate nega l’uso. Il file originale non viene spostato o modificato.'
                    : 'Il gate negherà l’uso del componente finché non verrà nuovamente approvato.'}
              </p>
            </div>
            <button
              type="button"
              className="icon-button"
              disabled={busy}
              onClick={() => setAction(null)}
              aria-label="Annulla azione"
            >
              <X size={18} />
            </button>
          </div>
          <label>Versione {current.version} · SHA-256 canonico</label>
          <code className="hash-full">{current.canonical_hash}</code>
          {action === 'approve' && (
            <>
              <label htmlFor="approver">Nome dell’approvatore</label>
              <input
                id="approver"
                value={approver}
                onChange={(e) => setApprover(e.target.value)}
                placeholder="Nome e cognome"
                required
                maxLength={120}
                autoFocus
              />
            </>
          )}
          <label htmlFor="action-note">
            {action === 'approve' ? 'Nota di approvazione (facoltativa)' : 'Motivo'}
          </label>
          <textarea
            id="action-note"
            rows={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            required={action !== 'approve'}
            maxLength={2000}
          />
          {action === 'approve' && (
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
                required
              />
              <span>
                Ho esaminato contenuto, variazioni ed evidenze e approvo questa precisa versione.
              </span>
            </label>
          )}
          {error && <ErrorNotice message={error} />}
          <div className="modal-actions">
            <button
              type="button"
              className="button secondary"
              disabled={busy}
              onClick={() => setAction(null)}
            >
              Annulla
            </button>
            <button
              className={`button ${action === 'approve' ? 'primary' : 'danger'}`}
              disabled={
                busy ||
                (action === 'approve' &&
                  (!acknowledged || !approver.trim() || current.snapshot_valid !== true)) ||
                (action !== 'approve' && !note.trim())
              }
            >
              {busy ? <LoaderCircle size={17} className="spin" /> : <Check size={17} />}
              {action === 'approve'
                ? 'Firma e approva'
                : action === 'quarantine'
                  ? 'Conferma quarantena'
                  : 'Conferma revoca'}
            </button>
          </div>
        </form>
      ) : (
        <>
          <div className="tabs" role="tablist" aria-label="Dettagli del componente">
            {[
              { key: 'summary', name: 'Integrità', icon: Fingerprint },
              {
                key: 'changes',
                name: `Variazioni (${current.changes?.length || 0})`,
                icon: GitCompareArrows,
              },
              { key: 'content', name: 'Contenuto', icon: FileJson2 },
              { key: 'history', name: 'Versioni', icon: Clock3 },
              { key: 'approval', name: 'Firma', icon: LockKeyhole },
            ].map((item) => (
              <button
                key={item.key}
                role="tab"
                aria-selected={tab === item.key}
                className={tab === item.key ? 'selected' : ''}
                onClick={() => void loadTab(item.key)}
                disabled={busy}
              >
                <item.icon size={15} />
                {item.name}
              </button>
            ))}
          </div>
          <div className="detail-tab-content" role="tabpanel">
            {error && <ErrorNotice message={error} />}
            {tab === 'summary' && (
              <>
                <div className="fingerprints">
                  <div>
                    <span>
                      <Hash size={14} />
                      RAW SHA-256
                    </span>
                    <code>{current.raw_hash}</code>
                  </div>
                  <div>
                    <span>
                      <Fingerprint size={14} />
                      CANONICAL SHA-256
                    </span>
                    <code>{current.canonical_hash}</code>
                  </div>
                  <div>
                    <span>
                      <GitCompareArrows size={14} />
                      SEMANTIC FINGERPRINT
                    </span>
                    <code>{current.semantic_fingerprint}</code>
                  </div>
                </div>
                <div className="detail-facts">
                  <div>
                    <span>Approvato da</span>
                    <strong>{current.approved_by || 'Non approvato'}</strong>
                  </div>
                  <div>
                    <span>Data approvazione</span>
                    <strong>{dateTime(current.approved_at)}</strong>
                  </div>
                  <div>
                    <span>Versione precedente</span>
                    <strong>
                      {current.previous_version == null ? '—' : `v${current.previous_version}`}
                    </strong>
                  </div>
                  <div>
                    <span>Azione della policy</span>
                    <strong>{label(current.action || '—')}</strong>
                  </div>
                </div>
                <h3 className="section-title">Evidenze di sicurezza</h3>
                <Findings findings={current.findings || []} />
                <div className="gate-check">
                  <div>
                    <h3>Verifica prima dell’uso</h3>
                    <p>
                      Il gate rilegge il file e valuta questa versione. La verifica non esegue il
                      componente.
                    </p>
                  </div>
                  <button className="button secondary small" disabled={busy} onClick={checkGate}>
                    <ShieldCheck size={16} />
                    Interroga gate
                  </button>
                </div>
                {gate && (
                  <div className={`notice ${gate.allowed ? 'success' : 'error'}`} role="status">
                    <ShieldCheck size={20} />
                    <div>
                      <strong>
                        {gate.allowed ? 'Uso consentito dal gate' : 'Uso negato dal gate'} ·{' '}
                        {label(gate.action)}
                      </strong>
                      <p>{gate.reason}</p>
                      <small>
                        Versione {gate.version} · {shortHash(gate.canonical_hash)}
                      </small>
                    </div>
                  </div>
                )}
              </>
            )}
            {tab === 'changes' &&
              (current.changes?.length ? (
                <div className="changes-list">
                  {current.changes.map((change, index) => (
                    <div className="change-card" key={`${change.path}-${index}`}>
                      <div className="change-head">
                        <code>{change.path || '/'}</code>
                        <Badge state={change.severity} />
                      </div>
                      <small>{label(change.category)}</small>
                      <div className="diff-columns">
                        <div className="diff-old">
                          <span>PRIMA</span>
                          <pre>{serialize(change.old)}</pre>
                        </div>
                        <div className="diff-new">
                          <span>DOPO</span>
                          <pre>{serialize(change.new)}</pre>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty
                  icon={<GitCompareArrows size={25} />}
                  title="Nessuna variazione registrata"
                  text="Le differenze tra versioni vengono mostrate con percorso, valore precedente e nuovo valore."
                />
              ))}
            {tab === 'content' && (
              <>
                <div className="notice info">
                  <LockKeyhole size={17} />
                  <span>
                    Contenuto visualizzato con i segreti oscurati dal backend. Le fingerprint si
                    riferiscono al contenuto originale.
                  </span>
                </div>
                <JsonView value={current.content} />
              </>
            )}
            {tab === 'history' &&
              (busy ? (
                <Loading />
              ) : history ? (
                <>
                  <p className="muted">
                    {history.length} versioni registrate. Snapshot restituiti dal registro
                    persistente.
                  </p>
                  <JsonView value={history} />
                </>
              ) : null)}
            {tab === 'approval' &&
              (busy ? (
                <Loading />
              ) : approval ? (
                <>
                  <div className="approval-export">
                    <p className="muted">Approvazione firmata Ed25519 restituita dal backend.</p>
                    <button
                      className="button secondary small"
                      onClick={() =>
                        downloadJson(approval, `approval-${current.id}-v${current.version}.json`)
                      }
                    >
                      <Download size={15} />
                      Esporta firma
                    </button>
                  </div>
                  <JsonView value={approval} />
                </>
              ) : (
                !error && (
                  <Empty
                    title="Nessuna approvazione disponibile"
                    text="Approva una versione per creare una firma associata al suo contenuto."
                  />
                )
              ))}
          </div>
        </>
      )}
    </Modal>
  );
}
