import { useCallback, useEffect, useRef, useState, type DragEvent, type FormEvent } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCheck,
  CircleAlert,
  CircleX,
  Download,
  File,
  FileCheck2,
  FileQuestion,
  FileSearch,
  FileWarning,
  FolderOpen,
  Hash,
  Info,
  ListFilter,
  LoaderCircle,
  RefreshCw,
  ScanLine,
  Search,
  ShieldAlert,
  ShieldCheck,
  Square,
  Upload,
} from 'lucide-react';
import type { Api, Notify } from './App';
import { dateTime, downloadJson, shortHash } from './api';
import type { ScanReport, ScanStats, Verdict } from './types';
import { Badge, CardHeader, Empty, ErrorNotice, Loading, PageHeading, label, tone } from './ui';
import { Findings } from './Components';
import { FileWatchers } from './FileWatchers';
import { Sanitizations } from './Sanitizations';

const PAGE_SIZE = 25;
const verdicts: Verdict[] = ['VALID', 'INFECTED', 'CORRUPTED', 'REVIEW_REQUIRED', 'UNSCANNABLE'];
type BatchState = 'QUEUED' | 'SCANNING' | 'DONE' | 'ERROR' | 'SKIPPED';
type BatchItem = {
  id: number;
  filename: string;
  state: BatchState;
  verdict?: Verdict;
  error?: string;
  report?: ScanReport;
};

export function ScannerPage({
  api,
  onChanged,
  notify,
}: {
  api: Api;
  onChanged: () => void;
  notify: Notify;
}) {
  const [report, setReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<ScanReport[]>([]);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [historyError, setHistoryError] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [opening, setOpening] = useState(false);
  const [path, setPath] = useState('');
  const [dragging, setDragging] = useState(false);
  const [mode, setMode] = useState('upload');
  const [batch, setBatch] = useState<BatchItem[]>([]);
  const [stopRequested, setStopRequested] = useState(false);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [verdict, setVerdict] = useState('ALL');
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const activeRun = useRef(false);
  const cancelRun = useRef(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const reportAnchor = useRef<HTMLDivElement>(null);
  const registryAnchor = useRef<HTMLElement>(null);
  const completed = batch.filter((item) => item.state === 'DONE' || item.state === 'ERROR').length;
  const succeeded = batch.filter((item) => item.state === 'DONE').length;
  const failed = batch.filter((item) => item.state === 'ERROR').length;
  const skipped = batch.filter((item) => item.state === 'SKIPPED').length;

  useEffect(
    () => () => {
      cancelRun.current = true;
    },
    [],
  );

  useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search.trim());
      setOffset(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    let stale = false;
    setLoadingHistory(true);
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      offset: String(offset),
      verdict,
      query,
    });
    void Promise.all([
      api<ScanReport[]>(`/scans?${params}`),
      api<ScanStats>(`/scan/stats?${new URLSearchParams({ verdict, query })}`),
    ])
      .then(([reports, nextStats]) => {
        if (!stale) {
          setHistory(reports);
          setStats(nextStats);
          setHistoryError('');
        }
      })
      .catch((error) => {
        if (!stale) setHistoryError((error as Error).message);
      })
      .finally(() => {
        if (!stale) setLoadingHistory(false);
      });
    return () => {
      stale = true;
    };
  }, [api, offset, verdict, query, revision]);

  const reloadRegistry = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    const refreshVisible = () => {
      if (!document.hidden && !activeRun.current) reloadRegistry();
    };
    const timer = setInterval(refreshVisible, 15000);
    document.addEventListener('visibilitychange', refreshVisible);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', refreshVisible);
    };
  }, [reloadRegistry]);

  async function scanFiles(files: File[]) {
    if (activeRun.current || !files.length) return;
    activeRun.current = true;
    cancelRun.current = false;
    setStopRequested(false);
    setBusy(true);
    setError('');
    setReport(null);
    setBatch(files.map((file, index) => ({ id: index, filename: file.name, state: 'QUEUED' })));
    let stored = 0;
    const update = (id: number, patch: Partial<BatchItem>) =>
      setBatch((items) => items.map((item) => (item.id === id ? { ...item, ...patch } : item)));
    try {
      for (let index = 0; index < files.length; index++) {
        if (cancelRun.current) {
          setBatch((items) =>
            items.map((item) => (item.state === 'QUEUED' ? { ...item, state: 'SKIPPED' } : item)),
          );
          break;
        }
        const file = files[index];
        update(index, { state: 'SCANNING' });
        try {
          if (file.size > 10 * 1024 * 1024)
            throw new Error('Il file supera il limite di 10 MiB e non è stato inviato al backend.');
          const form = new FormData();
          form.append('file', file);
          const result = await api<ScanReport>('/scan', { method: 'POST', body: form });
          setReport(result);
          update(index, { state: 'DONE', verdict: result.verdict, report: result });
          stored++;
          reloadRegistry();
        } catch (error) {
          update(index, { state: 'ERROR', error: (error as Error).message });
        }
      }
      onChanged();
      notify(
        `${stored} ${stored === 1 ? 'report salvato' : 'report salvati'} su ${files.length} file selezionati${cancelRun.current ? '. Coda interrotta.' : '.'}`,
      );
    } finally {
      activeRun.current = false;
      setBusy(false);
      if (fileInput.current) fileInput.current.value = '';
    }
  }

  async function scanPath(event: FormEvent) {
    event.preventDefault();
    if (activeRun.current) return;
    activeRun.current = true;
    setBusy(true);
    setError('');
    setReport(null);
    setBatch([]);
    try {
      const result = await api<ScanReport>('/scan/path', {
        method: 'POST',
        body: JSON.stringify({ path: path.trim() }),
      });
      setReport(result);
      reloadRegistry();
      onChanged();
      notify(`Scansione completata: ${result.filename}`);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
      activeRun.current = false;
    }
  }

  function drop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    if (!busy) void scanFiles([...event.dataTransfer.files]);
  }

  async function openReport(id: string) {
    setOpening(true);
    setError('');
    try {
      setReport(await api<ScanReport>(`/scans/${encodeURIComponent(id)}`));
      setTimeout(
        () => reportAnchor.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
        30,
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setOpening(false);
    }
  }

  function filterBy(next: string) {
    setVerdict(next);
    setOffset(0);
  }
  const knownTotal = stats?.matched ?? null;
  const hasNext =
    knownTotal === null ? history.length === PAGE_SIZE : offset + PAGE_SIZE < knownTotal;

  return (
    <>
      <PageHeading
        eyebrow="DOCUMENT SECURITY"
        title="File Scanner"
        description="Tutti i file elaborati, i risultati dei controlli e le evidenze da esaminare prima dell’uso."
        action={
          <button className="button secondary" onClick={reloadRegistry} disabled={loadingHistory}>
            <RefreshCw size={16} className={loadingHistory ? 'spin' : ''} />
            Aggiorna registro
          </button>
        }
      />
      <ScanMetrics stats={stats} selected={verdict} onFilter={filterBy} />
      <div className="scanner-layout">
        <div className="scanner-main">
          <section className="card upload-card">
            <CardHeader
              title="Analizza i tuoi documenti"
              subtitle="Un file o un’intera selezione, con elaborazione locale sequenziale"
            />
            <div className="segmented-control" aria-label="Origine dei file">
              <button
                aria-pressed={mode === 'upload'}
                className={mode === 'upload' ? 'active' : ''}
                onClick={() => setMode('upload')}
                disabled={busy}
              >
                <Upload size={15} />
                Carica file
              </button>
              <button
                aria-pressed={mode === 'path'}
                className={mode === 'path' ? 'active' : ''}
                onClick={() => setMode('path')}
                disabled={busy}
              >
                <FolderOpen size={15} />
                Percorso locale
              </button>
            </div>
            {mode === 'upload' ? (
              <div
                className={`dropzone ${dragging ? 'dragging' : ''} ${busy ? 'is-busy' : ''}`}
                onDragOver={(event) => {
                  event.preventDefault();
                  if (!busy) setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={drop}
              >
                <div className="upload-icon">
                  {busy ? (
                    <LoaderCircle size={30} className="spin" />
                  ) : (
                    <Upload size={30} strokeWidth={1.5} />
                  )}
                </div>
                <h3>{busy ? 'Analisi dei documenti…' : 'Trascina qui uno o più file'}</h3>
                <p>
                  {busy
                    ? `${completed} di ${batch.length} elaborati · ogni file riceve un report separato`
                    : 'oppure selezionali dal tuo dispositivo'}
                </p>
                <button
                  className="button secondary"
                  disabled={busy}
                  onClick={() => fileInput.current?.click()}
                >
                  <FileSearch size={17} />
                  Scegli file
                </button>
                <input
                  ref={fileInput}
                  type="file"
                  multiple
                  className="sr-only"
                  aria-label="Seleziona i documenti da analizzare"
                  disabled={busy}
                  onChange={(event) => {
                    if (event.target.files?.length) void scanFiles([...event.target.files]);
                  }}
                />
                <small>Testo, codice, JSON, HTML, XML, PDF, DOCX · Fino a 10 MiB per file</small>
              </div>
            ) : (
              <form className="path-form" onSubmit={scanPath}>
                <label htmlFor="scan-path">Percorso assoluto del documento</label>
                <input
                  id="scan-path"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder="/srv/documenti/nota.pdf"
                  required
                  maxLength={4096}
                  disabled={busy}
                />
                <p className="field-help">
                  Il backend Linux deve poter leggere il file. Il contenuto non viene eseguito.
                </p>
                <button className="button primary" disabled={busy || !path.trim()}>
                  {busy ? <LoaderCircle size={17} className="spin" /> : <ScanLine size={17} />}
                  {busy ? 'Analisi in corso…' : 'Scansiona file'}
                </button>
              </form>
            )}
            {error && (
              <div className="padded">
                <ErrorNotice message={error} />
              </div>
            )}
            <div className="extraction-footnote">
              <ShieldCheck size={14} />
              Estrazione senza esecuzione<span>·</span>
              <ShieldAlert size={14} />
              Limiti di dimensione e tempo
            </div>
          </section>
          {batch.length > 0 && (
            <section className="card batch-card">
              <CardHeader
                title={
                  busy
                    ? 'Elaborazione della selezione'
                    : skipped
                      ? 'Coda interrotta'
                      : 'Selezione elaborata'
                }
                subtitle={`${succeeded} report salvati · ${failed} errori${skipped ? ` · ${skipped} saltati` : ''}`}
                action={
                  busy ? (
                    <button
                      className="button secondary small"
                      disabled={stopRequested}
                      onClick={() => {
                        cancelRun.current = true;
                        setStopRequested(true);
                      }}
                    >
                      <Square size={13} />
                      {stopRequested ? 'Arresto richiesto' : 'Ferma la coda'}
                    </button>
                  ) : (
                    <button
                      className="button secondary small"
                      disabled={!succeeded}
                      onClick={() =>
                        downloadJson(
                          batch.filter((item) => item.report).map((item) => item.report),
                          `scan-batch-${new Date().toISOString().slice(0, 10)}.json`,
                        )
                      }
                    >
                      <Download size={14} />
                      Esporta report
                    </button>
                  )
                }
              />
              <div
                className="batch-progress"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={batch.length}
                aria-valuenow={completed + skipped}
                aria-label="Avanzamento elaborazione dei file"
              >
                <span style={{ width: `${((completed + skipped) / batch.length) * 100}%` }} />
              </div>
              {busy && !stopRequested && (
                <p className="batch-stop-note">
                  Lascia aperta questa pagina per completare la selezione. Cambiando pagina si ferma
                  la coda dopo il file in corso.
                </p>
              )}
              {stopRequested && busy && (
                <p className="batch-stop-note" role="status">
                  Il file in corso viene completato. I file successivi non verranno inviati.
                </p>
              )}
              <div className="batch-list" aria-live="polite" aria-relevant="text">
                {batch.map((item) => (
                  <div className={`batch-item ${item.state.toLowerCase()}`} key={item.id}>
                    <span className="batch-item-icon">
                      {item.state === 'SCANNING' ? (
                        <LoaderCircle size={16} className="spin" />
                      ) : item.state === 'DONE' ? (
                        <Check size={16} />
                      ) : item.state === 'ERROR' ? (
                        <CircleX size={16} />
                      ) : (
                        <File size={16} />
                      )}
                    </span>
                    <div>
                      <strong title={item.filename}>{item.filename}</strong>
                      {item.error && <small>{item.error}</small>}
                    </div>
                    {item.verdict ? (
                      <Badge state={item.verdict} />
                    ) : (
                      <span className="batch-state">
                        {
                          {
                            QUEUED: 'In coda',
                            SCANNING: 'Analisi',
                            DONE: 'Completato',
                            ERROR: 'Errore',
                            SKIPPED: 'Saltato',
                          }[item.state]
                        }
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
        <aside className="scanner-side scanner-side-guide">
          <section className="scan-explainer">
            <div className="eyebrow">COME LEGGERE I RISULTATI</div>
            <h3>Un registro, esiti distinti.</h3>
            <ul>
              <li>
                <span className="green">
                  <ShieldCheck size={14} />
                </span>
                <div>
                  <strong>Valido ai controlli</strong>
                  <small>
                    Le regole applicate non hanno segnalato rischi. Non è una garanzia di sicurezza.
                  </small>
                </div>
              </li>
              <li>
                <span className="red">
                  <ShieldAlert size={14} />
                </span>
                <div>
                  <strong>Sospetto / infetto</strong>
                  <small>
                    Rilevate istruzioni sospette o manipolative. Questo esito non certifica
                    un’infezione da virus.
                  </small>
                </div>
              </li>
              <li>
                <span className="amber">
                  <FileWarning size={14} />
                </span>
                <div>
                  <strong>Corrotto o non analizzabile</strong>
                  <small>
                    Formato malformato, non supportato o controllo incompleto. Il contenuto richiede
                    attenzione.
                  </small>
                </div>
              </li>
            </ul>
            <p>
              <Info size={15} />I contatori includono tutte le scansioni salvate. Lo stesso file può
              essere analizzato più volte e produrre più report.
            </p>
          </section>
          <section className="scanner-facts">
            <h3>Nel registro locale</h3>
            <div>
              <span>Contenuti unici</span>
              <strong>{stats?.unique_files ?? '—'}</strong>
            </div>
            <div>
              <span>Decisioni di blocco</span>
              <strong>{stats?.blocked ?? '—'}</strong>
            </div>
            <div>
              <span>Ultima scansione</span>
              <strong>{dateTime(stats?.last_scan_at)}</strong>
            </div>
          </section>
        </aside>
      </div>
      <Sanitizations
        api={api}
        notify={notify}
        disabled={busy || opening}
        openReport={(id) => void openReport(id)}
        onChanged={() => {
          reloadRegistry();
          onChanged();
        }}
      />
      <div ref={reportAnchor} className="report-anchor">
        {opening && <Loading text="Apertura del report…" />}
        {report && <ScanResult report={report} />}
      </div>
      <FileWatchers
        api={api}
        notify={notify}
        onReports={() => {
          reloadRegistry();
          onChanged();
        }}
        showPath={(folder) => {
          setSearch(folder);
          setQuery(folder);
          setVerdict('ALL');
          setOffset(0);
          setTimeout(
            () => registryAnchor.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
            30,
          );
        }}
      />
      <section ref={registryAnchor} className="card processed-registry">
        <CardHeader
          title="Registro dei file elaborati"
          subtitle="Storico persistente con ricerca e paginazione; ogni riga è una scansione"
          action={
            <span className="registry-total">
              <FileCheck2 size={15} />
              {stats?.analyzed ?? '—'} scansioni totali
            </span>
          }
        />
        <div className="table-toolbar">
          <div className="input-icon search-input">
            <Search size={17} />
            <input
              aria-label="Cerca file elaborati"
              placeholder="Cerca nome, percorso o hash…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <select
            aria-label="Filtra per esito della scansione"
            value={verdict}
            onChange={(event) => filterBy(event.target.value)}
          >
            <option value="ALL">Tutti gli esiti</option>
            {verdicts.map((value) => (
              <option key={value} value={value}>
                {label(value)}
              </option>
            ))}
          </select>
          {(search || verdict !== 'ALL') && (
            <button
              className="icon-button"
              title="Azzera filtri"
              aria-label="Azzera filtri del registro"
              onClick={() => {
                setSearch('');
                setQuery('');
                setVerdict('ALL');
                setOffset(0);
              }}
            >
              <ListFilter size={17} />
            </button>
          )}
        </div>
        {historyError && (
          <div className="padded">
            <ErrorNotice message={historyError} retry={reloadRegistry} />
          </div>
        )}
        {loadingHistory ? (
          <Loading text="Caricamento del registro…" />
        ) : history.length ? (
          <div className="table-scroll">
            <table className="processed-table">
              <thead>
                <tr>
                  <th>File elaborato</th>
                  <th>Esito</th>
                  <th>Decisione</th>
                  <th>Severità</th>
                  <th>Evidenze</th>
                  <th>Data di analisi</th>
                  <th>
                    <span className="sr-only">Apri report</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {history.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <button
                        className="component-cell processed-file"
                        onClick={() => void openReport(scan.id)}
                        disabled={busy || opening}
                      >
                        <span className={`file-type-icon ${tone(scan.verdict)}`}>
                          <File size={19} />
                        </span>
                        <span>
                          <strong title={scan.filename}>{scan.filename}</strong>
                          <small>
                            <code title={scan.sha256}>{shortHash(scan.sha256)}</code>
                          </small>
                        </span>
                      </button>
                    </td>
                    <td>
                      <Badge state={scan.verdict} />
                    </td>
                    <td>
                      <Badge state={scan.status} />
                    </td>
                    <td>
                      <Badge state={scan.severity} dot={false} />
                    </td>
                    <td>
                      <span className="finding-count">{scan.findings.length}</span>
                    </td>
                    <td className="muted nowrap">{dateTime(scan.created_at)}</td>
                    <td>
                      <button
                        className="icon-button"
                        onClick={() => void openReport(scan.id)}
                        disabled={busy || opening}
                        aria-label={`Apri report di ${scan.filename}`}
                      >
                        <ArrowRight size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            icon={<FileSearch size={26} />}
            title={
              search || verdict !== 'ALL'
                ? 'Nessun file corrispondente'
                : offset
                  ? 'Nessun altro risultato'
                  : 'Nessun file elaborato'
            }
            text={
              search || verdict !== 'ALL'
                ? 'Modifica i filtri per cercare altri risultati nel registro.'
                : offset
                  ? 'Torna alla pagina precedente per consultare i report.'
                  : 'Carica i primi documenti: ogni scansione comparirà in questo registro.'
            }
          />
        )}
        <div className="table-footer registry-pagination">
          <span>
            {history.length
              ? `${offset + 1}–${offset + history.length}${knownTotal !== null ? ` di ${knownTotal}` : ' risultati visualizzati'}`
              : '0 risultati'}
            {query && stats ? ` · ${stats.analyzed} scansioni nel registro` : ''}
          </span>
          <div>
            <button
              className="button secondary small"
              disabled={!offset || loadingHistory}
              onClick={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
            >
              <ArrowLeft size={14} />
              Precedenti
            </button>
            <span>Pagina {Math.floor(offset / PAGE_SIZE) + 1}</span>
            <button
              className="button secondary small"
              disabled={!hasNext || loadingHistory}
              onClick={() => setOffset((value) => value + PAGE_SIZE)}
            >
              Successivi
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </section>
    </>
  );
}

export function ScanMetrics({
  stats,
  selected,
  onFilter,
}: {
  stats: ScanStats | null;
  selected?: string;
  onFilter: (verdict: string) => void;
}) {
  const metrics = [
    {
      key: 'ALL',
      title: 'File analizzati',
      value: stats?.analyzed,
      icon: FileSearch,
      color: 'blue',
      caption: 'Tutte le scansioni salvate',
    },
    {
      key: 'INFECTED',
      title: 'Sospetti / infetti',
      value: stats?.infected,
      icon: ShieldAlert,
      color: 'red',
      caption: 'Istruzioni sospette rilevate',
    },
    {
      key: 'CORRUPTED',
      title: 'Corrotti',
      value: stats?.corrupted,
      icon: FileWarning,
      color: 'amber',
      caption: 'Struttura o formato malformato',
    },
    {
      key: 'VALID',
      title: 'Validi ai controlli',
      value: stats?.valid,
      icon: FileCheck2,
      color: 'green',
      caption: 'Nessuna evidenza rilevata',
    },
    {
      key: 'REVIEW_REQUIRED',
      title: 'Da verificare',
      value: stats?.review_required,
      icon: CircleAlert,
      color: 'amber',
      caption: 'Richiedono una revisione',
    },
    {
      key: 'UNSCANNABLE',
      title: 'Non analizzabili',
      value: stats?.unscannable,
      icon: FileQuestion,
      color: 'neutral',
      caption: 'Controllo non completato',
    },
  ];
  return (
    <section className="metrics scan-metrics" aria-label="Totali di tutti i file elaborati">
      {metrics.map((metric) => (
        <button
          className={`metric-card metric-filter ${selected === metric.key ? 'selected' : ''}`}
          key={metric.key}
          onClick={() => onFilter(metric.key)}
          aria-pressed={selected === metric.key}
        >
          <div className="metric-top">
            <span>{metric.title}</span>
            <metric.icon className={metric.color} size={18} />
          </div>
          <strong>{metric.value ?? '—'}</strong>
          <small>{metric.caption}</small>
        </button>
      ))}
    </section>
  );
}

function ScanResult({ report }: { report: ScanReport }) {
  return (
    <section className="card scan-result">
      <CardHeader
        title="Risultato della scansione"
        subtitle={report.filename}
        action={
          <button
            className="button secondary small"
            onClick={() => downloadJson(report, `scan-${report.id}.json`)}
          >
            <Download size={15} />
            Report JSON
          </button>
        }
      />
      <div className="scan-summary">
        <div className={`risk-score ${tone(report.verdict)}`}>
          <strong>{report.risk_score}</strong>
          <span>RISCHIO / 100</span>
        </div>
        <div>
          <div className="report-badges">
            <Badge state={report.verdict} />
            <Badge state={report.status} />
          </div>
          <h3>
            {report.findings.length
              ? `${report.findings.length} evidenze da esaminare`
              : report.verdict === 'VALID'
                ? 'Valido ai controlli eseguiti'
                : 'Esamina i limiti del controllo'}
          </h3>
          <p>
            {report.verdict === 'VALID'
              ? 'Nessuna regola ha superato le soglie della policy. Valuta comunque il contesto prima dell’uso.'
              : report.verdict === 'INFECTED'
                ? 'Rilevate istruzioni sospette o manipolative. Questo risultato non è una diagnosi di infezione da virus.'
                : 'Esamina le evidenze e i limiti di estrazione prima di usare il contenuto.'}
          </p>
        </div>
      </div>
      <div className="scan-stats">
        <div>
          <span>Formato</span>
          <strong>{report.extraction.format || '—'}</strong>
        </div>
        <div>
          <span>Caratteri estratti</span>
          <strong>{report.extraction.characters.toLocaleString('it-CH')}</strong>
        </div>
        <div>
          <span>Durata</span>
          <strong>{Math.round(report.duration_ms)} ms</strong>
        </div>
        <div>
          <span>Regole</span>
          <strong>v{report.rules_version}</strong>
        </div>
      </div>
      <div className="scan-result-body">
        {(report.source_path || report.size_bytes !== undefined) && (
          <div className="scan-source">
            {report.source_path && (
              <span>
                <FolderOpen size={14} />
                <code>{report.source_path}</code>
              </span>
            )}
            {report.size_bytes !== undefined && (
              <small>{report.size_bytes.toLocaleString('it-CH')} byte</small>
            )}
          </div>
        )}
        <div className="scan-hash">
          <span>
            <Hash size={14} /> SHA-256
          </span>
          <code>{report.sha256}</code>
        </div>
        {report.extraction.truncated && (
          <div className="notice warning">
            <ShieldAlert size={18} />
            <span>
              L’estrazione è stata troncata. Una parte del contenuto non è stata analizzata.
            </span>
          </div>
        )}
        {report.limitations?.length > 0 && (
          <div className="limitations">
            <h4>
              <Info size={16} />
              Limiti della scansione
            </h4>
            <ul>
              {report.limitations.map((limitation, index) => (
                <li key={index}>{limitation}</li>
              ))}
            </ul>
          </div>
        )}
        <h3 className="section-title">Evidenze rilevate</h3>
        {report.findings.length ? (
          <Findings findings={report.findings} />
        ) : report.verdict === 'VALID' ? (
          <div className="notice success">
            <CheckCheck size={19} />
            <span>Nessuna evidenza rilevata dalle regole applicate.</span>
          </div>
        ) : (
          <div className="notice warning">
            <Info size={18} />
            <span>
              L’assenza di evidenze non completa una scansione interrotta o non supportata. Leggi i
              limiti del report.
            </span>
          </div>
        )}
        <div className="report-footer">
          Analisi del {dateTime(report.created_at)} <span>·</span> {report.extraction.segments}{' '}
          segmenti estratti <span>·</span> ID {report.id}
          {report.sandbox?.active && report.sandbox.mechanism === 'landlock+seccomp' && (
            <span>Isolamento Linux attivo: Landlock + seccomp</span>
          )}
        </div>
      </div>
    </section>
  );
}
