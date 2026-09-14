import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import {
  Activity,
  ChevronDown,
  ChevronUp,
  Download,
  Folder,
  FolderPlus,
  Info,
  LoaderCircle,
  Pause,
  Play,
  RefreshCw,
  ScanLine,
  Search,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import type { Api, Notify } from './App';
import { dateTime, downloadJson } from './api';
import type { FileWatchJob, FileWatchRoot, FileWatchStatus } from './types';
import { CardHeader, Empty, ErrorNotice, Loading, Modal } from './ui';

const jobLabels: Record<FileWatchJob['status'], string> = {
  RUNNING: 'In corso',
  COMPLETED: 'Completato',
  PARTIAL: 'Copertura parziale',
  FAILED: 'Non riuscito',
  BUSY: 'Occupato',
  CANCELLED: 'Interrotto',
};

export function FileWatchers({
  api,
  notify,
  onReports,
  showPath,
}: {
  api: Api;
  notify: Notify;
  onReports: () => void;
  showPath: (path: string) => void;
}) {
  const [status, setStatus] = useState<FileWatchStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [adding, setAdding] = useState(false);
  const [path, setPath] = useState('');
  const [recursive, setRecursive] = useState(false);
  const [formError, setFormError] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const knownJobs = useRef(new Map<string, string>());
  const reportsChanged = useRef(onReports);
  reportsChanged.current = onReports;

  const accept = useCallback((next: FileWatchStatus) => {
    let newReports = false;
    for (const root of next.roots) {
      const job = root.last_job;
      if (!job) continue;
      const revision = `${job.id}:${job.status}:${job.scanned}:${job.failed}`;
      if (knownJobs.current.get(root.id) !== revision && (job.scanned > 0 || job.failed > 0))
        newReports = true;
      knownJobs.current.set(root.id, revision);
    }
    setStatus(next);
    if (newReports) reportsChanged.current();
  }, []);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        accept(await api<FileWatchStatus>('/filewatch'));
        setError('');
      } catch (error) {
        setError((error as Error).message);
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [api, accept],
  );

  useEffect(() => {
    void load();
    const timer = setInterval(() => {
      if (!document.hidden) void load(true);
    }, 10000);
    return () => clearInterval(timer);
  }, [load]);

  async function toggleAll() {
    if (!status) return;
    setBusy('global');
    setError('');
    try {
      const next = await api<FileWatchStatus>('/filewatch', {
        method: 'POST',
        body: JSON.stringify({ enabled: !status.running }),
      });
      accept(next);
      notify(
        next.running
          ? 'Monitoraggio delle cartelle avviato.'
          : 'Monitoraggio delle cartelle fermato.',
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy('');
    }
  }

  async function addRoot(event: FormEvent) {
    event.preventDefault();
    setBusy('add');
    setFormError('');
    try {
      await api<FileWatchRoot>('/filewatch/roots', {
        method: 'POST',
        body: JSON.stringify({ path: path.trim(), recursive }),
      });
      setAdding(false);
      setPath('');
      setRecursive(false);
      await load(true);
      notify('Cartella aggiunta al monitoraggio dei file.');
    } catch (error) {
      setFormError((error as Error).message);
    } finally {
      setBusy('');
    }
  }

  async function toggleRoot(root: FileWatchRoot) {
    setBusy(root.id);
    setError('');
    try {
      await api<FileWatchRoot>(`/filewatch/roots/${encodeURIComponent(root.id)}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: !root.enabled }),
      });
      await load(true);
      notify(
        root.enabled
          ? 'Monitoraggio della cartella sospeso.'
          : 'Cartella abilitata al monitoraggio.',
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy('');
    }
  }

  async function removeRoot(root: FileWatchRoot) {
    setBusy(root.id);
    setError('');
    try {
      await api<{ removed: string }>(`/filewatch/roots/${encodeURIComponent(root.id)}`, {
        method: 'DELETE',
      });
      await load(true);
      notify('Cartella rimossa dal monitoraggio. I file originali restano al loro posto.');
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy('');
    }
  }

  async function scanRoot(root: FileWatchRoot) {
    setBusy(`scan:${root.id}`);
    setError('');
    setExpanded(root.id);
    try {
      const job = await api<FileWatchJob>(`/filewatch/roots/${encodeURIComponent(root.id)}/scan`, {
        method: 'POST',
      });
      await load(true);
      reportsChanged.current();
      if (job.status === 'COMPLETED')
        notify(`Passaggio completato: ${job.scanned} file analizzati, ${job.unchanged} invariati.`);
      else
        setError(
          `Il passaggio ha copertura incompleta (${jobLabels[job.status]}): esamina il dettaglio e gli eventuali limiti.`,
        );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy('');
    }
  }

  return (
    <section className="card filewatch-card">
      <CardHeader
        title="Cartelle da analizzare"
        subtitle="Scansione automatica dei file nuovi o modificati, solo nei percorsi che registri"
        action={
          <div className="filewatch-header-actions">
            <button
              className="icon-button"
              onClick={() => void load()}
              disabled={loading || !!busy}
              aria-label="Aggiorna cartelle monitorate"
            >
              <RefreshCw size={16} className={loading ? 'spin' : ''} />
            </button>
            <button
              className="button secondary small"
              disabled={!!busy}
              onClick={() => {
                setFormError('');
                setAdding(true);
              }}
            >
              <FolderPlus size={15} />
              Aggiungi cartella
            </button>
          </div>
        }
      />
      <div className="filewatch-control">
        <div>
          <Activity size={18} className={status?.running ? 'green' : 'muted'} />
          <span>
            <strong>
              {status?.running ? 'Monitor cartelle attivo' : 'Monitor cartelle fermo'}
            </strong>
            <small>
              {status
                ? `${status.roots.filter((root) => root.enabled).length} cartelle abilitate su ${status.roots.length} registrate`
                : 'Caricamento della configurazione'}
            </small>
          </span>
        </div>
        <button className="button secondary small" disabled={!status || !!busy} onClick={toggleAll}>
          {busy === 'global' ? (
            <LoaderCircle size={14} className="spin" />
          ) : status?.running ? (
            <Pause size={14} />
          ) : (
            <Play size={14} />
          )}
          {status?.running ? 'Ferma monitor cartelle' : 'Avvia monitor cartelle'}
        </button>
      </div>
      {error && (
        <div className="filewatch-error">
          <ErrorNotice message={error} retry={() => void load()} />
        </div>
      )}
      {loading && !status ? (
        <Loading text="Caricamento delle cartelle…" />
      ) : status?.roots.length ? (
        <div className="filewatch-roots">
          {status.roots.map((root) => (
            <article className="watched-root" key={root.id}>
              <div className="watched-root-header">
                <div className="watched-folder-icon">
                  <Folder size={21} />
                </div>
                <div className="watched-root-name">
                  <h3 title={root.path}>{root.path}</h3>
                  <p>
                    {root.recursive ? 'Include le sottocartelle' : 'Solo questa cartella'}
                    <span>·</span>
                    {root.files_seen} file visti nell’ultimo passaggio
                  </p>
                </div>
                <span
                  className={`badge ${root.error ? 'amber' : root.enabled && status.running ? 'green' : 'neutral'}`}
                >
                  <i />
                  {root.error
                    ? 'Da verificare'
                    : root.enabled
                      ? status.running
                        ? 'Osservata'
                        : 'Pronta'
                      : 'Sospesa'}
                </span>
              </div>
              <div className="watched-root-toolbar">
                <small>Ultimo passaggio: {dateTime(root.last_scan_at)}</small>
                <div>
                  <button
                    className="button secondary small"
                    disabled={!!busy}
                    onClick={() => void scanRoot(root)}
                  >
                    {busy === `scan:${root.id}` ? (
                      <LoaderCircle size={14} className="spin" />
                    ) : (
                      <ScanLine size={14} />
                    )}
                    {busy === `scan:${root.id}` ? 'Passaggio in corso…' : 'Analizza ora'}
                  </button>
                  <button
                    className="icon-button"
                    disabled={!!busy}
                    onClick={() => void toggleRoot(root)}
                    aria-label={`${root.enabled ? 'Sospendi' : 'Abilita'} cartella ${root.path}`}
                    title={root.enabled ? 'Sospendi cartella' : 'Abilita cartella'}
                  >
                    {root.enabled ? <Pause size={15} /> : <Play size={15} />}
                  </button>
                  <button
                    className="icon-button"
                    disabled={!!busy}
                    onClick={() => showPath(root.path)}
                    aria-label={`Mostra report della cartella ${root.path}`}
                    title="Mostra file nel registro"
                  >
                    <Search size={15} />
                  </button>
                  <button
                    className="icon-button remove-root"
                    disabled={!!busy}
                    onClick={() => void removeRoot(root)}
                    aria-label={`Rimuovi dal monitoraggio ${root.path}`}
                    title="Rimuovi dal monitoraggio; i file restano al loro posto"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
              {busy === `scan:${root.id}` && (
                <div className="watch-running-note" role="status">
                  <LoaderCircle size={15} className="spin" />
                  <span>
                    Il backend sta elaborando un passaggio limitato. L’esito verrà mostrato al
                    completamento.
                  </span>
                </div>
              )}
              {root.error && (
                <div className="notice warning watched-root-warning">
                  <ShieldAlert size={17} />
                  <span>{root.error}</span>
                </div>
              )}
              {root.last_job && (
                <>
                  <button
                    className="watch-job-toggle"
                    aria-expanded={expanded === root.id}
                    onClick={() => setExpanded(expanded === root.id ? null : root.id)}
                  >
                    <span>
                      Ultimo esito{' '}
                      <strong
                        className={
                          root.last_job.status === 'COMPLETED'
                            ? 'green'
                            : root.last_job.status === 'FAILED'
                              ? 'red'
                              : 'amber'
                        }
                      >
                        {jobLabels[root.last_job.status]}
                      </strong>
                    </span>
                    {expanded === root.id ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                  </button>
                  {expanded === root.id && <WatchJob job={root.last_job} />}
                </>
              )}
            </article>
          ))}
        </div>
      ) : (
        !loading && (
          <Empty
            icon={<FolderPlus size={25} />}
            title="Scegli le cartelle da osservare"
            text="Registra una cartella locale per analizzare automaticamente i file nuovi o modificati. I percorsi non vengono aggiunti in autonomia."
          />
        )
      )}
      <div className="filewatch-footnote">
        <Info size={15} />
        <span>
          Il monitor non segue collegamenti simbolici e non sposta i file. Un esito parziale indica
          che alcuni contenuti non sono stati coperti dal passaggio.
        </span>
      </div>
      {adding && (
        <Modal
          title="Aggiungi una cartella"
          description="Autorizza la lettura dei file in un percorso locale specifico."
          onClose={() => {
            if (busy !== 'add') setAdding(false);
          }}
        >
          <form className="modal-form" onSubmit={addRoot}>
            <label htmlFor="watch-folder-path">Percorso assoluto della cartella</label>
            <input
              id="watch-folder-path"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder="/srv/documenti/in-arrivo"
              required
              maxLength={4096}
              autoFocus
            />
            <label className="checkbox-label recursive-check">
              <input
                type="checkbox"
                checked={recursive}
                onChange={(event) => setRecursive(event.target.checked)}
              />
              <span>Includi le sottocartelle</span>
            </label>
            <p className="field-help">
              I file nuovi o modificati vengono analizzati quando il monitor cartelle è attivo. Puoi
              avviare un passaggio manuale anche con il monitor fermo. I file originali restano
              intatti.
            </p>
            {formError && <ErrorNotice message={formError} />}
            <div className="modal-actions">
              <button
                type="button"
                className="button secondary"
                disabled={busy === 'add'}
                onClick={() => setAdding(false)}
              >
                Annulla
              </button>
              <button className="button primary" disabled={busy === 'add' || !path.trim()}>
                {busy === 'add' ? (
                  <LoaderCircle size={16} className="spin" />
                ) : (
                  <FolderPlus size={16} />
                )}
                Registra cartella
              </button>
            </div>
          </form>
        </Modal>
      )}
    </section>
  );
}

function WatchJob({ job }: { job: FileWatchJob }) {
  return (
    <div className="watch-job">
      <div className="watch-job-metrics">
        {[
          { title: 'File visti', value: job.files_seen },
          { title: 'Analizzati', value: job.scanned },
          { title: 'Invariati', value: job.unchanged },
          { title: 'Saltati', value: job.skipped },
          { title: 'Errori', value: job.failed },
          { title: 'Non più presenti', value: job.removed },
        ].map((item) => (
          <div key={item.title}>
            <span>{item.title}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
      {job.limited && (
        <div className="notice warning">
          <ShieldAlert size={17} />
          <span>
            Il passaggio ha raggiunto un limite di tempo, dimensione o quantità. La copertura è
            parziale.
          </span>
        </div>
      )}
      {job.errors.length > 0 && (
        <div className="watch-job-errors">
          {job.errors.map((error, index) => (
            <div key={`${error.code}-${index}`}>
              <strong>{error.code}</strong>
              <code>{error.path}</code>
              <p>{error.message}</p>
            </div>
          ))}
        </div>
      )}
      <div className="watch-job-footer">
        <span>
          {dateTime(job.completed_at)} · {Math.round(job.duration_ms)} ms
        </span>
        <button
          className="text-button"
          onClick={() => downloadJson(job, `watch-pass-${job.id}.json`)}
        >
          <Download size={14} />
          Esporta passaggio
        </button>
      </div>
    </div>
  );
}
