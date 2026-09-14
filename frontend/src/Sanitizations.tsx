import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Download,
  FileText,
  FolderOpen,
  Info,
  LoaderCircle,
  RefreshCw,
  Upload,
} from 'lucide-react';
import type { Api, Notify } from './App';
import { ApiError, dateTime, shortHash } from './api';
import type { Sanitization, SanitizationResult } from './types';
import { CardHeader, Empty, ErrorNotice, Loading, Modal } from './ui';

const PAGE_SIZE = 10;
const omissionLabels: Record<string, string> = {
  comments: 'Commenti',
  hidden_nodes: 'Elementi nascosti',
  metadata_nodes: 'Metadati',
  active_nodes: 'Script e template',
  nontext_nodes: 'Nodi non testuali',
  attributes: 'Attributi',
};
const reasons: Record<string, string> = {
  COPY_PASSED_CHECKS:
    'La copia ha superato i controlli applicati ed è disponibile per la consegna.',
  INPUT_INCOMPLETE: 'L’analisi dell’originale è incompleta. La consegna della copia è negata.',
  OUTPUT_REQUIRES_REVIEW: 'La copia richiede una verifica delle evidenze. La consegna è negata.',
  OUTPUT_INCOMPLETE: 'L’analisi della copia è incompleta. La consegna è negata.',
  WORKERS_BUSY:
    'I processi di analisi sono occupati. Riprova quando le operazioni in corso sono terminate.',
  POLICY_CHANGED:
    'La policy è cambiata durante l’operazione. La consegna è negata: verifica la policy prima di riprovare.',
  SOURCE_UNAVAILABLE: 'Il file originale non è disponibile o non è leggibile dal backend.',
  UNSUPPORTED_TRANSFORMATION:
    'Questo formato non è supportato dal profilo di trasformazione HTML in testo.',
  SENSITIVE_CONTENT: 'I controlli hanno rilevato contenuti sensibili. La consegna è negata.',
  TRANSFORMATION_INCOMPLETE:
    'La trasformazione non è stata completata. Nessuna copia viene consegnata.',
  INPUT_INVALID: 'Il contenuto ricevuto non è valido per la trasformazione.',
  INPUT_SIZE_LIMIT: 'Il file HTML supera il limite di dimensione previsto per la trasformazione.',
  TEXT_ENCODING:
    'La codifica del file HTML non è supportata. Sono richiesti UTF-8 valido oppure UTF-16 con indicatore iniziale della codifica (BOM).',
  TEXT_CONTROL: 'Il file HTML contiene caratteri di controllo non supportati.',
  MALFORMED_HTML:
    'La struttura HTML non rispetta il formato richiesto: verifica che gli elementi siano aperti e chiusi correttamente.',
  UNSUPPORTED_ELEMENT: 'Il file HTML contiene un elemento non supportato dalla trasformazione.',
  UNSUPPORTED_CSS:
    'Il file HTML contiene un foglio di stile o regole CSS non supportati dalla trasformazione.',
  UNSUPPORTED_DECLARATION:
    'Il file HTML contiene una dichiarazione non supportata dalla trasformazione.',
  STRUCTURE_LIMIT:
    'La struttura HTML supera i limiti di complessità previsti per la trasformazione.',
  OUTPUT_SIZE_LIMIT:
    'Il testo della copia supera il limite di 256 KiB. Nessuna copia viene consegnata.',
  EMPTY_OUTPUT: 'Dopo la trasformazione non rimane testo da consegnare.',
  TIME_LIMIT: 'La trasformazione HTML ha superato il tempo massimo disponibile.',
  TRANSFORM_FAILED: 'Non è stato possibile completare la trasformazione HTML.',
};

function Outcomes({ item }: { item: Sanitization }) {
  return (
    <div className="sanitization-outcomes">
      <span>
        Trasformazione
        <strong className={`badge ${item.transformation_status === 'SANITIZED' ? 'green' : 'red'}`}>
          {item.transformation_status === 'SANITIZED' ? 'Copia creata' : 'Non riuscita'}
        </strong>
      </span>
      <span>
        Consegna
        <strong className={`badge ${item.delivery_status === 'ALLOWED' ? 'green' : 'red'}`}>
          {item.delivery_status === 'ALLOWED' ? 'Consentita' : 'Negata'}
        </strong>
      </span>
    </div>
  );
}

function Metadata({
  item,
  openReport,
  disabled,
}: {
  item: Sanitization;
  openReport: (id: string) => void;
  disabled: boolean;
}) {
  return (
    <div className="sanitization-metadata">
      <Outcomes item={item} />
      <p className="sanitization-reason">
        {reasons[item.reason] || `Esito comunicato dal backend: ${item.reason}`}
        <small>{item.reason}</small>
      </p>
      <div className="sanitization-files">
        {(
          [
            [
              'Originale HTML',
              item.input_filename,
              item.input_sha256,
              item.input_size_bytes,
              item.input_report_id,
            ],
            [
              'Copia testuale',
              item.output_filename,
              item.output_sha256,
              item.output_size_bytes,
              item.output_report_id,
            ],
          ] as const
        ).map(([title, filename, hash, size, reportId]) => (
          <div key={title}>
            <h4>{title}</h4>
            <strong>{filename || '—'}</strong>
            <small>
              {size === null
                ? 'Dimensione non disponibile'
                : `${size.toLocaleString('it-CH')} byte`}
            </small>
            <span className="sanitization-hash-label">SHA-256</span>
            <code>{hash || '—'}</code>
            {reportId ? (
              <button
                className="button secondary small"
                disabled={disabled}
                onClick={() => openReport(reportId)}
              >
                <FileText size={14} />
                {title === 'Originale HTML' ? 'Apri report originale' : 'Apri report copia'}
              </button>
            ) : (
              <p className="field-help">Report della copia non disponibile.</p>
            )}
          </div>
        ))}
      </div>
      {Object.keys(item.omitted_counts).length > 0 && (
        <details className="sanitization-omissions">
          <summary>Elementi omessi nella trasformazione</summary>
          <dl>
            {Object.entries(item.omitted_counts).map(([name, count]) => (
              <div key={name}>
                <dt title={name}>{omissionLabels[name] || name}</dt>
                <dd>{count.toLocaleString('it-CH')}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
      <p className="sanitization-reference">
        Profilo {item.profile} · {dateTime(item.created_at)}
        <br />
        Operazione <code>{item.id}</code>
      </p>
    </div>
  );
}

export function Sanitizations({
  api,
  notify,
  onChanged,
  openReport,
  disabled,
}: {
  api: Api;
  notify: Notify;
  onChanged: () => void;
  openReport: (id: string) => void;
  disabled: boolean;
}) {
  const [mode, setMode] = useState<'upload' | 'path'>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [path, setPath] = useState('');
  const [expectedHash, setExpectedHash] = useState('');
  const [busy, setBusy] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<SanitizationResult | null>(null);
  const [history, setHistory] = useState<Sanitization[]>([]);
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [historyError, setHistoryError] = useState('');
  const [detail, setDetail] = useState<Sanitization | null>(null);
  const [opening, setOpening] = useState('');
  const submitting = useRef(false);

  useEffect(() => {
    let stale = false;
    setLoading(true);
    void api<Sanitization[]>(`/sanitizations?limit=${PAGE_SIZE}&offset=${offset}`)
      .then((items) => {
        if (!stale) {
          setHistory(items);
          setHistoryError('');
        }
      })
      .catch((error) => {
        if (!stale) setHistoryError((error as Error).message);
      })
      .finally(() => {
        if (!stale) setLoading(false);
      });
    return () => {
      stale = true;
    };
  }, [api, offset, revision]);

  async function createCopy(event: FormEvent) {
    event.preventDefault();
    if (submitting.current || disabled || downloading) return;
    setError('');
    const hash = expectedHash.trim().toLowerCase();
    if (hash && !/^[a-f0-9]{64}$/.test(hash)) {
      setError('Inserisci un SHA-256 di 64 caratteri esadecimali oppure lascia vuoto il campo.');
      return;
    }
    if (mode === 'upload' && !file) return;
    if (mode === 'upload' && file!.size > 10 * 1024 * 1024) {
      setError('Il file supera il limite di 10 MiB e non è stato inviato al backend.');
      return;
    }
    submitting.current = true;
    setBusy(true);
    setResult(null);
    try {
      let next: SanitizationResult;
      if (mode === 'upload') {
        const form = new FormData();
        form.append('file', file!);
        if (hash) form.append('expected_sha256', hash);
        next = await api<SanitizationResult>('/sanitizations/html', { method: 'POST', body: form });
      } else {
        next = await api<SanitizationResult>('/sanitizations/html/path', {
          method: 'POST',
          body: JSON.stringify({ path: path.trim(), ...(hash ? { expected_sha256: hash } : {}) }),
        });
      }
      setResult(next);
      setOffset(0);
      notify(
        next.delivery_status === 'ALLOWED'
          ? 'Copia testuale creata: consegna consentita.'
          : 'Operazione registrata: consegna della copia negata.',
      );
    } catch (error) {
      setError(
        error instanceof ApiError && error.status === 409
          ? 'Il file non corrisponde allo SHA-256 atteso o la sorgente è cambiata. Verifica il file e il suo hash prima di riprovare.'
          : (error as Error).message,
      );
    } finally {
      setBusy(false);
      submitting.current = false;
      setRevision((value) => value + 1);
      onChanged();
    }
  }

  async function openMetadata(id: string) {
    setOpening(id);
    setHistoryError('');
    try {
      setDetail(await api<Sanitization>(`/sanitizations/${encodeURIComponent(id)}`));
    } catch (error) {
      setHistoryError((error as Error).message);
    } finally {
      setOpening('');
    }
  }

  async function downloadCopy() {
    if (
      busy ||
      downloading ||
      !result ||
      result.transformation_status !== 'SANITIZED' ||
      result.delivery_status !== 'ALLOWED' ||
      !result.delivery
    )
      return;
    setDownloading(true);
    setError('');
    try {
      if (
        result.delivery.encoding !== 'base64' ||
        result.delivery.media_type !== 'text/plain;charset=utf-8'
      )
        throw new Error(
          'Formato della copia restituita non riconosciuto. Download non disponibile.',
        );
      const binary = atob(result.delivery.data_base64);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
      if (bytes.byteLength !== result.output_size_bytes)
        throw new Error(
          'La dimensione della copia ricevuta non corrisponde al report. Download non disponibile.',
        );
      if (!globalThis.crypto?.subtle)
        throw new Error(
          'La verifica SHA-256 non è disponibile in questo browser. Download non disponibile.',
        );
      const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
      const hash = Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, '0'),
      ).join('');
      if (hash !== result.output_sha256)
        throw new Error(
          'Lo SHA-256 della copia ricevuta non corrisponde al report. Download non disponibile.',
        );
      const url = URL.createObjectURL(new Blob([bytes], { type: result.delivery.media_type }));
      const link = document.createElement('a');
      link.href = url;
      link.download =
        result.output_filename.replace(/[^a-zA-Z0-9._-]/g, '_') || 'copia-testuale.txt';
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : 'Impossibile scaricare la copia restituita.',
      );
    } finally {
      setDownloading(false);
    }
  }

  const canDownload =
    result?.transformation_status === 'SANITIZED' &&
    result.delivery_status === 'ALLOWED' &&
    !!result.delivery;

  return (
    <section className="card sanitizations-card" aria-label="Copie testuali HTML">
      <CardHeader
        title="Crea copia testuale"
        subtitle="Trasformazione esplicita da HTML a testo · profilo html-text-v1"
      />
      <div className="sanitization-intro notice info">
        <Info size={18} />
        <span>
          <strong>Una copia con contenuto e formato ridotti.</strong>
          La trasformazione rimuove markup, metadati e altri elementi HTML. La copia può perdere
          informazioni e non è equivalente all’originale. I controlli non offrono una garanzia
          universale di sicurezza.
          <p>
            Originale e copia vengono analizzati separatamente: i loro report contribuiscono ai
            normali contatori delle scansioni. La creazione della copia non implica che la sua
            consegna sia consentita.
          </p>
        </span>
      </div>
      <div className="segmented-control" aria-label="Origine HTML per la copia testuale">
        <button
          type="button"
          aria-pressed={mode === 'upload'}
          className={mode === 'upload' ? 'active' : ''}
          disabled={busy}
          onClick={() => {
            if (mode !== 'upload') setFile(null);
            setMode('upload');
            setError('');
          }}
        >
          <Upload size={15} /> File HTML
        </button>
        <button
          type="button"
          aria-pressed={mode === 'path'}
          className={mode === 'path' ? 'active' : ''}
          disabled={busy}
          onClick={() => {
            setMode('path');
            setError('');
          }}
        >
          <FolderOpen size={15} /> Percorso Linux
        </button>
      </div>
      <form className="sanitization-form" onSubmit={createCopy}>
        {mode === 'upload' ? (
          <div>
            <label htmlFor="sanitization-file">File HTML originale</label>
            <input
              id="sanitization-file"
              type="file"
              accept=".html,.htm,text/html"
              required
              disabled={busy || disabled}
              onChange={(event) => {
                setFile(event.target.files?.[0] || null);
                setError('');
              }}
            />
            <p className="field-help">
              Scegli un file HTML fino a 10 MiB. La selezione non avvia la trasformazione.
            </p>
          </div>
        ) : (
          <div>
            <label htmlFor="sanitization-path">Percorso assoluto del file HTML</label>
            <input
              id="sanitization-path"
              placeholder="/srv/documenti/pagina.html"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              maxLength={4096}
              required
              disabled={busy || disabled}
            />
            <p className="field-help">
              Percorso sul dispositivo Linux dove è in esecuzione il backend.
            </p>
          </div>
        )}
        <details className="sanitization-pin">
          <summary>Verifica un hash atteso (opzionale)</summary>
          <label htmlFor="sanitization-hash">SHA-256 atteso dell’originale</label>
          <input
            id="sanitization-hash"
            value={expectedHash}
            onChange={(event) => setExpectedHash(event.target.value)}
            placeholder="64 caratteri esadecimali"
            maxLength={64}
            autoCapitalize="none"
            spellCheck={false}
            disabled={busy || disabled}
            aria-describedby="sanitization-hash-help"
          />
          <p id="sanitization-hash-help" className="field-help">
            La richiesta viene rifiutata se i byte della sorgente non corrispondono a questo hash.
          </p>
        </details>
        {error && <ErrorNotice message={error} />}
        <button
          className="button primary"
          disabled={busy || downloading || disabled || (mode === 'upload' ? !file : !path.trim())}
        >
          {busy ? <LoaderCircle size={17} className="spin" /> : <FileText size={17} />}
          {busy ? 'Creazione e controlli in corso…' : 'Crea copia testuale'}
        </button>
        {busy && (
          <p className="field-help" role="status">
            Attendi l’esito prima di lasciare la pagina. I byte della copia vengono consegnati
            soltanto in questa risposta.
          </p>
        )}
      </form>
      {result && (
        <div className="sanitization-result" aria-label="Esito dell’ultima trasformazione">
          <h3>Esito dell’ultima richiesta</h3>
          <Metadata item={result} openReport={openReport} disabled={disabled} />
          {canDownload ? (
            <div className="sanitization-download">
              <button
                className="button primary"
                disabled={downloading}
                onClick={() => void downloadCopy()}
              >
                {downloading ? <LoaderCircle size={16} className="spin" /> : <Download size={16} />}
                {downloading ? 'Verifica SHA-256…' : 'Scarica copia testuale'}
              </button>
              <p>
                Il download contiene esattamente i byte restituiti dal backend. La copia è
                disponibile in questa pagina fino a una nuova richiesta o alla chiusura della
                pagina.
              </p>
            </div>
          ) : (
            <div className="notice warning">
              <Info size={17} />
              <span>
                {result.delivery_status === 'DENIED'
                  ? 'La consegna è negata: nessuna copia è disponibile per il download. Consulta i report per le evidenze.'
                  : 'La risposta non contiene una copia scaricabile. Nel registro sono conservati solo metadati e riferimenti ai report.'}
              </span>
            </div>
          )}
        </div>
      )}
      <div className="sanitization-history">
        <CardHeader
          title="Registro delle trasformazioni"
          subtitle="Metadati persistenti; le copie non sono scaricabili dallo storico"
          action={
            <button
              className="button secondary small"
              disabled={loading || busy}
              onClick={() => setRevision((value) => value + 1)}
            >
              <RefreshCw size={14} className={loading ? 'spin' : ''} />
              Aggiorna
            </button>
          }
        />
        {historyError && (
          <div className="padded">
            <ErrorNotice message={historyError} retry={() => setRevision((value) => value + 1)} />
          </div>
        )}
        {loading ? (
          <Loading text="Caricamento delle trasformazioni…" />
        ) : history.length ? (
          <ul className="sanitization-history-list">
            {history.map((item) => (
              <li key={item.id}>
                <div className="sanitization-history-name">
                  <strong>{item.input_filename}</strong>
                  <small>
                    {dateTime(item.created_at)} ·{' '}
                    <code title={item.input_sha256 || undefined}>
                      {shortHash(item.input_sha256 || undefined)}
                    </code>
                  </small>
                </div>
                <Outcomes item={item} />
                <button
                  className="button secondary small"
                  disabled={!!opening}
                  onClick={() => void openMetadata(item.id)}
                  aria-label={`Dettagli trasformazione di ${item.input_filename}`}
                >
                  {opening === item.id ? (
                    <LoaderCircle size={14} className="spin" />
                  ) : (
                    <ArrowRight size={14} />
                  )}
                  Dettagli
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <Empty
            icon={<FileText size={26} />}
            title={offset ? 'Nessun’altra trasformazione' : 'Nessuna trasformazione registrata'}
            text={
              offset
                ? 'Torna alla pagina precedente per consultare le operazioni salvate.'
                : 'Scegli un file HTML e avvia esplicitamente la creazione di una copia testuale.'
            }
          />
        )}
        <div className="table-footer registry-pagination">
          <span>
            {history.length
              ? `${offset + 1}–${offset + history.length} operazioni visualizzate`
              : '0 operazioni visualizzate'}
          </span>
          <div>
            <button
              className="button secondary small"
              aria-label="Trasformazioni precedenti"
              disabled={!offset || loading}
              onClick={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
            >
              <ArrowLeft size={14} />
              Precedenti
            </button>
            <span>Pagina {Math.floor(offset / PAGE_SIZE) + 1}</span>
            <button
              className="button secondary small"
              aria-label="Trasformazioni successive"
              disabled={history.length < PAGE_SIZE || loading}
              onClick={() => setOffset((value) => value + PAGE_SIZE)}
            >
              Successivi
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </div>
      {detail && (
        <Modal
          title="Dettagli trasformazione"
          description="Solo metadati; nessuna copia testuale è conservata in questo registro."
          wide
          onClose={() => setDetail(null)}
        >
          <Metadata
            item={detail}
            disabled={disabled}
            openReport={(id) => {
              setDetail(null);
              openReport(id);
            }}
          />
        </Modal>
      )}
    </section>
  );
}
