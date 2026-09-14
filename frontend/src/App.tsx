import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import {
  Activity,
  ArrowRight,
  Bell,
  Boxes,
  CircleHelp,
  FileSearch,
  Fingerprint,
  FolderSearch,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  RefreshCw,
  Settings2,
  Shield,
  ShieldCheck,
  ShieldOff,
  Terminal,
  X,
} from 'lucide-react';
import { ApiError, dateTime, initialToken, request, saveToken, shortHash } from './api';
import type { AuditEvent, Component, Page, Status, ScanStats } from './types';
import {
  ArrowLink,
  Badge,
  CardHeader,
  Empty,
  ErrorNotice,
  Loading,
  Modal,
  PageHeading,
} from './ui';
import { ComponentsPage, ComponentDetail } from './Components';
import { ScannerPage } from './Scanner';
import { AuditPage, PolicyPage } from './Operations';

const navigation = [
  { id: 'overview' as Page, title: 'Panoramica', icon: LayoutDashboard },
  { id: 'components' as Page, title: 'Componenti MCP', icon: Boxes },
  { id: 'scanner' as Page, title: 'File Scanner', icon: FileSearch },
  { id: 'audit' as Page, title: 'Registro audit', icon: GitBranch },
  { id: 'policy' as Page, title: 'Policy e controlli', icon: Settings2 },
];

function Connection({ onConnect, reason }: { onConnect: (token: string) => void; reason: string }) {
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(reason);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await request<Status>('/status', token.trim());
      onConnect(token.trim());
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="connection-screen">
      <div className="connection-art" aria-hidden="true">
        <div className="orbit orbit-one" />
        <div className="orbit orbit-two" />
        <div className="orbit orbit-three" />
        <div className="large-shield">
          <ShieldCheck size={82} strokeWidth={1} />
        </div>
        <span className="orbit-label top">SHA-256</span>
        <span className="orbit-label bottom">CONTENT-ADDRESSED TRUST</span>
      </div>
      <section className="connection-card">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={23} />
          </div>
          <div>
            MCP Integrity Guard<small>LOCAL SECURITY CONSOLE</small>
          </div>
        </div>
        <div className="eyebrow">ACCESSO LOCALE</div>
        <h1>
          La fiducia inizia
          <br />
          dal contenuto.
        </h1>
        <p className="connection-intro">
          Verifica i componenti MCP, approva versioni precise e analizza i documenti prima che
          arrivino al tuo agente.
        </p>
        <form onSubmit={submit}>
          <label htmlFor="access-token">Token di accesso</label>
          <div className="input-icon">
            <KeyRound size={18} />
            <input
              id="access-token"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Incolla il token dell’applicazione"
              autoComplete="off"
              required
              autoFocus
            />
          </div>
          <p className="field-help">
            Il token è disponibile all’avvio dell’app. Rimane solo nella sessione di questa scheda.
          </p>
          {error && <ErrorNotice message={error} />}
          <button className="button primary full" disabled={busy || !token.trim()}>
            {busy ? <RefreshCw size={17} className="spin" /> : <LockKeyhole size={17} />}{' '}
            {busy ? 'Connessione…' : 'Apri la console'}
            <ArrowRight size={17} />
          </button>
        </form>
        <div className="connection-footer">
          <span>
            <i className="status-dot" /> Elaborazione locale
          </span>
          <span>Nessuna telemetria</span>
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(initialToken);
  const [reason, setReason] = useState('');
  const [page, setPage] = useState<Page>('overview');
  const [status, setStatus] = useState<Status | null>(null);
  const [scanStats, setScanStats] = useState<ScanStats | null>(null);
  const [components, setComponents] = useState<Component[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState('');
  const [selected, setSelected] = useState<Component | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileNavigation, setMobileNavigation] = useState(
    () => window.matchMedia('(max-width: 680px)').matches,
  );
  const refreshRevision = useRef(0);
  const sidebar = useRef<HTMLElement>(null);
  const menuToggle = useRef<HTMLButtonElement>(null);
  const [showDiscover, setShowDiscover] = useState(false);
  const [notification, setNotification] = useState('');
  const logout = useCallback((message = '') => {
    refreshRevision.current++;
    saveToken('');
    setToken('');
    setStatus(null);
    setScanStats(null);
    setComponents([]);
    setEvents([]);
    setSelected(null);
    setNotification('');
    setError('');
    setReason(message);
    setMenuOpen(false);
  }, []);
  const api = useCallback(
    async <T,>(path: string, options: RequestInit = {}): Promise<T> => {
      try {
        return await request<T>(path, token, options);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) logout(error.message);
        throw error;
      }
    },
    [token, logout],
  );
  const refresh = useCallback(
    async (silent = false) => {
      if (!token) return;
      const revision = ++refreshRevision.current;
      if (!silent) setBusy(true);
      try {
        const [nextStatus, nextComponents, nextEvents, nextScanStats] = await Promise.all([
          api<Status>('/status'),
          api<Component[]>('/components'),
          api<AuditEvent[]>('/audit'),
          api<ScanStats>('/scan/stats'),
        ]);
        if (revision !== refreshRevision.current) return;
        setStatus(nextStatus);
        setComponents(nextComponents);
        setSelected((selected) =>
          selected ? (nextComponents.find((item) => item.id === selected.id) ?? null) : null,
        );
        setEvents(nextEvents);
        setScanStats(nextScanStats);
        setError('');
        setLastUpdated(new Date().toISOString());
      } catch (error) {
        if (revision === refreshRevision.current) setError((error as Error).message);
      } finally {
        if (revision === refreshRevision.current) setBusy(false);
      }
    },
    [api, token],
  );
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => {
      if (!document.hidden) void refresh(true);
    }, 15000);
    return () => clearInterval(timer);
  }, [refresh]);
  useEffect(() => {
    if (!notification) return;
    const timer = setTimeout(() => setNotification(''), 7000);
    return () => clearTimeout(timer);
  }, [notification]);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 680px)');
    function resizeNavigation() {
      setMobileNavigation(media.matches);
      setMenuOpen(false);
      if (media.matches && sidebar.current?.contains(document.activeElement)) {
        menuToggle.current?.focus({ preventScroll: true });
      }
    }
    media.addEventListener('change', resizeNavigation);
    return () => media.removeEventListener('change', resizeNavigation);
  }, []);
  useEffect(() => {
    if (!mobileNavigation || !menuOpen) return;
    const panel = sidebar.current;
    if (!panel) return;
    const items = () => [...panel.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')];
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    items()[0]?.focus({ preventScroll: true });
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault();
        setMenuOpen(false);
      } else if (event.key === 'Tab') {
        const buttons = items();
        const first = buttons[0];
        const last = buttons.at(-1);
        if (!first || !last) return;
        if (
          event.shiftKey &&
          (document.activeElement === first || !panel?.contains(document.activeElement))
        ) {
          event.preventDefault();
          last.focus();
        } else if (
          !event.shiftKey &&
          (document.activeElement === last || !panel?.contains(document.activeElement))
        ) {
          event.preventDefault();
          first.focus();
        }
      }
    }
    document.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener('keydown', onKey);
      if (window.matchMedia('(max-width: 680px)').matches) {
        menuToggle.current?.focus({ preventScroll: true });
      }
    };
  }, [mobileNavigation, menuOpen]);
  function navigate(next: Page) {
    setPage(next);
    setMenuOpen(false);
  }
  function discover() {
    navigate('components');
    setShowDiscover(true);
  }
  function changed(component?: Component) {
    if (component) setSelected(component);
    void refresh(true);
  }
  if (!token)
    return (
      <Connection
        reason={reason}
        onConnect={(next) => {
          saveToken(next);
          setToken(next);
          setReason('');
        }}
      />
    );
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content" inert={mobileNavigation && menuOpen}>
        Vai al contenuto
      </a>
      {menuOpen && <div className="sidebar-scrim" onClick={() => setMenuOpen(false)} />}
      <aside
        ref={sidebar}
        id="workspace-navigation"
        className={`sidebar ${menuOpen ? 'open' : ''}`}
        inert={mobileNavigation && !menuOpen}
        role={mobileNavigation ? 'dialog' : undefined}
        aria-label={mobileNavigation ? 'Menu di navigazione' : undefined}
        aria-modal={mobileNavigation && menuOpen ? true : undefined}
      >
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>
          <div>
            Integrity Guard<small>MCP SECURITY CONSOLE</small>
          </div>
        </div>
        <div className="workspace-label">
          <span className="workspace-icon">
            <Terminal size={15} />
          </span>
          <div>
            Workspace locale<small>Ambiente privato</small>
          </div>
          <LockKeyhole size={13} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Navigazione principale">
          {navigation.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${page === item.id ? 'active' : ''}`}
              aria-current={page === item.id ? 'page' : undefined}
              onClick={() => navigate(item.id)}
            >
              <item.icon size={19} />
              <span>{item.title}</span>
              {item.id === 'components' && !!status?.pending && (
                <span className="nav-count">{status.pending}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="trust-note">
            <Fingerprint size={22} />
            <p>
              Trust the content,
              <br />
              <strong>not the name.</strong>
            </p>
            <span>
              Ogni approvazione è legata
              <br />a una precisa versione.
            </span>
          </div>
          <button
            className="nav-item"
            onClick={() => {
              setMenuOpen(false);
              setShowHelp(true);
            }}
          >
            <CircleHelp size={18} />
            <span>Come funziona</span>
            <ArrowRight size={14} />
          </button>
          <button className="nav-item" onClick={() => logout()}>
            <LogOut size={18} />
            <span>Disconnetti</span>
          </button>
          <div className="local-footer">
            <i className="status-dot" /> Local-first <span>·</span> No telemetry
          </div>
        </div>
      </aside>
      <div className="main-shell" inert={mobileNavigation && menuOpen}>
        <header className="topbar">
          <button
            ref={menuToggle}
            className="icon-button menu-toggle"
            onClick={() => setMenuOpen(true)}
            aria-label="Apri navigazione"
            aria-controls="workspace-navigation"
            aria-expanded={mobileNavigation && menuOpen}
          >
            <Menu size={20} />
          </button>
          <div className="breadcrumb">
            Workspace <span>/</span>{' '}
            <strong>{navigation.find((item) => item.id === page)?.title}</strong>
          </div>
          <div className="topbar-right">
            <span className={`monitor-indicator ${status?.monitor_running ? 'on' : ''}`}>
              <span className="status-dot" />
              {status?.monitor_running ? 'Monitor attivo' : 'Monitor inattivo'}
            </span>
            <button
              className="icon-button"
              onClick={() => void refresh()}
              disabled={busy}
              aria-label="Aggiorna tutti i dati"
              title="Aggiorna dati"
            >
              <RefreshCw size={17} className={busy ? 'spin' : ''} />
            </button>
            <div className="avatar" title="Sessione locale autenticata">
              LC
            </div>
          </div>
        </header>
        <main id="main-content" tabIndex={-1}>
          {error && <ErrorNotice message={error} retry={() => void refresh()} />}
          {status?.scanner_sandbox?.available === false && (
            <ErrorNotice
              message={`Isolamento dello scanner non disponibile. Su Linux le scansioni vengono bloccate finché il sistema non supporta Landlock ABI 3 e libseccomp. ${status.scanner_sandbox.error ?? ''}`}
            />
          )}
          {page === 'overview' && (
            <Overview
              status={status}
              scanStats={scanStats}
              components={components}
              events={events}
              loading={busy}
              lastUpdated={lastUpdated}
              navigate={navigate}
              discover={discover}
              select={setSelected}
            />
          )}
          {page === 'components' && (
            <ComponentsPage
              api={api}
              components={components}
              busy={busy}
              refresh={() => void refresh()}
              select={setSelected}
              discoverOpen={showDiscover}
              setDiscoverOpen={setShowDiscover}
              notify={setNotification}
            />
          )}
          {page === 'scanner' && (
            <ScannerPage api={api} onChanged={() => void refresh(true)} notify={setNotification} />
          )}
          {page === 'audit' && <AuditPage api={api} />}
          {page === 'policy' && (
            <PolicyPage api={api} onChanged={() => void refresh(true)} notify={setNotification} />
          )}
        </main>
        <footer className="main-footer">
          <span>
            <Shield size={13} /> MCP Integrity Guard
          </span>
          <span>Controllo locale · Nessun contenuto inviato a servizi esterni</span>
        </footer>
      </div>
      {selected && (
        <ComponentDetail
          component={selected}
          policyVersion={status?.policy_version}
          api={api}
          onChanged={changed}
          onClose={() => setSelected(null)}
          notify={setNotification}
        />
      )}
      {notification && (
        <div className="toast" role="status">
          <ShieldCheck size={19} />
          <span>{notification}</span>
          <button
            className="icon-button"
            onClick={() => setNotification('')}
            aria-label="Chiudi notifica"
          >
            <X size={15} />
          </button>
        </div>
      )}
      {showHelp && (
        <Modal
          title="Protezione basata sul contenuto"
          description="Che cosa fa MCP Integrity Guard"
          onClose={() => setShowHelp(false)}
        >
          <div className="help-content">
            <ol>
              <li>
                <strong>Scopri e analizza.</strong> Inserisci il percorso di un file di
                configurazione MCP.
              </li>
              <li>
                <strong>Approva una versione.</strong> Esamina contenuto, fingerprint e variazioni.
                L’approvazione firmata è legata all’hash del contenuto.
              </li>
              <li>
                <strong>Controlla prima dell’uso.</strong> Collega il tuo client al gate{' '}
                <code>POST /api/gate</code>. Il gate rilegge la sorgente e applica le policy.
              </li>
              <li>
                <strong>Scansiona i documenti.</strong> Analizza i file prima di passarli all’agente
                e valuta le evidenze segnalate.
              </li>
            </ol>
            <div className="notice info">
              <ShieldOff size={20} />
              <span>
                La console e il monitor non intercettano automaticamente le chiamate MCP. Il client
                deve usare il gate e rispettarne la decisione prima di eseguire un componente.
              </span>
            </div>
            <p className="muted">
              Le regole di scansione possono generare falsi positivi o non rilevare istruzioni
              malevole. Una scansione consentita non certifica la sicurezza del documento.
            </p>
          </div>
        </Modal>
      )}
    </div>
  );
}

export type Api = <T>(path: string, options?: RequestInit) => Promise<T>;
export type Notify = (message: string) => void;

function Overview({
  status,
  scanStats,
  components,
  events,
  loading,
  lastUpdated,
  navigate,
  discover,
  select,
}: {
  status: Status | null;
  scanStats: ScanStats | null;
  components: Component[];
  events: AuditEvent[];
  loading: boolean;
  lastUpdated: string;
  navigate: (page: Page) => void;
  discover: () => void;
  select: (component: Component) => void;
}) {
  const attention = components.filter((component) => component.state !== 'APPROVED');
  const approved = status?.approved ?? 0;
  const total = status?.components ?? 0;
  const metrics = [
    {
      title: 'Componenti monitorati',
      value: status?.components,
      icon: Boxes,
      text: 'Configurazioni e definizioni',
      color: 'blue',
    },
    {
      title: 'Versioni approvate',
      value: status?.approved,
      icon: ShieldCheck,
      text: 'Fiducia legata al contenuto',
      color: 'green',
    },
    {
      title: 'In attesa di revisione',
      value: status?.pending,
      icon: Fingerprint,
      text: 'Richiedono approvazione',
      color: 'amber',
    },
    {
      title: 'Componenti bloccati',
      value: status?.blocked,
      icon: ShieldOff,
      text: 'Accesso negato dal gate',
      color: 'red',
    },
  ];
  return (
    <>
      <PageHeading
        eyebrow="CONTROL CENTER"
        title="Il tuo perimetro MCP."
        description="Integrità dei componenti, fiducia verificabile e visibilità su ogni modifica."
        action={
          <button className="button primary" onClick={discover}>
            <FolderSearch size={17} />
            Scopri componenti
          </button>
        }
      />
      <section className="status-banner">
        <div className="status-banner-icon">
          <ShieldCheck size={28} strokeWidth={1.6} />
        </div>
        <div>
          <h2>{status ? 'Il contenuto è la tua baseline.' : 'Connessione al workspace…'}</h2>
          <p>Le approvazioni seguono gli hash. Ogni modifica viene rivalutata dalle policy.</p>
        </div>
        <div className="banner-meta">
          <span className={`badge ${status ? (status.audit_valid ? 'green' : 'red') : 'neutral'}`}>
            <i />
            {status
              ? status.audit_valid
                ? 'Catena audit valida'
                : 'Anomalia nella catena audit'
              : 'Verifica in corso'}
          </span>
          <small>Gate di integrazione · Policy v{status?.policy_version ?? '—'}</small>
        </div>
      </section>
      <section className="metrics" aria-label="Stato del workspace">
        {metrics.map((metric) => (
          <div className="metric-card" key={metric.title}>
            <div className="metric-top">
              <span>{metric.title}</span>
              <metric.icon className={metric.color} size={18} />
            </div>
            <strong>{metric.value === undefined ? '—' : metric.value}</strong>
            <small>{metric.text}</small>
          </div>
        ))}
      </section>
      <FileOverviewSummary stats={scanStats} openScanner={() => navigate('scanner')} />
      <div className="overview-grid">
        <section className="card attention-card">
          <CardHeader
            title="Da tenere d’occhio"
            subtitle="Componenti che richiedono una decisione"
            action={
              <ArrowLink onClick={() => navigate('components')}>Tutti i componenti</ArrowLink>
            }
          />
          {loading && !status ? (
            <Loading />
          ) : attention.length ? (
            <div className="attention-list">
              {attention.slice(0, 5).map((component) => (
                <button
                  className="attention-item"
                  key={component.id}
                  onClick={() => select(component)}
                >
                  <div
                    className={`component-icon ${component.state === 'BLOCKED' || component.state === 'REVOKED' ? 'red' : 'amber'}`}
                  >
                    <Boxes size={19} />
                  </div>
                  <div className="attention-name">
                    <strong>{component.name}</strong>
                    <small>
                      {component.kind} <span>·</span> Versione {component.version}
                    </small>
                  </div>
                  <Badge state={component.state} />
                  <ArrowRight size={16} className="muted" />
                </button>
              ))}
            </div>
          ) : (
            <Empty
              title={total ? 'Nessuna revisione in sospeso' : 'Costruisci la tua prima baseline'}
              text={
                total
                  ? 'Tutti i componenti registrati risultano approvati. Il monitor verifica le modifiche quando è attivo.'
                  : 'Scopri una configurazione MCP per analizzarne contenuto, hash e possibili rischi.'
              }
              action={
                !total ? (
                  <button className="button secondary small" onClick={discover}>
                    <FolderSearch size={16} />
                    Aggiungi una sorgente
                  </button>
                ) : undefined
              }
            />
          )}
        </section>
        <section className="card posture-card">
          <CardHeader
            title="Copertura delle approvazioni"
            subtitle="Stato delle versioni registrate"
          />
          <div className="coverage">
            <svg
              viewBox="0 0 180 180"
              role="img"
              aria-label={`${approved} componenti approvati su ${total}`}
            >
              <circle cx="90" cy="90" r="70" fill="none" stroke="var(--border)" strokeWidth="9" />
              <circle
                cx="90"
                cy="90"
                r="70"
                fill="none"
                stroke="var(--accent)"
                strokeWidth="9"
                strokeDasharray={`${total ? (approved / total) * 439.82 : 0} 439.82`}
                strokeLinecap={approved ? 'round' : 'butt'}
                transform="rotate(-90 90 90)"
              />
            </svg>
            <div>
              <strong>{total ? `${Math.round((approved / total) * 100)}%` : '—'}</strong>
              <span>{total ? 'approvato' : 'nessuna baseline'}</span>
            </div>
          </div>
          <div className="coverage-legend">
            <span>
              <i className="legend-dot green" />
              Approvati<strong>{status?.approved ?? '—'}</strong>
            </span>
            <span>
              <i className="legend-dot neutral" />
              Altri stati<strong>{status ? total - approved : '—'}</strong>
            </span>
          </div>
        </section>
        <section className="card">
          <CardHeader
            title="Attività recente"
            subtitle="Eventi registrati nella catena audit"
            action={<ArrowLink onClick={() => navigate('audit')}>Apri registro</ArrowLink>}
          />
          {events.length ? (
            <div className="activity-list">
              {[...events]
                .sort((a, b) => b.sequence - a.sequence)
                .slice(0, 5)
                .map((event) => (
                  <div className="activity-item" key={event.sequence}>
                    <div className="activity-marker">
                      <Activity size={15} />
                    </div>
                    <div>
                      <strong>{event.event_type.replaceAll('_', ' ')}</strong>
                      <small>
                        {event.component_id ? shortHash(event.component_id) : 'Workspace'}{' '}
                        <span>·</span> #{event.sequence}
                      </small>
                    </div>
                    <time>{dateTime(event.timestamp)}</time>
                  </div>
                ))}
            </div>
          ) : (
            <Empty
              icon={<GitBranch size={25} />}
              title="Il registro è pronto"
              text="Le operazioni del workspace compariranno qui, collegate da hash verificabili."
            />
          )}
        </section>
        <section className="scanner-shortcut">
          <div className="scan-illustration" aria-hidden="true">
            <div className="document-shape">
              <span />
              <span />
              <span />
              <span />
              <FileSearch size={33} />
            </div>
            <div className="scan-line" />
          </div>
          <div className="eyebrow">PRIMA DELL’AGENTE</div>
          <h2>
            Un file può contenere
            <br />
            più di un documento.
          </h2>
          <p>
            Analizza istruzioni nascoste, prompt injection e contenuti offuscati prima dell’uso.
          </p>
          <button className="button secondary" onClick={() => navigate('scanner')}>
            Apri File Scanner
            <ArrowRight size={16} />
          </button>
          <small>{status?.scans ?? '—'} scansioni registrate nel workspace</small>
        </section>
      </div>
      <div className="integration-note">
        <Bell size={16} />
        <span>
          Il blocco richiede l’integrazione del client con il gate. Il monitor rileva le modifiche
          ai file registrati.
        </span>
        <span className="last-updated">
          Aggiornato{' '}
          {lastUpdated
            ? new Intl.DateTimeFormat('it-CH', { timeStyle: 'short' }).format(new Date(lastUpdated))
            : '—'}
        </span>
      </div>
    </>
  );
}

function FileOverviewSummary({
  stats,
  openScanner,
}: {
  stats: ScanStats | null;
  openScanner: () => void;
}) {
  return (
    <section className="card overview-files">
      <CardHeader
        title="File elaborati"
        subtitle="Il totale dei controlli salvati, su tutto il registro locale"
        action={<ArrowLink onClick={openScanner}>Apri registro file</ArrowLink>}
      />
      <div className="overview-file-metrics">
        {[
          { label: 'Analizzati', value: stats?.analyzed, color: 'blue' },
          { label: 'Sospetti / infetti', value: stats?.infected, color: 'red' },
          { label: 'Corrotti', value: stats?.corrupted, color: 'amber' },
          { label: 'Validi ai controlli', value: stats?.valid, color: 'green' },
        ].map((item) => (
          <button key={item.label} onClick={openScanner}>
            <span>
              <i className={`legend-dot ${item.color}`} />
              {item.label}
            </span>
            <strong>{item.value ?? '—'}</strong>
          </button>
        ))}
      </div>
      <div className="overview-files-footer">
        <span>
          {stats?.review_required ?? '—'} da verificare <i>·</i> {stats?.unscannable ?? '—'} non
          analizzabili
        </span>
        <span>Esiti delle regole, senza certificazione antivirus.</span>
      </div>
    </section>
  );
}
