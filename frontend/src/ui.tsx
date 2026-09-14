import { useEffect, useRef, type ReactNode } from 'react';
import { AlertCircle, Check, ChevronRight, LoaderCircle, ShieldCheck, X } from 'lucide-react';

const labels: Record<string, string> = {
  VALID: 'Valido ai controlli',
  INFECTED: 'Sospetto / infetto',
  CORRUPTED: 'Corrotto',
  REVIEW_REQUIRED: 'Da verificare',
  UNSCANNABLE: 'Non analizzabile',
  APPROVED: 'Approvato',
  PENDING_APPROVAL: 'Da approvare',
  REAPPROVAL_REQUIRED: 'Da riapprovare',
  BLOCKED: 'Bloccato',
  QUARANTINED: 'In quarantena',
  REVOKED: 'Revocato',
  ALLOWED: 'Consentito',
  FLAGGED: 'Da verificare',
  ALLOW: 'Consenti',
  WARN: 'Avvisa',
  REQUIRE_REAPPROVAL: 'Richiedi approvazione',
  QUARANTINE: 'Quarantena',
  BLOCK: 'Blocca',
  INFO: 'Info',
  LOW: 'Bassa',
  MEDIUM: 'Media',
  HIGH: 'Alta',
  CRITICAL: 'Critica',
  FORMAT_ONLY_CHANGE: 'Solo formato',
  BYTE_CHANGE: 'Modifica dei byte',
  SEMANTIC_CHANGE: 'Modifica semantica',
  SECURITY_RELEVANT_CHANGE: 'Modifica di sicurezza',
};
export const label = (state: string): string => labels[state] || state.replaceAll('_', ' ');
export function tone(state: string): string {
  if (['APPROVED', 'ALLOWED', 'ALLOW', 'LOW', 'VALID'].includes(state)) return 'green';
  if (['BLOCKED', 'BLOCK', 'HIGH', 'CRITICAL', 'REVOKED', 'INFECTED', 'CORRUPTED'].includes(state))
    return 'red';
  if (
    [
      'QUARANTINED',
      'QUARANTINE',
      'MEDIUM',
      'WARN',
      'PENDING_APPROVAL',
      'REAPPROVAL_REQUIRED',
      'REQUIRE_REAPPROVAL',
      'FLAGGED',
      'REVIEW_REQUIRED',
    ].includes(state)
  )
    return 'amber';
  return 'neutral';
}
export function Badge({ state, dot = true }: { state: string; dot?: boolean }) {
  return (
    <span className={`badge ${tone(state)}`}>
      {dot && <i />}
      {label(state)}
    </span>
  );
}
export function ErrorNotice({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="notice error" role="alert">
      <AlertCircle size={18} />
      <span>{message}</span>
      {retry && (
        <button className="text-button" onClick={retry}>
          Riprova
        </button>
      )}
    </div>
  );
}
export function Loading({ text = 'Caricamento dei dati…' }: { text?: string }) {
  return (
    <div className="loading" role="status">
      <LoaderCircle className="spin" size={20} />
      {text}
    </div>
  );
}
export function Empty({
  icon,
  title,
  text,
  action,
}: {
  icon?: ReactNode;
  title: string;
  text: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon || <ShieldCheck size={26} />}</div>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
export function CardHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="card-header">
      <div>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
export function PageHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
export function JsonView({ value }: { value: unknown }) {
  return (
    <pre className="json-view">
      {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
}
export function Modal({
  title,
  description,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const panel = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    panel.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close.current();
      if (event.key !== 'Tab') return;
      const items = panel.current?.querySelectorAll<HTMLElement>(
        'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]',
      );
      if (!items?.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (
        event.shiftKey &&
        (document.activeElement === first || document.activeElement === panel.current)
      ) {
        event.preventDefault();
        last.focus();
      } else if (
        !event.shiftKey &&
        (document.activeElement === last || document.activeElement === panel.current)
      ) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener('keydown', onKey);
      previous?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={panel}
        tabIndex={-1}
        className={`modal ${wide ? 'wide' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-head">
          <div>
            <h2>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Chiudi finestra">
            <X size={20} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
export function Success({ children }: { children: ReactNode }) {
  return (
    <div className="notice success" role="status">
      <Check size={18} />
      {children}
    </div>
  );
}
export function ArrowLink({ children, onClick }: { children: ReactNode; onClick: () => void }) {
  return (
    <button className="text-button" onClick={onClick}>
      {children}
      <ChevronRight size={16} />
    </button>
  );
}
