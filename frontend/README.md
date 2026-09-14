# Console MCP Integrity Guard

Interfaccia React, TypeScript e Vite per il backend locale Linux. La console mostra dati persistenti ottenuti dalle API: non include metriche o risultati simulati.

## Sviluppo Linux

Il progetto condiviso è in `/mnt/d/Cheker/dev/frontend` (directory `D:\Cheker\dev\frontend` sull’host).

```bash
cd /mnt/d/Cheker/dev/frontend
npm ci
GUARD_API_TARGET=http://127.0.0.1:8766 npm run dev
```

Il proxy Vite inoltra `/api` a `GUARD_API_TARGET`; senza la variabile usa `http://127.0.0.1:8765`. La produzione usa API sulla stessa origine.

```bash
npm run build
npm audit
npm run format:check
```

La build verifica TypeScript e crea `dist`. Il launcher di progetto distribuisce questi file con il backend in `D:\Cheker\app`.

## Accesso

Incollare nella console il token emesso dal launcher. In alternativa, il launcher può aprire `/#token=TOKEN`: la console rimuove subito il frammento dall’indirizzo e conserva il token in `sessionStorage`. Ogni chiamata API porta il token nell’header Authorization. Disconnetti cancella il token dalla sessione.

## Workflow

- **Panoramica**: stato delle componenti e conteggi di tutti i file analizzati, sospetti, corrotti e validi ai controlli, con revisione richiesta e non analizzabili.
- **Componenti MCP**: scoperta da un file di configurazione; filtri; contenuto con segreti oscurati; hash, variazioni, storico, approvazione vincolata a hash e versione, revoca e quarantena logica.
- **Verifica prima dell’uso**: il pulsante nel dettaglio chiama il vero gate con ID, hash canonico e versione mostrati. Il componente non viene eseguito; il dettaglio viene aggiornato dopo la decisione.
- **File Scanner**: selezione o trascinamento di più file (massimo 10 MB per file) con scansioni reali sequenziali e avanzamento per file; arresto dopo il file corrente; percorso locale per singolo file; export JSON del report o della selezione.
- **Registro file elaborati**: tabella persistente con nome, hash, esito, decisione, severità, evidenze e data. Ricerca per nome, percorso o hash; filtro per esito; pagine da 25 righe. I totali globali e filtrati vengono dal backend, non dal numero di righe caricate. Contenuti unici significa hash SHA-256 distinti.
- **Cartelle da analizzare**: percorsi espliciti, sottocartelle facoltative, avvio/arresto globale, pausa per cartella, passaggio manuale e report dei limiti. La rimozione dalla lista non elimina i file. Il monitor non segue collegamenti simbolici; gli esiti parziali sono segnalati.
- **Registro audit**: eventi reali, dettagli, verifica della catena ed esportazione del backend.
- **Policy e controlli**: modifica versionata delle policy, soglie ordinate, avvio e arresto del monitor.

Gli esiti distinguono VALID (valido ai controlli), INFECTED (istruzioni sospette/manipolative rilevate), CORRUPTED (corrotto), REVIEW_REQUIRED (da verificare) e UNSCANNABLE (non analizzabile). Non sono una certificazione antivirus o una garanzia di sicurezza.

La console non è un proxy MCP trasparente. Il client deve interrogare il gate prima dell’uso e applicarne la decisione.

## Accessibilità e dati

La UI include navigazione da tastiera, focus visibile, collegamento per saltare al contenuto, dialoghi con gestione del focus, messaggi di errore annunciati, riduzione del movimento e layout responsive. Il contenuto non viene inserito come HTML: file e report sono visualizzati come testo. Non vengono caricati font, script o asset da servizi esterni.

Il controllo di regressione `tests/mobile-layout.cjs` usa un backend di test con almeno un report e Playwright: verifica viewport da 360 a 1440 px, assenza di overflow della pagina, scorrimento interno della tabella e assenza di errori JavaScript. Accetta percorso del token, modulo Playwright, URL del backend e cartella screenshot come argomenti. Non modifica file o dati del backend.
