# Cheker · MCP Integrity Guard

Cheker è un’applicazione locale per **Linux** che verifica l’integrità delle configurazioni MCP, registra le modifiche e analizza i file prima del loro utilizzo attraverso i lettori integrati. La console mostra i file processati, i risultati, le sommatorie, le approvazioni e l’audit.

È disponibile in anteprima anche il pacchetto **Windows x64 con GUI**, che avvia lo stesso motore Linux locale tramite WSL 2. La [guida Windows](docs/WINDOWS.md) descrive il setup singolo `cheker-setup-xlsx-preview-2.exe`, la scelta della cartella e **Installa e avvia**, oltre all’alternativa ZIP. WSL 2, una distribuzione predefinita con Python 3.11+ e `venv`, WebView2 e .NET Framework 4.8 devono essere già disponibili; il setup non li installa automaticamente. La pubblicazione della [release preview.2](https://github.com/okno/cheker/releases/tag/v1.0.0-preview.2) è prevista, non ancora confermata in questo aggiornamento documentale.

Una modifica ai byte della configurazione invalida l’approvazione precedente. Il gate verifica nuovamente sorgente, versione, firma e policy prima di consentire l’uso. Le approvazioni sono legate al contenuto, non al solo nome del componente.

## Documentazione

| Per chi | Guida |
|---|---|
| Utilizzatori | [Manuale utente](docs/MANUALE_UTENTE.md): installazione, primo avvio, file, approvazioni, monitor, errori e FAQ |
| Windows | [App Windows](docs/WINDOWS.md): EXE con interfaccia dedicata, motore WSL 2 e avvio guidato |
| Amministratori e integratori | [Manuale tecnico](docs/MANUALE_TECNICO.md): architettura, API/CLI, persistenza, backup e ripristino |
| Sviluppatori | [Guida allo sviluppo](docs/SVILUPPO.md): ambiente, codice, build, test e rilascio |
| Client MCP | [Integrazione MCP](docs/MCP_INTEGRATION.md): server stdio, radici consentite e lettura protetta |
| Contratto di sicurezza | [CONTRACT.md](CONTRACT.md) e [architettura](docs/ARCHITETTURA.md) |
| Formati e confini | [Copertura dei requisiti](docs/REQUISITI_COPERTURA.md), [sandbox Linux](docs/LINUX_SANDBOX.md), [estrattori](docs/ESTRATTORI.md) |
| Copia HTML | [Sanitizzazione esplicita](docs/SANITIZZAZIONE.md) |
| Evidenze e prestazioni | [Validazione](docs/VALIDAZIONE.md) e [prestazioni](docs/PERFORMANCE.md) |
| Ricerca e protezioni | [Casi documentati e protezioni implementate](docs/PROTEZIONI.md) |

## Installazione su Linux

Requisiti: Linux a 64 bit, Python 3.11+, supporto `venv`, Landlock ABI 3 o successiva e `libseccomp.so.2`. In genere serve Linux 6.2+ con Landlock abilitato; la diagnostica verifica la disponibilità effettiva. Le prove locali riguardano Debian 13/WSL2 x86_64 con Python 3.13.5 e 3.11.16. Aarch64 è previsto dal codice ma non verificato su hardware.

Dopo avere scaricato il pacchetto Linux e il relativo checksum nella stessa cartella:

```bash
sha256sum -c mcp-integrity-guard-1.0.0-linux.tar.gz.sha256
tar -xzf mcp-integrity-guard-1.0.0-linux.tar.gz
cd mcp-integrity-guard
bash install-linux.sh
bash start.sh
```

L’installer richiede rete per le dipendenze e crea un ambiente Python locale. L’uso ordinario non richiede Node o servizi esterni. Il pacchetto contiene wheel, interfaccia compilata, script, esempi e manuali; non contiene dati, token o chiavi preesistenti. Il checksum rileva alterazioni rispetto al riferimento, ma non è una firma indipendente del distributore. I manuali incorporati negli archivi conservano lo snapshot del freeze; le note e i manuali aggiornati per la release sono preparati separatamente per la pubblicazione, senza modificare wheel, ZIP o tar già qualificati.

La console ascolta su `http://127.0.0.1:8765`. Il launcher verifica il servizio e apre la sessione; mantenere il processo attivo e usare Ctrl+C per arrestarlo. La prima apertura è vuota: non vengono inseriti dati fittizi. Il token locale è una credenziale amministrativa e non deve essere condiviso. Se il sandbox non è disponibile, le scansioni restano bloccate.

Su questa installazione, richiesta in **D:\Cheker**:

| Percorso | Contenuto |
|---|---|
| `/mnt/d/Cheker/app` | App Linux, ambiente Python, interfaccia compilata e manuali |
| `/mnt/d/Cheker/app/data-linux` | Dati privati, token, chiave Ed25519 e checkpoint |
| `/mnt/d/Cheker/dev` | Sorgenti, test e documentazione |
| `/mnt/d/Cheker/Avvia-Cheker.sh` | Avvio locale dell’app |
| `/mnt/d/Cheker/site` | Sito e guide navigabili |

Su un altro host Linux si può usare una directory diversa. Per installazione, permessi, systemd e aggiornamenti consultare i manuali.

## Primo utilizzo

1. Scoprire una configurazione MCP indicando il percorso assoluto di un file JSON, JSON5, YAML, TOML o `.env`. Nessun comando MCP viene avviato.
2. Aprire un componente e leggere contenuto, differenze, rischi, versione e hash. Le parti sensibili riconosciute sono mascherate.
3. Approvare intenzionalmente la versione corrente. Una modifica successiva richiede una nuova revisione; revoca e quarantena negano l’uso tramite gate.
4. Analizzare un file dalla console oppure configurare cartelle esplicite da monitorare. Consultare il registro, i dettagli e i contatori globali.
5. Collegare il proprio client al gate o al lettore protetto per applicare effettivamente il blocco prima dell’utilizzo.

Il monitor da solo non impedisce a un altro programma di leggere un file o usare un server MCP senza passare da Cheker.

## File e risultati

| Formati prioritari | Comportamento attuale |
|---|---|
| PDF | Testo, livelli e metadati ispezionabili; immagini che richiedono OCR e contenuti non ispezionabili restano bloccati |
| DOCX | Testo e parti OOXML previste, compresi livelli nascosti/metadati; limiti e contenuti non ispezionabili impediscono l’autorizzazione |
| TXT, MD | Analisi del testo; commenti e frontmatter Markdown riconosciuti entro i limiti |
| XLSX | Profilo statico Transitional nella wheel `f426c5aa…`: celle, stringhe condivise, metadati e viste nascoste; formule, immagini e parti fuori profilo restano bloccate |
| DOC, XLS, XLSM, XLSB | **Non supportati: bloccati come non analizzabili**, non classificati validi |
| Altri formati supportati | JSON/JSON5, YAML, TOML, CSV, HTML, XML, LOG, PY, JS, TS, SH, PS1 e `.env`, trattati come dati |

Il profilo XLSX è incluso nella wheel **`f426c5aa…`**, qualificata su Python 3.13 e 3.11 e installata nell’app Linux il 15 settembre 2026. La precedente `039e0fd8…` non lo include. La [Validazione](docs/VALIDAZIONE.md) riporta hash completi, suite, installazione, upgrade e prove Windows. Un risultato valido ai controlli non certifica ogni variante del formato.

Il registro distingue `VALID`, `INFECTED`, `CORRUPTED`, `REVIEW_REQUIRED` e `UNSCANNABLE`. I contatori si riferiscono alle elaborazioni; i contenuti unici sono hash SHA-256 distinti. Analizzare nuovamente lo stesso contenuto aggiunge un report. Filtri e pagine non cambiano i totali globali. Il conteggio dei bloccati attraversa i verdetti e non è una categoria da sommare alle altre.

`INFECTED` indica istruzioni o manipolazioni sospette rilevate, non una diagnosi antivirus. `VALID` significa che i controlli implementati sono stati completati: non garantisce l’assenza di qualsiasi minaccia. Il motore usa regole versionate, normalizzazioni e decodifiche limitate; sono possibili falsi positivi e falsi negativi. OCR e comprensione universale degli attacchi sconosciuti non sono presenti.

La copia testuale HTML è un’operazione esplicita: scansione dell’originale, trasformazione confinata e scansione degli esatti byte derivati. `SANITIZED` descrive la trasformazione; la consegna richiede separatamente `ALLOWED` e analisi completa della copia. Lo storico conserva metadati, non un archivio di copie scaricabili.

## Integrazioni e dati

- **CLI**: `guard.sh` espone discovery, inventario, gate, scansione, lettura protetta e verifica audit. Usare `bash guard.sh --help` per gli argomenti.
- **MCP stdio**: `scan_file` e `read_file` su radici dichiarate. La lettura consegna soltanto testo UTF-8 ammesso, completo e valido, fino a 256 KiB.
- **API locale**: autenticazione Bearer, controllo Host/Origin e prova del servizio. Non è prevista esposizione pubblica diretta del backend.
- **Persistenza**: database, firme e checkpoint rimangono locali. La chiave privata e il checkpoint devono essere conservati insieme al backup coerente dei dati.

L’audit grafico mostra fino a 200 eventi recenti; l’export è limitato a 100.000 eventi. La verifica esplicita della catena resta integrale. La quarantena è logica: Cheker non sposta né elimina i file originali.

## Sviluppo

Le istruzioni riproducibili sono nella [guida allo sviluppo](docs/SVILUPPO.md). Il backend è Python/FastAPI; la console è React/TypeScript con Vite. Lock delle dipendenze in `backend/requirements-linux.lock` e `frontend/package-lock.json`.

`start-dev.sh` usa stato separato e porte 8766/5173. `build-linux.sh` ricostruisce e aggiorna la cartella app adiacente: arrestare prima i servizi interessati. Per una build isolata usare il percorso di staging descritto nel manuale tecnico. Non usare dati di produzione nelle prove.

La validazione distingue wheel, UI, suite e prove di durata. I risultati parziali, interrotti o falliti sono conservati come tali; la presenza di molti test superati non prova copertura universale.
