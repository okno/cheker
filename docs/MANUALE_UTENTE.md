# Manuale utente — MCP Integrity Guard

Questo manuale descrive l'applicazione Linux e i controlli disponibili nella console italiana. MCP Integrity Guard registra le configurazioni MCP, lega le approvazioni al loro contenuto e analizza documenti prima dell'uso da parte di un agente. Le analisi e i report rimangono sul dispositivo che esegue l'applicazione.

Il rilevamento delle istruzioni sospette è euristico: può richiedere una revisione di un documento innocuo oppure non riconoscere una manipolazione. **Valido ai controlli** significa che l'analisi si è conclusa senza evidenze rilevate dai controlli implementati. Non è una certificazione di sicurezza, né un verdetto antivirus.

Per rendere effettivo il blocco prima dell'uso, l'agente o il programma chiamante deve utilizzare il gate, `guarded-read` oppure il lettore MCP protetto. La sola apertura della console e il monitoraggio delle cartelle non impediscono ad altri programmi di leggere file o avviare server.

### I formati prioritari, subito

| Formato | Supporto attuale | Limite da conoscere |
|---|---|---|
| **PDF** (`.pdf`) | Sì, per contenuto ispezionabile | Immagini che richiedono OCR, cifratura e contenuti non ispezionabili impediscono un'analisi completa |
| **DOC** (`.doc`) | **No: non supportato, bloccato** | Il formato Word binario precedente non è DOCX |
| **DOCX** (`.docx`) | Sì, entro i limiti dell'estrattore | Immagini che richiedono OCR e oggetti incorporati non ispezionabili possono causare il blocco |
| **XLS** (`.xls`) | **No: non supportato, bloccato** | Il formato Excel binario non è analizzato |
| **XLSX** (`.xlsx`) | **No: non supportato, bloccato** | Il registro per estrattori futuri non include ancora un estrattore XLSX |
| **TXT** (`.txt`) | Sì | Restano i controlli di codifica, contenuto e dimensione |
| **Markdown** (`.md`) | Sì | Testo e frontmatter iniziale sono coperti secondo i limiti descritti sotto |

L'estensione seleziona il formato da analizzare, ma non dimostra che i byte siano validi: cambiare il nome di un file non lo converte. **OCR non è implementato**: anche un PDF con testo leggibile può contenere immagini che impediscono di coprire tutto il documento. Per un formato non supportato, ottenere una conversione attraverso uno strumento fidato e analizzarla come documento distinto; il suo risultato non certifica il file originale né gli elementi persi nella conversione.

## Indice

1. [Installare e avviare](#1-installare-e-avviare)
2. [Accedere e orientarsi nella console](#2-accedere-e-orientarsi-nella-console)
3. [Scoprire, esaminare e approvare componenti MCP](#3-scoprire-esaminare-e-approvare-componenti-mcp)
4. [Analizzare documenti e consultare il registro](#4-analizzare-documenti-e-consultare-il-registro)
5. [Monitorare cartelle](#5-monitorare-cartelle)
6. [Creare una copia testuale da HTML](#6-creare-una-copia-testuale-da-html)
7. [Configurare policy e monitor delle sorgenti](#7-configurare-policy-e-monitor-delle-sorgenti)
8. [Verificare ed esportare l'audit](#8-verificare-ed-esportare-laudit)
9. [Usare la CLI e collegare un agente](#9-usare-la-cli-e-collegare-un-agente)
10. [Risolvere problemi, conservare i dati e chiedere supporto](#10-risolvere-problemi-conservare-i-dati-e-chiedere-supporto)
11. [Domande frequenti](#11-domande-frequenti)

## 1. Installare e avviare

### Requisiti

Servono Linux a 64 bit, architettura x86_64 o aarch64, Python 3.11 o successivo con supporto `venv`, Landlock ABI almeno 3 e la libreria `libseccomp.so.2`. Landlock ABI 3 richiede un kernel Linux 6.2 o successivo con la funzionalità abilitata: il solo numero di versione del kernel non basta. I risultati effettivamente verificati sulle piattaforme sono riportati in [VALIDAZIONE.md](VALIDAZIONE.md).

L'installazione delle dipendenze richiede una connessione di rete. L'esecuzione ordinaria non richiede rete esterna o Node.js. Lo scanner usa processi isolati: se il confinamento necessario non è disponibile, l'analisi viene negata. La diagnostica di installazione deve terminare con `status: READY`, `scan_complete: true` e `sandbox_active: true`.

### Installazione da distribuzione Linux

1. Procurarsi l'archivio Linux della versione desiderata attraverso il canale di distribuzione del progetto e verificarne la provenienza.
2. Estrarlo in una cartella dedicata dell'utente. L'archivio comprende applicazione, UI, script, esempi e documentazione; non contiene token, chiavi, dati personali o un ambiente Python già installato.
3. Aprire un terminale nella cartella estratta che contiene `install-linux.sh` ed eseguire:

   ```bash
   bash install-linux.sh
   ```

4. Attendere il completamento. L'installer verifica i checksum, crea `runtime-linux`, installa le dipendenze e l'applicazione, prepara `data-linux` ed esegue la diagnostica. Un checksum verifica la corrispondenza dei file al manifesto; non sostituisce la verifica dell'identità del distributore.
5. Dalla stessa cartella avviare:

   ```bash
   bash start.sh
   ```

Se l'installazione si interrompe, leggere il messaggio finale e risolvere la causa prima dell'avvio. Per prerequisiti di sistema, aggiornamenti e installazioni gestite vedere il [manuale tecnico](MANUALE_TECNICO.md). Non occorre eseguire l'applicazione come amministratore.

### Installazione nella cartella D:\Cheker

Nell'installazione predisposta su WSL, `D:\Cheker` corrisponde a `/mnt/d/Cheker`. Applicazione e sviluppo sono separati:

| Percorso | Utilizzo |
|---|---|
| `/mnt/d/Cheker/Avvia-Cheker.sh` | Avvio dell'applicazione Linux predisposta |
| `/mnt/d/Cheker/app` | Applicazione installata, UI e runtime Linux |
| `/mnt/d/Cheker/app/data-linux` | Dati persistenti dell'istanza predefinita |
| `/mnt/d/Cheker/dev` | Sorgenti, test e documentazione di sviluppo |

Per l'uso normale:

```bash
cd /mnt/d/Cheker
bash Avvia-Cheker.sh
```

L'ambiente di sviluppo ha un proprio avvio, `dev/start-dev.sh`; non serve per utilizzare l'app installata. Su altri host Linux i percorsi dipendono dalla cartella scelta durante l'estrazione. Negli esempi successivi `start.sh` e `guard.sh` si eseguono dalla cartella dell'applicazione installata.

### Avvio, arresto e cartella dati

La console web è disponibile su `http://127.0.0.1:8765`, nel dispositivo o ambiente Linux in cui gira il servizio. Lo script tenta di aprire il browser dopo aver verificato l'identità del servizio locale. Lasciare aperto il terminale; **Ctrl+C** arresta il servizio. Chiudere una scheda del browser o scegliere **Disconnetti** non arresta il backend.

Per avviare senza aprire automaticamente il browser:

```bash
GUARD_NO_BROWSER=1 bash start.sh
```

Per scegliere una porta diversa:

```bash
bash start.sh --port 8767
```

In questo caso usare `http://127.0.0.1:8767` e configurare la stessa porta nei client e nella CLI. Non esporre la console amministrativa su una rete pubblica: questa distribuzione è progettata per l'accesso locale.

Per impostazione predefinita i dati sono in `data-linux`, sotto la cartella dell'app. La variabile `MCP_GUARD_DATA` permette una destinazione alternativa: applicazione e CLI devono usare la stessa cartella. Un percorso dati diverso può mostrare un inventario vuoto perché rappresenta un'altra istanza. La configurazione di questa variabile e l'avvio automatico con systemd sono descritti nel [manuale tecnico](MANUALE_TECNICO.md); il servizio systemd non viene installato automaticamente.

## 2. Accedere e orientarsi nella console

Al primo avvio vengono creati i dati locali e il token amministrativo. L'accesso automatico passa temporaneamente il token nel frammento dell'URL; la pagina lo rimuove subito dall'indirizzo e lo conserva per la sessione della scheda.

Se compare il modulo di accesso, aprire il file locale `data-linux/api-token` con un editor locale fidato, copiarne il contenuto nel campo **Token di accesso** e premere **Apri la console**. Nella disposizione WSL predefinita il file è `/mnt/d/Cheker/app/data-linux/api-token`. Se si è configurata una cartella dati alternativa, cercarlo lì. Evitare di mostrarlo nel terminale, includerlo in screenshot, incollarlo in chat o inserirlo in comandi salvati nella cronologia. **Disconnetti** rimuove l'accesso memorizzato dalla scheda.

Il token abilita le operazioni amministrative locali. Non esistono account individuali o ruoli distinti nella console; il nome inserito durante un'approvazione è una dichiarazione registrata, non un'autenticazione personale separata.

Il menu principale contiene:

| Pagina | Cosa permette di fare |
|---|---|
| **Panoramica** | Vedere conteggi dei componenti, approvazioni, elementi da esaminare, attività recente e riepilogo delle scansioni |
| **Componenti MCP** | Registrare configurazioni, esaminare differenze, approvare versioni, revocare e mettere in quarantena |
| **File Scanner** | Analizzare documenti, consultare report, monitorare cartelle e creare copie testuali HTML |
| **Registro audit** | Consultare eventi recenti, verificare la catena ed esportare gli eventi disponibili |
| **Policy e controlli** | Modificare azioni e soglie, gestire il monitor delle configurazioni |

**Come funziona** apre la guida sintetica. **Aggiorna dati**, nella barra superiore, aggiorna la panoramica dei dati; alcune sezioni hanno anche un proprio comando di aggiornamento. Sugli schermi stretti il menu si apre dal pulsante nella barra superiore.

La prima installazione mostra un inventario vuoto: non sono inseriti automaticamente componenti o scansioni dimostrativi. I file in `examples` sono esempi da selezionare esplicitamente; non avviano server MCP.

## 3. Scoprire, esaminare e approvare componenti MCP

### Registrare una configurazione

1. Aprire **Componenti MCP** e premere **Scopri componenti**.
2. Nel campo **Percorso del file di configurazione** inserire un percorso assoluto Linux, per esempio `/srv/mcp/config.json`. Su WSL una sorgente in `D:\Documenti` si indica normalmente sotto `/mnt/d/Documenti`.
3. Premere **Analizza sorgente** e attendere l'esito.

Sono supportate configurazioni JSON, JSON5, YAML, TOML e `.env`. La discovery registra la configurazione e le definizioni riconosciute di server, tool, resource e prompt. Non avvia i comandi descritti nel file, non contatta gli endpoint e non interroga automaticamente server remoti. Le definizioni dinamiche devono essere esportate e registrate attraverso l'integrazione scelta.

I limiti principali sono 4 MiB per configurazione, 256 componenti per sorgente e 8 MiB complessivi di contenuto canonico espanso. Una discovery incompleta viene rifiutata nel suo insieme. Se una sorgente già conosciuta cambia e non può più essere analizzata interamente, le approvazioni precedenti non autorizzano quella sorgente modificata.

### Leggere il dettaglio

Usare la ricerca per nome, percorso o fingerprint e il filtro di stato. Aprire una riga per vedere il dettaglio del componente:

| Scheda | Lettura consigliata |
|---|---|
| **Integrità** | Stato, hash RAW, hash canonico, fingerprint semantica, approvazione, evidenze e verifica tramite gate |
| **Variazioni** | Campi modificati, categoria, severità e valori prima/dopo |
| **Contenuto** | Definizione registrata, con valori sensibili riconosciuti mascherati |
| **Versioni** | Cronologia delle versioni registrate |
| **Firma** | Documento di approvazione ed esportazione tramite **Esporta firma** |

L'hash RAW identifica i byte della sorgente. L'hash canonico identifica la definizione normalizzata con il contesto ereditato. La fingerprint semantica serve a distinguere il contenuto dalla sola rappresentazione, ma non dimostra che due testi abbiano un significato equivalente. La mascheratura sullo schermo non elimina quei valori dal calcolo degli hash originali.

Aprire le evidenze e verificare descrizione, severità, posizione e contenuto rilevante. Esaminare in particolare cambiamenti a comandi, argomenti, endpoint, variabili d'ambiente, schemi, capability e istruzioni. L'approvazione riguarda la configurazione: non certifica i byte degli eseguibili, le immagini container o il comportamento futuro dei servizi remoti.

### Approvare una versione precisa

1. Dopo la revisione, premere **Approva versione**.
2. Verificare versione e hash mostrati nel modulo.
3. Compilare **Nome dell'approvatore** e, se utile, **Nota di approvazione (facoltativa)**.
4. Selezionare la conferma di aver esaminato contenuto, variazioni ed evidenze.
5. Premere **Firma e approva**.

La sorgente viene riletta prima della firma. Se cambia nel frattempo, l'operazione viene rifiutata: esaminare la versione corrente e ripetere consapevolmente la revisione. Non riutilizzare una conferma riferita a un contenuto precedente.

Quando cambia il contenuto, lo stato di fiducia o il contesto di policy, il dettaglio aggiornato azzera le conferme e le verifiche precedenti. Un messaggio segnala che occorre esaminare il contesto corrente. Se la copia registrata non supera i controlli d'integrità, l'uso e l'approvazione restano bloccati: conservare le evidenze e seguire la procedura di assistenza.

La firma è legata a componente, versione, hash e policy. Anche una modifica di soli spazi o formattazione può produrre una nuova versione da approvare. Ripristinare i byte di una vecchia versione non ripristina automaticamente la fiducia precedente.

### Rileggere, verificare, revocare e mettere in quarantena

**Rileggi sorgente** aggiorna il componente a partire dal file attuale. Nella scheda **Integrità**, **Interroga gate** verifica nuovamente se la versione richiesta può essere usata. Il risultato indica **Uso consentito dal gate** oppure **Uso negato dal gate**, con motivazione, versione e hash. Non avvia il componente e non autorizza versioni future.

Per togliere fiducia a un componente, scegliere **Revoca**, compilare **Motivo** e premere **Conferma revoca**. Per isolarlo logicamente, scegliere **Quarantena**, compilare il motivo e premere **Conferma quarantena**. Entrambe le operazioni negano l'uso tramite gate e sono registrate nell'audit.

La quarantena è logica: non sposta, cancella o modifica file. Non esiste un pulsante che certifichi o ripari automaticamente il componente. Per consentirne di nuovo l'uso, risolvere la causa nella sorgente, rileggere, esaminare la versione corrente e procedere con una nuova approvazione quando i controlli lo consentono.

## 4. Analizzare documenti e consultare il registro

### Caricamento o percorso locale

In **File Scanner**, nel riquadro **Analizza i tuoi documenti**, scegliere:

- **Carica file**: trascinare uno o più file oppure premere **Scegli file**. La selezione avvia subito le scansioni, una alla volta.
- **Percorso locale**: inserire **Percorso assoluto del documento** e premere **Scansiona file**. Il percorso si riferisce al dispositivo Linux del backend, che deve poter leggere il file.

Il limite ordinario è 10 MiB per file. L'upload del browser rifiuta prima dell'invio un file che supera questo limite: quel rifiuto non produce un report nel registro. Un errore della richiesta e un report con decisione **Bloccato** sono situazioni diverse: nel secondo caso l'elaborazione ha prodotto un report consultabile.

Durante una selezione multipla, **Ferma la coda** lascia terminare il file corrente e salta quelli ancora in attesa. Il riepilogo distingue report salvati, errori e file saltati. Restare nella pagina per seguire tutta la selezione. **Esporta report**, nel riepilogo della selezione, esporta i report di quella selezione, non l'intero registro storico.

### Formati e contenuti esaminati

| Famiglia | Estensioni supportate |
|---|---|
| Testo e Markdown | `.txt`, `.md`, `.log` |
| Dati e configurazioni | `.json`, `.json5`, `.yaml`, `.yml`, `.toml`, `.csv`, `.env` |
| Markup | `.html`, `.htm`, `.xml` |
| Codice come testo | `.py`, `.js`, `.ts`, `.sh`, `.ps1` |
| Documenti strutturati | `.docx`, `.pdf`, quando il contenuto è ispezionabile |

Il codice e gli script vengono letti come contenuto, mai eseguiti per l'analisi. Lo scanner usa regole statiche, strutture di istruzioni, normalizzazione Unicode e decodifiche limitate. Le lingue previste dalle regole correnti sono inglese, italiano, tedesco, francese e spagnolo; non è un servizio di traduzione né una garanzia di riconoscere ogni espressione in quelle lingue.

Le evidenze distinguono tre livelli:

| Livello nel report | Significato |
|---|---|
| `VISIBLE_CONTENT` | Testo del contenuto principale secondo l'estrattore |
| `HIDDEN_CONTENT` | Testo o strutture riconosciute come nascoste, commenti e altri contenuti non principali |
| `METADATA` | Proprietà, attributi, campi e metadati estratti dal formato |

HTML e documenti strutturati possono contenere commenti, nodi nascosti, testo alternativo, note, campi e tipografia anomala. L'estrattore cerca questi contenuti dove il formato lo permette e riporta la loro posizione. La separazione non equivale a una riproduzione esatta di ciò che mostrerebbe ogni browser o lettore PDF.

Il frontmatter iniziale Markdown delimitato da `---` per YAML o `+++` per TOML è analizzato anche come metadati grezzi; l'intero sorgente resta coperto come testo visibile. Un blocco chiuso oltre 64 KiB o 4096 righe interrompe l'analisi. Un delimitatore iniziale senza chiusura resta testo Markdown ordinario, entro i limiti generali.

OCR non è implementato. PDF/DOCX con immagini che richiedono riconoscimento, PDF cifrati, oggetti attivi o incorporati non ispezionabili e formati non supportati possono essere bloccati senza una lettura completa. XLSX, PPTX, EML, MSG, RTF e ODT non sono supportati nella distribuzione corrente; il registro per estrattori futuri non aggiunge automaticamente questi formati. Rinominare un'estensione non converte il documento.

Un DOCX può contenere appendici in altri formati o riferimenti a contenuti esterni. Se Cheker non può ispezionarli completamente, il file risulta **Non analizzabile / Bloccato**; non significa necessariamente che sia infetto. Il report indica `DOCX_UNINSPECTED_PART`, `DOCX_ALTCHUNK_UNSUPPORTED` o `DOCX_EXTERNAL_CONTENT`. Ottenere dalla sorgente una versione autonoma in un formato analizzabile e sottoporla a una nuova scansione. I normali collegamenti vengono esaminati come metadati, senza aprire le destinazioni.

I caratteri Unicode invisibili anomali possono produrre **Da verificare** anche in un documento ordinario. Il report mostra la posizione e rappresenta i caratteri con codici leggibili, per esempio `\U000e0061`. Le tre bandiere regionali RGI complete previste da Unicode sono riconosciute come uso ordinario; altri casi richiedono revisione. Non eliminare automaticamente gli indizi soltanto per ottenere un esito valido: controllare provenienza e significato del contenuto.

### Interpretare l'esito

Ogni report separa **esito**, **decisione**, **severità** e punteggio di rischio. Il punteggio da 0 a 100 è un indicatore determinato dalle regole; non rappresenta una probabilità statistica d'infezione.

| Esito nella UI | Codice | Come comportarsi |
|---|---|---|
| **Valido ai controlli** | `VALID` | Analisi completa senza evidenze rilevate; valutare comunque provenienza e contesto prima dell'uso |
| **Sospetto / infetto** | `INFECTED` | Esaminare le istruzioni o manipolazioni individuate; non è una diagnosi antivirus |
| **Corrotto** | `CORRUPTED` | Struttura o formato malformato; ottenere una copia corretta dalla sorgente |
| **Da verificare** | `REVIEW_REQUIRED` | Sono presenti indizi che richiedono revisione, anche deboli |
| **Non analizzabile** | `UNSCANNABLE` | Controllo incompleto, formato non supportato, limite raggiunto o contenuto non ispezionabile |

La **decisione** usa `ALLOWED` (**Consentito**), `FLAGGED` (**Da verificare**), `QUARANTINED` (**In quarantena**) o `BLOCKED` (**Bloccato**), secondo controlli e policy. Per la lettura protetta non basta un singolo badge positivo: sono richiesti contemporaneamente `VALID`, `ALLOWED`, analisi completa e corrispondenza agli stessi byte. Una scansione incompleta non diventa valida perché non contiene evidenze.

Nel **Risultato della scansione** leggere hash SHA-256, formato, numero di caratteri e segmenti, durata, versione delle regole, evidenze e **Limiti della scansione**. Espandere le evidenze per vedere regola, categoria, livello, posizione, eventuale riga e codifica. **Report JSON** scarica quel singolo report, con il suo ID e i dati disponibili; non scarica una copia del documento originale.

Le decodifiche annidate hanno profondità massima 3 e limiti di espansione. Ogni worker ordinario ha al massimo 512 MiB di memoria, 10 secondi CPU e 12 secondi complessivi; sono disponibili al massimo due worker contemporanei. Un limite raggiunto produce un rifiuto o un'analisi incompleta, non un risultato parziale autorizzato. Le specifiche complete sono nel [manuale tecnico](MANUALE_TECNICO.md) e in [LINUX_SANDBOX.md](LINUX_SANDBOX.md).

### Registro, ricerca, pagine e contatori

**Registro dei file elaborati** conserva ogni scansione salvata. Cercare per nome, percorso o hash, selezionare **Tutti gli esiti** oppure un esito specifico e usare **Precedenti** / **Successivi**. Le pagine contengono fino a **25 scansioni**. Il nome del file o la freccia della riga aprono il report storico. **Aggiorna registro** ricarica i dati; **Azzera filtri** ripristina la vista senza filtri.

I riquadri **File analizzati**, **Sospetti / infetti**, **Corrotti**, **Validi ai controlli**, **Da verificare** e **Non analizzabili** mostrano i totali dell'intero registro. Fare clic su un riquadro filtra le righe per quell'esito. Ricerca e paginazione non riducono i totali globali; il piè di pagina riporta i risultati della selezione corrente.

**Contenuti unici** conta gli SHA-256 distinti, mentre **File analizzati** conta le elaborazioni salvate. Per esempio, caricare tre volte gli stessi byte produce tre scansioni e un solo contenuto unico. Due file con nomi differenti ma byte uguali condividono il contenuto unico. **Decisioni di blocco** è un conteggio delle decisioni: non è una sesta categoria di esito da sommare alle cinque precedenti.

Un report descrive lo snapshot del momento indicato. Se il file cambia, il report precedente non autorizza i nuovi byte. Nel registro non è presente un comando per approvare manualmente un documento e aggirare i controlli di consegna.

## 5. Monitorare cartelle

In **File Scanner**, **Cartelle da analizzare** gestisce il monitor dei documenti. Le cartelle non vengono aggiunte automaticamente.

1. Premere **Aggiungi cartella**.
2. Inserire **Percorso assoluto della cartella**.
3. Se necessario selezionare **Includi le sottocartelle**; senza questa opzione il monitor considera solo la cartella indicata.
4. Premere **Registra cartella**.
5. Verificare che il monitor sia attivo oppure premere **Avvia monitor cartelle**. **Analizza ora** avvia un passaggio manuale anche con il monitor fermo.

Registrare una cartella autorizza la lettura dei suoi file per la scansione. Scegliere percorsi che contengano i documenti pertinenti. Il monitor non segue link simbolici e non sposta i file. La directory dati dell'applicazione e i suoi file riservati sono esclusi.

Ogni cartella dispone dei controlli **Analizza ora**, **Sospendi cartella** / **Abilita cartella**, **Mostra file nel registro** e **Rimuovi dal monitoraggio**. La rimozione riguarda il monitoraggio: i documenti rimangono al loro posto. **Ferma monitor cartelle** arresta il monitor globale senza revocare le radici configurate.

Aprire **Ultimo esito** per leggere file visti, analizzati, invariati, saltati, errori e non più presenti. **Esporta passaggio** scarica il riepilogo di quel passaggio. **Copertura parziale**, **Non riuscito**, **Occupato** o **Interrotto** non attestano che tutti i file della cartella siano stati analizzati.

Il monitor usa eventi del filesystem e riconciliazioni periodiche. Evita nuove scansioni della stessa versione quando il contesto dei controlli è invariato; modifiche a contenuto, regole, policy, parser o runtime possono richiedere nuove analisi. Questo spiega perché un passaggio può mostrare molti file **Invariati** senza altrettanti report nuovi.

Sono ammesse fino a 64 radici; un passaggio ha limiti, fra cui 2000 voci, 128 MiB e 60 secondi. Un albero grande può richiedere ulteriori passaggi. Controllare lo stato effettivo e gli errori, senza dedurre copertura completa dalla sola presenza della cartella nell'elenco. Le radici di questo monitor non configurano automaticamente le radici del lettore MCP protetto.

## 6. Creare una copia testuale da HTML

La funzione **Crea copia testuale**, nella pagina **File Scanner**, usa il profilo `html-text-v1`. È una trasformazione esplicita da HTML a testo UTF-8. L'originale rimane intatto e la copia può perdere markup, metadati, immagini, collegamenti e altre informazioni. Non è una riscrittura semantica generale di contenuti pericolosi.

1. Scegliere **File HTML** e selezionare un `.html` o `.htm`, oppure scegliere **Percorso Linux** e inserire il percorso assoluto.
2. Se si dispone dell'hash atteso, aprire **Verifica un hash atteso (opzionale)** e inserire lo SHA-256 di 64 caratteri esadecimali. La richiesta sarà rifiutata se i byte non corrispondono.
3. Premere **Crea copia testuale**. In questo riquadro la sola selezione del file **non** avvia la trasformazione.
4. Attendere nella pagina l'esito della richiesta. Esaminare separatamente **Trasformazione** e **Consegna**, la motivazione e i collegamenti **Apri report originale** / **Apri report copia**.
5. Se la consegna è consentita, premere **Scarica copia testuale**. Il browser verifica dimensione e SHA-256 e salva gli esatti byte restituiti.

**Copia creata** (`SANITIZED`) indica solo il completamento della trasformazione. La consegna può comunque essere **Negata**. Per consegnare la copia, il servizio deve completare i controlli richiesti, analizzare gli esatti byte prodotti e registrare l'operazione con una policy coerente. Se mancano queste condizioni, non compare un download autorizzato.

Il profilo accetta HTML bilanciato del sottoinsieme documentato, fino a 10 MiB in ingresso; l'uscita è limitata a **256 KiB UTF-8**, incluso il newline finale. Accetta UTF-8 oppure UTF-16 con BOM. Commenti, metadati, script, template, attributi e sottostrutture nascoste riconosciute vengono omessi. Non esegue JavaScript, non recupera risorse esterne e non applica il rendering di un browser. CSS e tag non supportati, strutture incomplete e superamento dei limiti provocano un rifiuto. I dettagli del sottoinsieme sono in [SANITIZZAZIONE.md](SANITIZZAZIONE.md).

Il **Registro delle trasformazioni** contiene metadati, hash, motivazioni, conteggi degli elementi omessi e riferimenti ai report. **Dettagli** apre una singola operazione; **Precedenti** / **Successivi** mostrano pagine di **10 operazioni**. Lo storico non conserva il corpo della copia: dopo una nuova richiesta, la chiusura o il ricaricamento della pagina non è possibile riscaricarla dallo storico. Se serve ancora, occorre ripetere esplicitamente la trasformazione e i controlli.

Se vengono completate entrambe le scansioni, l'originale HTML e la copia aggiungono **due elaborazioni** al registro ordinario, anche quando la consegna finale è negata. La trasformazione non aggiunge una terza scansione né un sesto esito. Se si registra soltanto l'analisi dell'originale, rimane un report. Un hash atteso non corrispondente rifiuta la richiesta prima delle scansioni.

## 7. Configurare policy e monitor delle sorgenti

Aprire **Policy e controlli**. La pagina mostra la versione attiva della policy.

In **Decisioni sulle modifiche** scegliere un'azione per **Modifica del solo formato**, **Modifica semantica**, **Modifica rilevante per la sicurezza** e **Contenuto non approvato**. Le opzioni disponibili sono **Consenti**, **Avvisa**, **Richiedi approvazione**, **Quarantena** e **Blocca**.

Queste azioni classificano la risposta alla modifica. Selezionare **Consenti** non crea un'approvazione firmata per un contenuto che non ne ha una valida; il gate continua a verificare contenuto, versione, policy e audit.

In **Soglie del File Scanner**, impostare **Segnalazione**, **Quarantena** e **Blocco** come interi che rispettano:

```text
1 ≤ Segnalazione < Quarantena < Blocco ≤ 100
```

**Salva policy** registra la nuova versione. **Annulla modifiche** abbandona le modifiche non salvate nel modulo. Le policy sono versionate e firmate; le approvazioni devono essere valide per la policy corrente. Dopo una modifica controllare nuovamente i componenti da approvare e gli esiti del gate. Una schermata obsoleta può ricevere un conflitto: aggiornare e rivedere i valori correnti prima di salvare.

Le soglie non rendono completa una scansione interrotta e non autorizzano la consegna di file con evidenze deboli. Non sono presenti un editor delle regole o un comando per installare estrattori arbitrari dalla UI; modifiche a regole e formati appartengono al processo tecnico di aggiornamento.

Il riquadro **Monitor delle sorgenti** controlla le configurazioni MCP registrate. Il suo interruttore si applica immediatamente ed è separato da **Salva policy**. Verificare **Monitor attivo** / **Monitor inattivo**, sorgenti osservate ed eventuali errori. Questo monitor è distinto da **Cartelle da analizzare**, che riguarda i documenti. Disattivare un monitor non trasforma una vecchia approvazione in un'autorizzazione permanente: il gate rilegge la sorgente quando viene interrogato.

## 8. Verificare ed esportare l'audit

**Registro audit** mostra gli eventi registrati, con tipo, componente, data e numero di sequenza. Espandere un evento per leggere dettagli, hash e collegamento all'evento precedente. **Verifica integrità** controlla la catena; **Aggiorna audit** ricarica la vista.

La conferma **La catena audit è integra** indica che la verifica prevista dal prodotto è riuscita rispetto allo stato disponibile. Se compare **Anomalia nella catena audit**, interrompere l'uso dei componenti interessati e conservare lo stato per la diagnosi. Non cancellare eventi, checkpoint o chiavi per far scomparire l'errore.

I limiti della consultazione sono distinti:

| Operazione | Copertura effettiva |
|---|---|
| Pannello **Registro audit** | Fino agli ultimi **200 eventi**; ricerca e filtro operano sugli eventi caricati, senza paginazione dello storico completo |
| **Esporta audit** | JSON con risultato della verifica e fino agli ultimi **100.000 eventi** |
| Verifica della catena | Controllo dell'intera catena disponibile, distinto dal numero di eventi visualizzati o esportati |

L'esportazione non include necessariamente l'intera cronologia quando supera 100.000 eventi. Il file contiene i più recenti entro il limite, anche se la verifica riporta un numero maggiore di eventi controllati. Non è un backup dei database e non permette di ricostruire da solo tutte le approvazioni e le chiavi.

Gli eventi sono firmati e collegati tramite hash, con un checkpoint firmato. La protezione del dispositivo, della chiave privata e dei backup resta necessaria. Per conservare riferimenti fidati esterni e gestire ripristini o rollback seguire il [manuale tecnico](MANUALE_TECNICO.md).

## 9. Usare la CLI e collegare un agente

Dalla cartella dell'app installata, la CLI espone questi comandi:

```bash
bash guard.sh --help
bash guard.sh discover /srv/mcp/config.json
bash guard.sh list
bash guard.sh scan /srv/documenti/nota.txt
bash guard.sh verify-audit
```

Sostituire i percorsi di esempio con file esistenti. `discover` registra o aggiorna la configurazione; `scan` registra un nuovo report. Quando l'app è aperta, la CLI usa il servizio locale; quando non c'è un listener, può aprire lo stesso archivio con accesso esclusivo. Non avviare istanze indipendenti sullo stesso archivio. Per una porta diversa, l'opzione globale deve precedere il comando:

```bash
bash guard.sh --api-url http://127.0.0.1:8767 list
```

Per interrogare il gate, sostituire ID, hash e versione con quelli della definizione che il client intende realmente usare:

```bash
bash guard.sh gate ID_COMPONENTE --hash HASH_CANONICO --version NUMERO_VERSIONE
```

Questi tre valori sono segnaposto, non dati da copiare letteralmente. Un risultato positivo riguarda la versione verificata; il client deve usare quella definizione e negare l'operazione in caso di errore, risposta incompleta o cambiamento del contenuto.

Per leggere gli stessi byte che hanno superato l'analisi:

```bash
bash guard.sh guarded-read /srv/documenti/nota.txt
```

`guarded-read` emette il contenuto su stdout solo con analisi completa, esito `VALID`, decisione `ALLOWED` e hash corrispondente. In caso di rifiuto stdout è vuoto e stderr riporta un riepilogo senza testo sorgente. Per PDF/DOCX, un eventuale output consentito è il file binario originale, non testo estratto: non inviarlo direttamente a un terminale testuale. Il chiamante deve controllare il codice di uscita e usare esattamente i byte ricevuti.

| Codice di uscita | Significato |
|---|---|
| `0` | Operazione riuscita o uso consentito, secondo il comando |
| `3` | Uso negato oppure audit non valido |
| `2` | Errore operativo |

Il lettore MCP protetto offre `scan_file` e `read_file` su trasporto stdio. Richiede l'app avviata e radici esplicite impostate nel client; non eredita le cartelle selezionate nella UI. `read_file` consegna solo testo UTF-8 entro 256 KiB negli specifici formati ammessi. PDF, DOCX, `.env` e `.log` sono disponibili con `scan_file`, ma non con `read_file`. Seguire [MCP_INTEGRATION.md](MCP_INTEGRATION.md) per la configurazione completa, senza inserire il token nei file del client.

## 10. Risolvere problemi, conservare i dati e chiedere supporto

### Problemi comuni

| Messaggio o situazione | Azione consigliata |
|---|---|
| **Backend non raggiungibile** | Verificare che il terminale dell'app sia aperto, leggere eventuali errori di avvio e controllare indirizzo e porta |
| **Token non valido** | Disconnettere la scheda e usare il token dell'istanza effettiva; non riutilizzare quello di un'altra cartella dati |
| Inventario improvvisamente vuoto | Controllare cartella di avvio e `MCP_GUARD_DATA`; non ricreare approvazioni prima di aver identificato l'istanza corretta |
| Archivio già in uso o porta occupata | Verificare se un'istanza è già avviata; utilizzare quella o arrestarla ordinatamente prima di riavviare. Non cancellare il lock per forzare l'accesso |
| Percorso non disponibile o non leggibile | Usare un percorso Linux assoluto, verificare esistenza e permessi dell'utente del backend e scegliere un file regolare; i flussi protetti rifiutano link e percorsi riservati |
| Contenuto o versione cambiati durante l'approvazione | Rileggere la sorgente, confrontare differenze e hash, poi esaminare di nuovo la versione corrente |
| Policy cambiata durante un'operazione | Ricaricare la policy e rivalutare l'operazione; un download negato non va trattato come riuscito |
| `OCR_REQUIRED`, PDF cifrato o formato non supportato | Procurarsi una versione testuale ispezionabile dalla sorgente fidata e analizzarla separatamente; conservare la distinzione rispetto all'originale |
| `TIME_LIMIT`, limite di memoria o struttura | Leggere i limiti del report. Un file non analizzato non è autorizzato; evitare tentativi ripetuti senza prima comprenderne la causa |
| Worker occupati / `WORKERS_BUSY` | Lasciare terminare le scansioni o i passaggi in corso, poi riprovare la richiesta necessaria |
| Sandbox indisponibile | Eseguire la diagnostica prevista dal manuale tecnico e verificare kernel, Landlock e libseccomp; non disattivare l'isolamento per ottenere un esito positivo |
| Copertura cartella parziale | Aprire **Ultimo esito**, leggere limiti ed errori, correggere le cause e controllare gli ulteriori passaggi |
| `UNSUPPORTED_CSS` o `MALFORMED_HTML` nella copia | Consultare il sottoinsieme HTML supportato; un documento visualizzabile dal browser può essere fuori profilo |
| Copia HTML presente nello storico ma non scaricabile | Lo storico conserva metadati. Se occorre una copia, avviare esplicitamente una nuova trasformazione |
| Hash o dimensione della copia non verificabili nel browser | Non utilizzare una copia ricostruita manualmente dalla risposta; conservare ID e messaggio e verificare browser e installazione |
| Anomalia audit o integrità della copia registrata | Sospendere le operazioni interessate, conservare lo stato e seguire il ripristino tecnico; non eliminare le evidenze |

### Backup e ripristino

I report esportati sono utili per la consultazione, ma **non sostituiscono il backup dell'intera cartella dati**. L'archivio comprende database, token, chiave di firma e checkpoint; copiarne solo una parte può produrre uno stato incoerente.

Per una copia manuale coerente:

1. Identificare la cartella dati effettiva, compresa l'eventuale impostazione `MCP_GUARD_DATA`.
2. Arrestare ordinatamente l'applicazione e gli eventuali client o comandi che scrivono nello stesso archivio. Se il servizio si riavvia automaticamente, seguire prima la procedura systemd del manuale tecnico.
3. Copiare **l'intera cartella dati**, inclusi file nascosti e gli eventuali file SQLite ausiliari presenti, verso una nuova destinazione protetta. Non limitarsi ai soli file con estensione `.sqlite3` e non cancellare manualmente file WAL, checkpoint o lock.
4. Conservare insieme l'identificazione della versione applicativa e le informazioni necessarie a individuare il backup. Conservare separatamente anche le configurazioni MCP sorgenti, con percorsi e versioni coerenti: gli snapshot storici non sostituiscono i file correnti richiesti dal gate. Proteggere le copie almeno quanto i dati originali; possono contenere credenziali e materiale di firma. Scegliere una destinazione esterna alle cartelle del runtime e con permessi di accesso effettivamente applicati dal filesystem.
5. Riavviare l'applicazione e verificare l'audit. Periodicamente verificare anche il recupero della copia in un ambiente separato, secondo il manuale tecnico.

Per il ripristino, tenere l'app arrestata, conservare lo stato problematico e ripristinare un insieme coerente seguendo il [manuale tecnico](MANUALE_TECNICO.md). Non fondere file provenienti da backup differenti e non generare nuove chiavi per far accettare una vecchia cronologia. Il ripristino di dati e checkpoint richiede controlli d'integrità e confronto con i riferimenti fidati disponibili.

La cartella dati può contenere snapshot di configurazioni con segreti originali. Anche i report possono rivelare nomi, percorsi o frammenti di documenti. La mascheratura dei valori riconosciuti non garantisce di rimuovere ogni dato sensibile scritto in testo libero.

### Preparare una richiesta di supporto

Annotare versione dell'applicazione, distribuzione Linux, versione Python, messaggio o codice di errore, ora dell'evento, azione eseguita e ID del report o dell'operazione. Aggiungere l'esito della diagnostica se pertinente. Per una riproduzione, preferire un documento innocuo creato appositamente che mostri lo stesso problema.

Prima di condividere un report JSON o uno screenshot, esaminarlo e rimuovere dati personali, nomi e percorsi riservati. Non condividere `api-token`, chiavi private, cartella dati, backup completi o configurazioni contenenti credenziali. Se si segnala un problema sul repository pubblico, includere soltanto materiale adatto alla pubblicazione. Non esiste un invio automatico dei documenti al supporto dalla console.

Per aggiornamento, diagnosi del runtime, permessi, backup coerenti e gestione del servizio consultare [MANUALE_TECNICO.md](MANUALE_TECNICO.md). I risultati delle prove per ciascuna versione, con limiti e attribuzione, sono in [VALIDAZIONE.md](VALIDAZIONE.md).

## 11. Domande frequenti

**Basta lasciare aperta la dashboard per proteggere tutti gli agenti?**  
No. L'integrazione deve interrogare il gate o usare la lettura protetta prima dell'uso. Un altro programma può ignorare la console e leggere direttamente il filesystem.

**“Sospetto / infetto” significa che ho un virus?**  
No. Indica istruzioni o manipolazioni sospette rilevate nel contenuto. Per malware eseguibile serve anche una protezione adatta a quel tipo di minaccia.

**Posso ignorare un'evidenza debole perché il punteggio è basso?**  
Un'evidenza debole richiede revisione e impedisce la consegna protetta. Il punteggio non sostituisce la lettura di esito, completezza e limiti. La UI non offre un'approvazione manuale dei file per aggirare questa condizione.

**Un file valido oggi rimane valido se cambia domani?**  
Il report riguarda gli esatti byte identificati dal suo SHA-256. Un contenuto cambiato richiede una nuova verifica; il gate e i lettori protetti controllano la versione che viene effettivamente usata.

**Perché devo riapprovare una configurazione dopo aver cambiato solo spazi?**  
Il prodotto registra anche la variazione dei byte della sorgente e lega la fiducia alla versione precisa. La differenza viene classificata come formale, ma non riutilizza automaticamente l'approvazione precedente.

**Revoca e quarantena cancellano qualcosa?**  
No. Negano l'uso attraverso i controlli integrati. I file originali restano dove si trovano.

**Perché il numero di scansioni è maggiore del numero di documenti?**  
Ogni elaborazione salvata conta. Scansioni ripetute e le due analisi di una copia HTML aumentano quel totale; **Contenuti unici** conta invece gli hash distinti.

**Perché trovo più eventi nella verifica audit che nel pannello?**  
La verifica considera la catena disponibile; il pannello carica fino a 200 eventi e l'esportazione fino a 100.000. Sono limiti diversi, non una prova di perdita degli eventi precedenti.

**Posso scaricare una copia HTML dal registro dopo aver chiuso la pagina?**  
No. Lo storico conserva soltanto metadati e collegamenti ai report. Occorre una nuova richiesta esplicita, con nuova trasformazione e controlli.

**Posso usare la copia testuale al posto dell'HTML senza leggerla?**  
La copia può perdere informazioni e non equivale all'originale. Verificarne contenuto e adeguatezza all'uso previsto, anche quando la consegna è consentita.

**Il monitor delle cartelle e quello delle sorgenti sono lo stesso comando?**  
No. Il primo analizza documenti nelle cartelle registrate in **File Scanner**; il secondo controlla le configurazioni MCP e si gestisce da **Policy e controlli**. Le radici del lettore MCP sono configurate separatamente nel client.

**Chi è l'approvatore registrato?**  
È il nome dichiarato da chi opera con il token amministrativo locale. La firma lega l'approvazione al contenuto e alla chiave dell'istanza; non autentica separatamente una persona o un account aziendale.

**Posso estendere formati e lingue dalla console?**  
La console corrente non installa regole o estrattori. Le estensioni richiedono un aggiornamento tecnico verificato; la sola presenza di un registro per formati futuri non rende supportato un nuovo tipo di file.

## Riferimenti

- [Manuale tecnico](MANUALE_TECNICO.md): installazione gestita, struttura, esercizio e recupero.
- [Integrazione MCP](MCP_INTEGRATION.md): configurazione del lettore protetto e relativi limiti.
- [Copia testuale HTML](SANITIZZAZIONE.md): profilo, controlli e codici di rifiuto.
- [Sandbox Linux](LINUX_SANDBOX.md): requisiti e confini dell'isolamento.
- [Registro degli estrattori](ESTRATTORI.md): estensioni tecniche e formati non ancora implementati.
- [Validazione](VALIDAZIONE.md): prove eseguite e loro attribuzione alle versioni.
- [Requisiti e copertura](REQUISITI_COPERTURA.md): confronto fra richiesta originaria e funzionalità realizzate.

I nomi dei controlli di questo manuale sono verificati sui sorgenti della console italiana. I comandi sono confrontati con gli script di distribuzione e con l'help della CLI; il documento non dichiara nuove prove su dati dell'utente.
