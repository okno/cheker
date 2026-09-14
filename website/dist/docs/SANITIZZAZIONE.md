# Copia testuale da HTML

La funzione crea **su richiesta esplicita** una copia UTF-8 di un file `.html` o
`.htm`, secondo il profilo versionato `html-text-v1`. L'originale non viene
riscritto, spostato o cancellato. La copia perde markup, metadati e altri
contenuti esclusi dal profilo: non è una conversione semanticamente equivalente
al documento e non costituisce una bonifica universale delle prompt injection.

Nella pagina File Scanner, la sezione **Copie testuali HTML** permette di
selezionare un file oppure indicarne il percorso assoluto Linux. L'operazione è
distinta dalla scansione ordinaria. Watcher, gate e lettori MCP non trasformano
automaticamente i documenti.

## Stato corrente della verifica: `d59523d2…`

Il candidato corretto ha wheel SHA-256
`d59523d28b11da7c7be670e464ed4d99e70899e822e53c900d4aa6f09c6a0973`
e tar verificato
`88c833583a2d8fe66705372c672ed82a547d593bdb68c81a2295c41a51e3de0e`.
Rispetto al precedente `891d7fc8…` cambia soltanto `html_text.py`; la UI è
invariata. L’installazione Linux pulita è **PASS**, con diagnostica `READY`,
analisi completa e sandbox attiva su Python 3.13.5. Evidenza:
`dev/.test-data/release-parser-compat.json`.

La QA mirata del runtime installato ha superato **27 controlli browser e 10
host, 37 complessivi**. Il commento valido di 16.000 caratteri seguito da
`<p>Notes</p>` produce `SANITIZED`/`ALLOWED`: il download desktop e mobile
contiene esattamente `Notes` seguito da LF, sei byte, SHA-256
`38732073f309589131fec63f417896537e63d27fc29fcf7c60d5f47379f0887a`.
Originale e copia hanno due report distinti e completi. Il commento di 70.000
caratteri viene negato con `STRUCTURE_LIMIT`, senza copia o download. Le due
operazioni generano tre report ordinari e totali coerenti con l’API; lo storico
contiene solo metadati. Nessun errore JavaScript, console o API, né overflow a
1440 e 360 pixel; backend della prova chiuso. Evidenza:
`dev/.test-data/parser-compat-ui-20260914/REPORT.md`. La precedente suite browser
da 74 controlli non è stata ripetuta e rimane attribuita al wheel `891d7fc8…`.

L’upgrade da `ea5e9d26…` al candidato corretto ha superato **53 controlli** in
una sola esecuzione, preservando file di stato, chiave, token, checkpoint,
componenti, approvazione, report, radice in pausa e policy. Due nuove copie,
inclusa quella con un commento di 16.384 byte, portano il totale a cinque report
e due operazioni; audit valido, GET senza payload, diagnostica `READY` e
processi chiusi. Evidenza:
`dev/.test-data/upgrade-parser-compat-20260914/REPORT.md`.

La suite completa Python 3.13 è **PASS**: 1.036 test backend, uno SKIP Windows,
28 metodi QA e 43 sottocasi, senza fallimenti, in 490,162 secondi. Sono passate
anche le due regressioni del processo isolato reale per i commenti da 16.000
e 70.000 caratteri. Evidenza: `dev/.test-data/linux-parser-compat-result.json`.
La suite installata Python 3.11 è **PASS**: 1.036 test superati e uno SKIP Windows, senza fallimenti, in 561,785 secondi; `dev/.test-data/python311-parser-compat/backend-tests.xml`. Anche il collaudo prolungato
è **in corso, non PASS**: avviato
il 14 settembre alle 19:33:39 UTC, PID 54430 e `start_ticks` 9584616, sul runtime
immutabile `/tmp/cheker-linux-release-0kslmc33/mcp-integrity-guard/runtime-linux/bin/python`.
Dati separati in `/tmp/cheker-linux-finalrun/.test-data/d595-release`, controllo
in `d595-control`, conclusione dell’esercizio pianificata entro le 02:25 UTC del
15 settembre. Provenienza: `dev/.test-data/soak-d595-launch.json`. L’avvio mentre
entrambe le suite erano in corso non costituisce una convalida del rilascio. La baseline
r3 precedente rimane distinta. I risultati storici e i fallimenti di `891d7fc8…`
sono conservati sotto e in [VALIDAZIONE.md](VALIDAZIONE.md).

## Trasformazione e autorizzazione sono separate

Il servizio esegue tre stadi sequenziali:

1. Acquisisce i byte dell'originale e ne registra una scansione ordinaria.
2. Se quella scansione è completa, un worker Linux confinato produce la copia
   testuale. Il parent verifica protocollo, completamento, dimensioni, UTF-8 e
   hash dei byte ricevuti.
3. Una **nuova scansione ordinaria degli esatti byte della copia** determina se
   il contenuto può essere consegnato.

Un originale classificato sospetto può quindi essere trasformato, purché la sua
analisi sia completa. Il suo report resta invariato. Un originale non analizzato
completamente interrompe il flusso prima della trasformazione.

| Campo dell'operazione | Valori | Significato |
|---|---|---|
| `transformation_status` | `SANITIZED`, `FAILED` | Il profilo ha prodotto una copia, oppure non ha completato la trasformazione. |
| `delivery_status` | `ALLOWED`, `DENIED` | La risposta corrente può contenere i byte della copia, oppure li esclude. |

`SANITIZED` **non autorizza il contenuto**. È possibile ottenere
`SANITIZED` insieme a `DENIED`: per esempio, un'istruzione sospetta ancora
presente nel testo visibile resta nella copia e viene rilevata dalla seconda
scansione. Il trasformatore non cerca di riscrivere o reinterpretare quelle
istruzioni.

La consegna richiede simultaneamente:

- hash SHA-256 e dimensione corrispondenti agli esatti byte prodotti;
- seconda analisi completa e non troncata;
- verdetto `VALID`, stato `ALLOWED` e lista dei finding vuota;
- assenza dei contenuti sensibili specificamente esclusi dal servizio;
- stessa versione di policy fra il report della copia e la registrazione finale;
- registrazione riuscita dell'operazione e del relativo evento audit.

La verifica della policy avviene nuovamente al termine. Se cambia, la consegna è
negata con `POLICY_CHANGED`. Un problema di registrazione restituisce HTTP 503
senza copia. Gli stati e i protocolli dello scanner ordinario e del gate non
acquisiscono alcuna eccezione per `SANITIZED`.

## Profilo HTML supportato

Sono ammessi documenti o frammenti HTML bilanciati, con tag ordinari per testo,
paragrafi, titoli, elenchi, tabelle e formattazione inline. Sono riconosciuti i
normali elementi senza chiusura esplicita, come `br`, `hr`, `img`, `meta`, `link`,
`wbr`, `col` e `source`. Il doctype ammesso è `<!doctype html>`.

Il profilo decodifica i riferimenti a caratteri HTML, comprime gli spazi del
testo ordinario, inserisce separatori LF per gli elementi di blocco e tratta
separatamente il testo in `pre`. L'output usa UTF-8 senza BOM e termina con LF.
L'ingresso può essere UTF-8, con o senza BOM, oppure UTF-16 con BOM.

Vengono esclusi:

- commenti HTML e attributi, compresi URL, alt text e altri metadati;
- contenuti di `head`, `title`, `meta` e `link`;
- contenuti di `script`, `template` e `noscript`;
- immagini e nodi `source`, senza recuperare o riconoscere il loro contenuto;
- sottostrutture marcate `hidden`, `aria-hidden="true"` o dalle dichiarazioni
  inline di occultamento riconosciute qui sotto.

La presenza dell'attributo HTML `hidden` è sufficiente, anche quando il suo
valore testuale è `false`. Un elemento annidato sotto una sottostruttura esclusa
rimane escluso.

### CSS: sottoinsieme letterale, nessun rendering

Non vengono interpretati fogli di stile o script. I blocchi `style`, i link a
fogli di stile esterni e le dichiarazioni inline fuori dal seguente elenco
producono `UNSUPPORTED_CSS`.

| Proprietà inline | Valori che escludono il nodo | Altri valori ammessi |
|---|---|---|
| `display` | `none` | `block`, `inline`, `inline-block` |
| `visibility` | `hidden`, `collapse` | `visible` |
| `opacity` | `0`, `0.0` | `1`, `1.0` |
| `font-size` | `0`, `0px`, `0pt`, `0em`, `1px`, `1pt` | Nessuno |

Le dichiarazioni sono separate da punto e virgola; proprietà duplicate vengono
rifiutate. Colori, selettori, cascata, `!important`, calcoli e altre sintassi CSS
non sono supportati da questa trasformazione. L'elenco non descrive un browser
né garantisce che il testo copiato coincida con quello visibile in ogni ambiente.

Tag sconosciuti, elementi complessi come SVG o iframe, chiusure implicite o non
bilanciate, attributi duplicati e dichiarazioni non ammesse vengono rifiutati.
Un HTML visualizzato correttamente da un browser può quindi non appartenere al
profilo. In tal caso non viene restituito un risultato parziale.

## Limiti e worker Linux

| Limite | Valore |
|---|---|
| Snapshot di ingresso | 10 MiB |
| Copia UTF-8, compreso LF finale | 256 KiB |
| Profondità HTML | 128 |
| Eventi strutturali del parser | 20.000 |
| Token HTML o buffer incompleto | 64 Ki caratteri |
| Budget interno di trasformazione | 8 secondi |
| Memoria per worker | 512 MiB |
| CPU per worker | 10 secondi |
| Tempo totale del singolo worker nel parent | 12 secondi |
| stdout + stderr del worker di trasformazione | 1 MiB |

Il limite di trasporto della trasformazione è inferiore al limite ordinario di
4 MiB dello scanner. Il suo protocollo separato include testo in Base64; quello
dello scanner continua a trasmettere report senza contenuto sorgente.

Il processo viene avviato con Python `-I` e ambiente minimo. I limiti di risorse,
Landlock e seccomp vengono applicati **prima della prima lettura dello snapshot**.
Servono Linux a 64 bit, Landlock ABI almeno 3 e libseccomp, come descritto in
[LINUX_SANDBOX.md](LINUX_SANDBOX.md). Senza il confinamento richiesto non viene
prodotta una copia utilizzabile. Scansioni e trasformazione condividono i due
slot per worker; ogni stadio rilascia il proprio slot prima del successivo.

Nessun documento, comando, JavaScript o risorsa esterna viene eseguito o
recuperato. Rifiuti e diagnostiche del nuovo worker usano codici e messaggi fissi,
senza riportare frammenti del documento.

## Originale, copia e registro

Un'operazione contiene `input_sha256`, `output_sha256`, dimensioni,
`input_report_id`, `output_report_id`, profilo, stati e motivazione. Gli ID
collegano le due elaborazioni ai report ordinari. Se il flusso si interrompe,
l'hash della copia o il suo report possono essere assenti.

Una richiesta che completa entrambe le scansioni aggiunge **due elaborazioni**
al registro. L'operazione di trasformazione non è una terza scansione e non
introduce un nuovo verdetto fra i cinque esistenti. I contenuti unici continuano
a essere contati per hash distinti, non per numero di copie richieste.

I contatori `omitted_counts` riportano commenti, radici di sottostrutture nascoste,
metadati, contenuti attivi, nodi non testuali e attributi esclusi. I discendenti di
una sottostruttura già esclusa non sono contati nuovamente come altre radici.
Non sono una misura dell'efficacia della bonifica.

La tabella `sanitizations` in `scans.sqlite3` conserva **solo metadati**.
L'evento `FILE_SANITIZATION_RECORDED` collega operazione, hash e report nell'audit.
Il corpo della copia non viene aggiunto ai database, ai report o all'audit.

Solo la risposta POST corrente può contenere il testo. Il browser può convertirlo
in un file `nome.sanitized.txt`; lo storico non permette di scaricare nuovamente
la copia. Dopo un ricaricamento o una nuova sessione occorre ripetere
esplicitamente l'operazione. Una registrazione storica `ALLOWED` descrive quella
richiesta, non un'autorizzazione riutilizzabile.

## API

Tutte le rotte richiedono l'autenticazione amministrativa locale. Per la
connessione verificata e il token locale seguire il [README](../README.md),
senza inserire token in documenti o esempi condivisi.

| Rotta | Richiesta o risposta |
|---|---|
| `POST /api/sanitizations/html` | Multipart con `file` e campo facoltativo `expected_sha256`. |
| `POST /api/sanitizations/html/path` | JSON con `path` e `expected_sha256` facoltativo. |
| `GET /api/sanitizations?limit=50&offset=0` | Elenco dei soli metadati; limite ammesso da 1 a 100. |
| `GET /api/sanitizations/{id}` | Metadati della singola operazione, mai contenuto. |

Esempio del solo corpo della richiesta per un percorso Linux:

```json
{"path":"/srv/documenti/riunione.html"}
```

`expected_sha256`, quando fornito, deve essere un SHA-256 esadecimale minuscolo
di 64 caratteri. Se lo snapshot leggibile non corrisponde, il servizio restituisce
HTTP 409 prima della scansione e della trasformazione.

La risposta POST include i metadati e `delivery`. Solo dopo tutti i controlli
positivi, `delivery` contiene:

```text
encoding: "base64"
media_type: "text/plain;charset=utf-8"
data_base64: i byte verificati codificati in Base64
```

Negli altri casi `delivery` è `null`. Le risposte GET non contengono questo campo.
**HTTP 200 da solo non autorizza alcuna consegna**: il client deve leggere
`delivery_status` e verificare la presenza del payload previsto. Un errore HTTP,
una risposta incompleta o un fallimento di registrazione non devono produrre un
download. Il client deve usare i byte decodificati, senza modificarli o
ricodificarli prima del salvataggio.

Fra le motivazioni possibili figurano `INPUT_INCOMPLETE`,
`UNSUPPORTED_TRANSFORMATION`, `SOURCE_UNAVAILABLE`, `UNSUPPORTED_CSS`,
`MALFORMED_HTML`, `EMPTY_OUTPUT`, `OUTPUT_SIZE_LIMIT`, `WORKERS_BUSY`,
`OUTPUT_INCOMPLETE`, `OUTPUT_REQUIRES_REVIEW`, `SENSITIVE_CONTENT` e
`POLICY_CHANGED`. L'esito positivo usa `COPY_PASSED_CHECKS`.

## Percorsi e contenuti esclusi

La variante per percorso è disponibile su Linux. Apre ogni componente del
percorso senza seguire link simbolici, accetta solo file regolari con un unico
hard link, esclude la cartella dati dell'istanza corrente e controlla che il file
non cambi durante la lettura. Un percorso non utilizzabile registra un esito
negato; non viene trattato come una copia riuscita.

Anche per upload, il servizio nega la consegna quando riconosce blocchi di chiavi
private PEM o il token dell'istanza corrente nell'ingresso o nell'uscita. Questi
controlli specifici non equivalgono a riconoscere qualsiasi segreto scritto nel
documento.

Non sono implementate trasformazioni per PDF, DOCX, Markdown o altri formati,
né OCR, esecuzione JavaScript, rendering browser o recupero di risorse esterne.
Il rilevamento delle istruzioni resta euristico: una copia autorizzata ai
controlli implementati non è una certificazione di sicurezza universale.

## Implementazione e verifica

Il profilo e il worker sono in `backend/integrity_guard/html_text.py`,
`sanitize_worker.py` e `sanitize_protocol.py`; il servizio è in `sanitizer.py`.
Le rotte sono definite in `api.py` e l'interfaccia in
`frontend/src/Sanitizations.tsx`.

I test dei tre moduli coprono conversione, struttura, limiti, schema del
protocollo, worker Linux reale e successiva scansione degli esatti byte. Il
risultato consolidato della prima serie su Python 3.13 è **113 test superati, senza skip**. Questa prova
precede il difetto di compatibilità 3.11 descritto sotto e non valida la correzione
successiva. Il primo errore sul limite di un commento lungo è
conservato separatamente dal risultato riuscito in
`dev/.test-data/sanitization-modules-20260914/report.json` e relativi JUnit.
Quella serie conserva due esecuzioni fallite, con 103/104 e 112/113 casi
superati: precedono il controllo della lunghezza dei token nei callback del
parser. Non vengono cancellate né confuse con il successivo difetto di
buffering specifico di Python 3.11.
Per servizio, API, interfaccia e rilascio fa fede il registro complessivo
[VALIDAZIONE.md](VALIDAZIONE.md).

### Compatibilità Python 3.11: prove storiche del candidato precedente

La suite completa sul wheel precedente `891d7fc8…` ha concluso su Python 3.11.16
con **995 test superati, un fallimento e uno skip Windows**, 997 casi in
659,989 secondi. Le prove sono preservate in
`dev/.test-data/python311-final-features/results.json` e `backend-tests.xml`.
I PASS ottenuti su Python 3.13, browser e installazione del medesimo wheel restano
attribuiti a esso e non cancellano questo fallimento.

Le tracce `parser-buffer-python311.json` e `parser-buffer-python313.json`
confermano una differenza nel buffering di `HTMLParser` durante `feed()` a
blocchi. Su 3.11.16 una parte dei dati resta in `_pending`; il metodo applicativo
`finish` controllava `rawdata` prima di chiamare `close()`. Con lo stesso modulo,
un commento completo di 16.000 caratteri veniva erroneamente rifiutato su 3.11;
un commento di 70.000 caratteri, oltre il limite, produceva `MALFORMED_HTML`
invece del previsto `STRUCTURE_LIMIT`. Su 3.13 i due esiti erano rispettivamente
trasformazione riuscita e rifiuto per limite.

Nessuna consegna impropria è stata osservata nelle prove. La correzione riguarda
il prodotto e conserva le asserzioni sui commenti validi e sui limiti.
`html_text.py` corretto è congelato con SHA-256
`974e9236bf075ee97312b8de5e5758c20718231f21201e447ecad08734b5cb9b`.
In ambienti temporanei separati, 85 test HTML, inclusi 38 nuovi casi, sono
superati su Python 3.11 in 0,769 secondi e su Python 3.13 in 0,845 secondi.
Evidenza: `dev/.test-data/html-parser-compatibility-20260914/results.json`.
Queste prove mirate non sono una suite completa installata e non hanno avviato
un worker dai pacchetti temporanei. Le due nuove regressioni del worker reale
sono poi passate nella suite completa Python 3.13 del candidato corretto;
anche la suite Python 3.11 è poi passata. I due casi sono verificati anche nella QA
browser mirata del candidato corretto.

Il candidato corretto `d59523d2…` contiene 26 file applicativi e cambia solo
`html_text.py` rispetto a `891d7fc8…`; le verifiche correnti sono descritte nella
sezione iniziale. Il precedente `891d7fc8…` è stato sostituito come candidato e
non verrà usato per la prova prolungata finale. Le sue prove e il fallimento
Python 3.11 restano conservati con la loro attribuzione.

### Prova breve storica del collaudo delle copie su `891d7fc8…`

Il nuovo harness separato, commit `6587f4e`, ha superato 16 metodi e 25 sottocasi.
Una sola esecuzione breve su Python 3.13.5 e wheel `891d7fc8…` è conclusa PASS in
181,834 secondi: 38 copie richieste, nove riavvii, 312 report complessivi con i
casi ordinari della baseline, 118 pagine di metadati controllate e 362 verifiche
di report storici, comprese riletture dopo riavvio. Bytes, dimensioni, SHA-256,
collegamenti dei report e GET senza contenuto sono risultati coerenti; nessun
processo posseduto è rimasto attivo fra quelli osservati. Evidenze:
`dev/.test-data/soak-features-selftest-20260914/REPORT.md` e `result.json`.
Questa verifica breve non sostituisce la suite completa 3.11 del candidato corretto,
ora passata, né la sua prova lunga, ancora in corso.
