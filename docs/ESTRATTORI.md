# Registro degli estrattori fidati

Il §11 dei requisiti chiede di predisporre nuovi formati senza considerarli già
supportati. `extractor_registry.py` offre un registro per estrattori inclusi
esplicitamente nel codice fidato del wheel. La release consegnata con wheel `039e0fd8…` ha un bootstrap vuoto. Il sorgente
aggiornato il 15 settembre 2026 registra invece il solo profilo XLSX statico,
destinato a un nuovo candidato: questa aggiunta non viene attribuita alla release
039e. PPTX, EML, MSG, RTF e ODT restano non supportati. Gli estrattori incorporati
continuano a usare il percorso già previsto in `extraction.py`.

Non esistono installazione di plugin dall'interfaccia, caricamento da documenti,
ricerca in cartelle utente, entry point automatici o variabili d'ambiente per
scegliere moduli. Aggiungere un estrattore richiede una modifica al codice fidato,
test, un nuovo pacchetto e il riavvio dell'applicazione e dei suoi processi. Il
registro descrive quel codice; non decide se un documento è sicuro e non concede
autorizzazioni.

## Contratto per lo sviluppatore

Ogni istanza di `ExtractorRegistry` espone:

```python
register_extractor(format, extensions, version, handler, dependencies=())
freeze()
lookup(extension)
descriptors()
fingerprint()
```

`register_extractor` restituisce un `RegisteredExtractor` immutabile con campi
`format`, `extensions`, `version`, `handler` e `dependencies`. Il formato è un
nome breve; le estensioni sono una lista o tupla di suffissi senza wildcard,
normalizzati in minuscolo con il punto iniziale. Il nome e le estensioni dei
formati incorporati sono riservati; nomi, estensioni e dipendenze duplicati sono
rifiutati. La versione deve essere esplicita e non vuota.

Il gestore è una funzione sincrona definita a livello di modulo, con esattamente
tre parametri posizionali:

```python
def extract_example(data: bytes, filename: str, budget: Budget) -> Extraction:
    ...
```

Il modulo deve appartenere al pacchetto `integrity_guard`, avere un file sorgente
Python regolare identificabile nella directory del pacchetto e corrispondere al
file della funzione effettiva. Il registro riceve un oggetto funzione: non
importa un gestore a partire da una stringa. Funzioni locali, lambda, generatori,
coroutine e oggetti callable generici non soddisfano il contratto.

Il gestore usa il `Budget` comune e aggiunge i segmenti tramite `budget.add`,
indicando posizione e livello di estrazione. Il chiamante controlla anche tipo
del risultato, formato, contabilità, limiti e completezza; un errore o un
risultato incompleto interrompe l'analisi. Il normale scanner esamina poi il
testo estratto. Registrare un formato non evita questa analisi.

`dependencies` contiene nomi di distribuzioni Python installate, per esempio
`["pypdf"]`, non specifiche di importazione o vincoli come `pypdf>=6`. I nomi
sono normalizzati e le versioni vengono lette dai metadati installati. Una
dipendenza mancante o senza versione identificabile fa fallire la registrazione
o la successiva lettura dei descrittori. La dichiarazione delle dipendenze
rimane responsabilità di chi sviluppa l'estrattore; il registro non ricostruisce
automaticamente tutti gli import transitivi.

## Bootstrap riproducibile nel worker

`trusted_extractors.register_all(registry)` è l'unico elenco statico previsto per
la produzione. Nel nuovo sorgente contiene un import letterale di
`xlsx_extractor.extract_xlsx` e la registrazione esplicita:

```python
registry.register_extractor("xlsx", (".xlsx",), "1.0.0", extract_xlsx, ("defusedxml",))
```

`defusedxml` è già una dipendenza del runtime, fissata a `0.7.1` nel lock. Non
viene aggiunta una libreria Office né caricata una configurazione dal documento.
Per aggiungere altri gestori occorre includerli nel wheel e registrarli con lo
stesso percorso esplicito. È una modifica del pacchetto, non una configurazione
fornita dall’utente o da un documento.

Il solo XLSX Transitional statico è previsto: celle, shared strings e metadati
entro limiti dichiarati. Formule, nomi definiti, media/OCR, macro, oggetti
incorporati, dati esterni e strutture non ispezionate restano bloccati. Anche
XLSM, XLSB e XLS legacy sono fuori profilo. Vedere il
[profilo tecnico XLSX](MANUALE_TECNICO.md#profilo-xlsx-statico-del-nuovo-sorgente).
Registrare `.xlsx` non abilita i formati futuri né rende ammissibile ogni file
con quella estensione.

`get_registry()` esegue il bootstrap una volta per processo, verifica i
descrittori, congela l'istanza e la pubblica solo dopo il successo. Un errore non
pubblica un registro parziale. Le operazioni di consultazione richiedono il
congelamento; dopo di esso nessuna nuova registrazione è ammessa.
`lookup_extractor(extension)` e `registry_fingerprint()` usano questa istanza.
Un'estensione sconosciuta, vuota o non valida restituisce `None` e resta nel
normale percorso di formato non supportato.

Nel worker Linux il bootstrap avviene dopo l'attivazione del confinamento e
prima di leggere i byte del documento. Il processo nuovo ricostruisce il
registro dal medesimo pacchetto: una registrazione fatta soltanto nella memoria
del processo padre non abilita un formato nel worker. Non si devono aggiungere
effetti collaterali, accessi alla rete o letture di configurazioni utente al
bootstrap. Restano applicati limiti e confinamento del normale scanner.

## Identità del codice e cache del monitor

`descriptors()` restituisce un manifesto JSON con `schema_version: 1`, i moduli
`registry` e `bootstrap`, una lista ordinata `extractors` e `package_sources`. Per ogni modulo
statico include nome, percorso relativo e SHA-256 del file sorgente. Ogni
estrattore aggiunge formato, estensioni, versione, modulo e nome della funzione,
SHA-256 del suo file effettivo e versioni delle dipendenze dichiarate.

`package_sources` comprende inoltre l'elenco ordinato di tutti i file `.py` e
`.json` del pacchetto `integrity_guard`, anche nelle sottocartelle: ogni voce ha
`file` relativo e `sha256`; `total_size_bytes` indica i byte complessivi.
Sono esclusi `__pycache__` e i file `.pyc`. In questo modo una modifica a un
helper o a una risorsa JSON cambia il fingerprint anche se il file principale
del gestore e la sua versione dichiarata rimangono uguali. Non occorre elencare
manualmente gli helper interni come dipendenze. Per le distribuzioni Python
esterne rimane necessaria la dichiarazione delle versioni usate.

`fingerprint()` calcola SHA-256 sulla serializzazione deterministica del
manifesto. Ogni lettura ricalcola gli hash del codice e risolve le versioni:
non riusa un vecchio descrittore quando un sorgente o una dipendenza non è più
leggibile. Il monitor include questo valore nel contesto delle scansioni,
insieme ai suoi altri parametri; una variazione invalida la corrispondenza della
cache e richiede una nuova analisi. Non abilita fiducia automatica nei file.

I percorsi relativi evitano di legare il manifesto alla directory di
installazione. L'hash identifica i file sorgenti distribuiti e le versioni
dichiarate, non certifica l'autore del plugin né costituisce attestazione di ogni
istruzione caricata in memoria. L'installazione del wheel è parte del codice
fidato; non è previsto modificarla mentre l'app è in esecuzione. Moduli senza
sorgente `.py`, caricamenti da archivi e percorsi simbolici non identificabili
sono rifiutati. I controlli correnti sono destinati alla distribuzione Linux.

Il registro limita le registrazioni a 64, le estensioni e le dipendenze a 32 per
gestore. L'inventario del pacchetto ammette al massimo 256 sorgenti per 4 MiB
complessivi; la visita è limitata anche a 1.024 voci e 16 livelli di sottocartelle.
Le directory vengono aperte senza seguire link, i file devono essere regolari
e gli hash provengono da letture stabili. Un secondo controllo dell'inventario
rifiuta variazioni rilevate durante la raccolta. Un limite superato, un link o
un sorgente non stabile interrompe il calcolo senza restituire un fingerprint
precedente. La visita enumera il percorso della directory, verificandone
l'identità rispetto al descrittore aperto prima e dopo la visita; i figli sono
aperti relativamente a quel descrittore e senza seguire link. Non richiede di
abilitare la duplicazione dei descrittori nel sandbox.
Gli errori sono
`ExtractorRegistryError`, sottoclasse di `ValueError`, con un codice stabile e
messaggio fisso senza testo del documento. Questi limiti riguardano il registro;
rimangono in vigore anche i limiti separati dei documenti e dei worker.

## Verifica

`backend/tests/test_extractor_registry.py` usa istanze isolate e moduli di
fixture temporanei, senza installare formati nel registro globale. Verifica
esecuzione del contratto `Budget`, collisioni, metadati, sorgenti e dipendenze,
congelamento, variazioni del fingerprint e bootstrap in processi Python nuovi.
Una regressione dedicata verifica che cambiare soltanto un helper confezionato
invalida il fingerprint, mantenendo invariati gestore e versione.
Le prove del nuovo XLSX sono in `backend/tests/test_xlsx_extractor.py` e includono
worker reali per documento statico, formula innocua e contenuto fuori profilo.
Il registro viene verificato anche in processi nuovi con la registrazione
statica XLSX presente; le istanze isolate dei test non installano plugin utente.
Le prove dei formati e della loro integrazione nel worker devono accompagnare
ogni modifica del bootstrap. L’esito della release 039e non qualifica questa
aggiunta: i test del nuovo candidato vanno attribuiti separatamente.
