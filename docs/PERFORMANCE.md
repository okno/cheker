# Audit e SQLite: misure prima dell'ottimizzazione

Misure del 14 settembre 2026, Python 3.13.5, Linux WSL2 x86_64
`6.6.87.2-microsoft-standard-WSL2`. L'audit completo eseguito prima di ogni
registrazione produce un rallentamento concreto: a 5.000 eventi una append
richiede circa 2 secondi. Il costo cumulativo cresce quadraticamente con il
numero di append, perché ciascuna ricontrolla tutta la cronologia precedente.

## Metodo e riproduzione

Ogni scenario usa un processo separato e un nuovo database temporaneo, eliminato
alla fine. Il limite è 90 secondi per scenario, 75 secondi CPU e 1 GiB di memoria.
Il caso più lungo ha richiesto 54 secondi. Nessun database dell'applicazione è
stato aperto o modificato.

Le fixture contengono 0, 100, 1.000 oppure 5.000 eventi con hash, firme Ed25519 e
checkpoint validi, più lo stesso numero di report sintetici nei cinque verdetti.
La preparazione inserisce le righe in una transazione e firma il checkpoint
finale; il verificatore reale controlla poi l'intera catena. Questo evita di
spendere il costo quadratico nella sola preparazione. Ogni scenario esegue anche
tre upload TXT reali attraverso l'API, con Landlock e seccomp attivi.

Sono riportate mediane di tre misure, dopo un riscaldamento del percorso HTTP.
Il server ha zero componenti MCP; la prova isola la crescita dell'audit e del
registro dei file. Il computer era condiviso con altri lavori: i risultati
misurano questa configurazione e non costituiscono una garanzia di latenza.

```bash
.venv/bin/python -u qa/benchmark_audit.py
.venv/bin/python -u qa/benchmark_audit.py \
  --sizes 0,5000 --parent /mnt/d/Cheker/dev/.test-data/performance \
  --contention --output .test-data/performance/drvfs.json
```

Lo script locale è in `qa/benchmark_audit.py`; i campioni,
le verifiche dei contatori e gli hash dei sorgenti sono salvati in `baseline.json`
e `drvfs.json` nella directory `.test-data/performance`. Gli hash di `core.py`, `reports.py`,
`api.py` e `scan_worker.py` sono rimasti identici fra tutti gli scenari misurati.

## Risultati su filesystem Linux ext4

Tutti i tempi sono in millisecondi. L'upload include scanner, persistenza e audit.

| Eventi e report iniziali | Verifica audit | Append audit | GET status | Upload TXT | Statistiche file |
|---:|---:|---:|---:|---:|---:|
| 0 | 0,30 | 1,20 | 2,77 | 393,81 | 0,03 |
| 100 | 42,07 | 37,65 | 39,57 | 578,42 | 0,21 |
| 1.000 | 330,09 | 341,18 | 345,29 | 762,74 | 1,13 |
| 5.000 | 1.861,62 | 2.134,94 | 2.027,73 | 2.984,14 | 17,36 |

A 5.000 eventi i tre campioni di verifica sono 1.777–2.301 ms; le append sono
1.823–2.955 ms. Il campo `duration_ms` dei report mostra una mediana di 517 ms
per gli upload dello stesso scenario: attualmente esclude la successiva
persistenza e la verifica dell'audit e quindi non descrive tutta l'attesa HTTP.

Il picco RSS del processo API passa da 61,11 MiB nel caso vuoto a 65,52 MiB nel
caso da 5.000 report. Database e WAL occupano circa 13,12 MiB a 5.000 righe per
registro, senza contare i file delle chiavi e i piccoli file SHM. Il consumo
misurato non indica una crescita della memoria proporzionale a tutte le firme
deserializzate; il verificatore legge le righe in sequenza.

## Risultati su D: tramite WSL/9p

Nel caso vuoto: verifica 5,87 ms, append 21,45 ms e status 6,82 ms. A 5.000 eventi:
verifica 2.100,66 ms, append 2.196,41 ms, status 2.263,54 ms e upload 2.764,42 ms.
Le statistiche dei file richiedono 261,08 ms e la pagina da 25 report 267,22 ms.
Le fixture condividono lo stesso timestamp: la paginazione include quindi il
costo dell'ordinamento dei valori a pari data e non rappresenta una cronologia
con timestamp tutti distinti.

Una coppia concorrente di richieste status richiede rispettivamente 2.057 e
4.131 ms. Una append concorrente a uno status richiede 1.795 ms, mentre lo
status termina dopo 3.934 ms. Sono singole prove di contesa, non percentili:
confermano l'accodamento sul blocco del `GuardStore`. L'interfaccia richiede lo
status ogni 15 secondi quando visibile, quindi la verifica completa durante
il polling aggiunge lavoro e contesa anche senza nuove operazioni dell'utente.

La lettura della policy, in assenza di eventi `POLICY_CHANGED`, percorre a sua
volta la cronologia: 51,64 ms su ext4 e 230,18 ms su 9p a 5.000 eventi.

## Esattezza e intervento proposto

Tutte le verifiche della catena e dei checkpoint sono riuscite. Totali globali,
cinque verdetti, numero dei contenuti unici e filtri sono esatti a ogni volume.
I tre upload aggiungono tre file validi e un unico nuovo hash; il conteggio degli
eventi cresce esattamente del numero di operazioni eseguite. Non sono state
modificate le query né introdotte statistiche simulate nell'applicazione.

La priorità è riutilizzare un prefisso già verificato per append interne e
status, invalidandolo in modo rigoroso su modifiche della connessione,
`PRAGMA data_version` e contenuto del checkpoint firmato. Una cache basata solo
su mtime o sul numero di eventi non sarebbe sufficiente. La verifica esplicita
dell'audit deve poter ricontrollare tutta la catena. Prima di adottare questa
ottimizzazione occorrono regressioni per manomissioni tramite la stessa
connessione, una connessione esterna, modifica del checkpoint, troncatura,
riavvio e rollback. Il protocollo deve mantenere il comportamento di blocco
in caso di integrità non verificabile.

Un secondo intervento, subordinato alla correttezza della cache, può evitare
la ricerca ripetuta dell'ultimo cambio di policy. Le misure non giustificano
ridurre la frequenza o l'accuratezza dei contatori. Nessuna ottimizzazione
dell'applicazione è stata applicata durante questo audit delle prestazioni.

## Ottimizzazione verificata e congelata per il rilascio

È stata successivamente introdotta una cache del prefisso già verificato.
`verify_audit()` rimane una verifica completa; soltanto `fast=True`, usato dallo
status e dai controlli interni, può riutilizzare una prova invariata.

Ogni riuso confronta `total_changes`, `data_version`, identità e metadati di
database/WAL, bytes effettivi del checkpoint limitati a 4 KiB e chiave caricata.
Controlla anche lo schema reale: tabella audit ordinaria con colonne attese,
assenza di viste temporanee e trigger. Questa verifica non si affida al solo
`schema_version`, che può essere ripristinato manualmente. L'append acquisisce
prima il blocco di scrittura SQLite e promuove il prefisso soltanto dopo commit
e checkpoint riusciti. Errori e rollback cancellano la cache. I batch modificati
rimangono conservativi: vengono verificati integralmente al prossimo utilizzo;
soltanto i refresh senza cambiamenti conservano la prova precedente.

Le 34 regressioni dedicate sono riuscite, comprese modifiche tramite la stessa
connessione e connessioni esterne, mtime ripristinato, checkpoint corrotto e
successivamente ripristinato, rollback, modifiche durante la verifica o durante
il checkpoint, sostituzione del file database, cambio chiave, trigger e viste
con versioni dello schema ripristinate. Le verifiche di snapshot, firme delle
approvazioni, policy e ciclo di vita del gate sono rimaste attive.

La ripetizione dello stesso benchmark a 0 e 5.000 eventi ha prodotto questi
risultati. Tempi in millisecondi, mediana di tre campioni:

| Filesystem, 5.000 eventi | Operazione | Prima | Dopo |
|---|---|---:|---:|
| ext4 | Append audit | 2.134,94 | 2,15 |
| ext4 | GET status | 2.027,73 | 46,35 |
| ext4 | Upload TXT reale | 2.984,14 | 440,89 |
| WSL/9p | Append audit | 2.196,41 | 54,46 |
| WSL/9p | GET status | 2.263,54 | 357,56 |
| WSL/9p | Upload TXT reale | 2.764,42 | 929,31 |

La verifica rapida a 5.000 eventi richiede 0,21 ms su ext4 e 10,50 ms su 9p.
Quella esplicita continua a verificare tutta la catena: 2.133,60 ms e 2.800,32 ms
rispettivamente. Le variazioni delle operazioni non ottimizzate riflettono anche
il carico condiviso del computer durante le prove.

Su 9p una append a database vuoto richiede ora 49,44 ms, rispetto ai 21,45 ms
iniziali: i controlli aggiuntivi dei file hanno un costo fisso, particolarmente
visibile sul filesystem condiviso. A 5.000 eventi lo stesso costo rimane 54,46 ms.
La ricerca della policy continua a essere lineare e richiede 35,26 ms su ext4
e 313,30 ms su 9p; non è stata modificata per questo rilascio.

La contesa status/status scende a 50/87 ms su ext4 e 311/687 ms su 9p. Nella
coppia status/append su 9p le operazioni terminano dopo 453/59 ms. Il picco RSS
è 65,95 MiB su ext4 e 66,11 MiB su 9p. Contatori, verdetti e tutte le 5.007 firme
finali sono corretti; gli upload sono stati eseguiti con sandbox attiva.

I nuovi risultati sono in `.test-data/performance/optimized_ext4.json` e
`optimized_drvfs.json`. Il caso più lungo dura 31,49 secondi. Il sorgente
`core.py` misurato ha SHA-256
`2719e6651542e3773e3f386cd83f7ad13a28351c6a3bb17f72f6f9d8dca8bec7`.

```bash
.venv/bin/python -u qa/benchmark_audit.py \
  --sizes 0,5000 --contention \
  --output .test-data/performance/optimized_ext4.json
.venv/bin/python -u qa/benchmark_audit.py \
  --sizes 0,5000 --parent /mnt/d/Cheker/dev/.test-data/performance \
  --contention --output .test-data/performance/optimized_drvfs.json
.venv/bin/python -m pytest backend/tests/test_core.py \
  backend/tests/test_core_limits.py backend/tests/test_audit_cache.py
```

## Costo della verifica degli snapshot nell'inventario

Una verifica successiva confronta la lettura dell'inventario della baseline
`b728fbb` con la proiezione che controlla gli snapshot prima di mostrarli.
La fixture comprende 101 componenti, 2.101 eventi firmati e 290.029 byte di
contenuto e record, su `/tmp` Linux con il Python 3.13.5 di sviluppo.
Dopo il riscaldamento sono state misurate 15 letture per variante:

| Lettura inventario | Mediana | Massimo |
|---|---:|---:|
| Baseline | 39,25 ms | 51,98 ms |
| Proiezione verificata | 168,80 ms | 301,94 ms |

Il costo aggiuntivo deriva dalla verifica canonica e dal collegamento alla
cronologia firmata. Le regressioni controllano che la raccolta degli eventi
venga eseguita una volta per elenco e due volte per una discovery invariata,
sia con due sia con 101 componenti. Il monitor raccoglie l'inventario una sola
volta per ciclo. La complessità cresce con eventi e byte degli snapshot, senza
ripetere una scansione completa della cronologia per ogni componente.

Il benchmark è stato eseguito mentre erano attive anche le regressioni: i tempi
descrivono quel carico condiviso, non un limite di latenza. I singoli campioni
non sono stati conservati; mediana, massimo e condizioni effettivamente osservati
sono in `.test-data/snapshot-projection-evidence-20260914/benchmark-observed.json`
e `report.json`. Il core misurato ha SHA-256
`cf50c080732dfb725c45a030051ee8a4d3e2da9dc0cea5b0546cb43180ffe395`.
Non sono state ripetute con questa modifica le misure dell'API a 5.000 eventi
riportate sopra.

Riproduttore `qa/benchmark_snapshot_projection.py`, conservato dopo la misura
senza rieseguirlo: verifica gli hash della baseline e del core corrente e usa
soltanto database sintetici temporanei. Richiede il commit baseline nel repository.

```bash
.venv/bin/python qa/benchmark_snapshot_projection.py
```
