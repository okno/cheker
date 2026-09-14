# Isolamento Linux del processo di scansione

`integrity_guard.linux_sandbox` applica Landlock e un filtro seccomp al singolo
processo che analizza i documenti. Non modifica impostazioni globali, non richiede
root e non cambia i limiti di memoria o CPU impostati dal chiamante. L'API web e
il monitor devono rimanere in processi separati: questa funzione è irreversibile.

## Requisiti e disponibilità

Sono previsti Linux nativo a 64 bit, architettura `x86_64` oppure `aarch64`,
Landlock ABI almeno 3 e la libreria di sistema `libseccomp.so.2` con API almeno 3.
La suite è stata eseguita su `x86_64`, kernel WSL2 `6.6.87.2`, Landlock ABI 3 e
libseccomp API 7. L'architettura aarch64 usa le corrispondenti syscall native ma
richiede ancora una verifica di rilascio su hardware aarch64.

L'ABI viene interrogata direttamente: il solo numero di versione del kernel non
prova che Landlock sia abilitato. L'ABI 3 include il controllo della troncatura;
un kernel senza questi diritti viene rifiutato. I dettagli sono definiti nella
[documentazione del kernel per Landlock](https://docs.kernel.org/userspace-api/landlock.html).

```python
from integrity_guard.linux_sandbox import probe_capabilities

capability = probe_capabilities()
# {"available": True, "landlock_abi": 3, "libseccomp_api": 7, "error": None}
```

`available` indica soltanto che le primitive richieste risultano disponibili.
Il caricamento del filtro può ancora fallire per le restrizioni del sistema
ospitante; solo il ritorno positivo di `apply_sandbox` attesta l'installazione
nel processo chiamante. Su un sistema incompatibile il probe restituisce
`available: false` con una spiegazione e la funzione di applicazione solleva
`SandboxUnavailable`. Non esiste una modalità di ripiego dentro questo modulo.

## Confine applicato

Landlock concede lettura soltanto alle directory del runtime Python, delle
dipendenze e del pacchetto del programma. Il chiamante può fornire un elenco
fidato completo tramite `read_roots`; l'elenco sostituisce quello predefinito.
Non si devono derivare queste radici da nomi di file ricevuti, directory da
analizzare o contenuti dei documenti. Cwd, cartella dati, home e directory padre
del progetto non vengono aggiunte automaticamente.

Seccomp usa `EPERM` come azione predefinita e ammette un elenco di syscall
necessarie alla lettura e al calcolo. `open` e `openat` accettano soltanto flag
di lettura; `write` e `writev` accettano soltanto gli FD 1 e 2. Non sono ammessi
creazione di socket, connessioni, exec, fork, clone, duplicazione dei descriptor,
nuove pipe, modifiche ai file, ioctl, ptrace, io_uring o syscall sconosciute.
I filtri verificano l'ABI nativa; un'ABI differente termina il processo.
La struttura del filtro segue le
[interfacce seccomp del kernel](https://docs.kernel.org/userspace-api/seccomp_filter.html)
e le [API di libseccomp](https://github.com/seccomp/libseccomp/blob/main/doc/man/man3/seccomp_rule_add.3).

La funzione imposta `NO_NEW_PRIVS` prima di applicare le restrizioni. Questo flag
impedisce di acquisire nuovi privilegi attraverso exec ed è necessario per
installare filtri seccomp senza privilegi amministrativi. Si veda la
[documentazione del kernel sul flag](https://docs.kernel.org/userspace-api/no_new_privs.html).

Prima dell'applicazione vengono rifiutati processi con più thread, mapping
condivisi preesistenti scrivibili o che possono diventarlo, oppure stdin/stdout/stderr che non siano pipe o `/dev/null` con
la direzione corretta. Gli altri descriptor ereditati vengono chiusi. Restano
aperti soltanto gli ancoraggi `O_PATH` delle radici fidate, senza diritti di
scrittura: mantenerli aperti risolve un problema di lettura riprodotto su
filesystem WSL/9p. Nessun descriptor del documento sorgente viene conservato;
il documento entra attraverso stdin.

Anche un mapping condiviso attualmente di sola lettura può conservare il diritto
di diventare scrivibile tramite `mprotect`. Per questo il controllo non si limita
ai permessi correnti: legge `/proc/self/smaps` e rifiuta i mapping condivisi con
`VmFlags: mw` (`VM_MAYWRITE`), oltre a quelli già scrivibili. L'assenza dei
`VmFlags` o un errore di lettura impedisce l'attivazione del sandbox. I mapping
condivisi immutabili restano consentiti: il runtime della locale, per esempio,
usa `gconv-modules.cache` in sola lettura senza `mw`.

## Integrazione del worker

Avviare un nuovo interprete con `-I`, ambiente minimo e stdin/stdout/stderr tramite
pipe. Impostare prima i limiti del processo. Applicare il confine prima di
importare lo scanner e prima di leggere dati non fidati:

```python
from integrity_guard.linux_sandbox import apply_sandbox, SandboxUnavailable

try:
    boundary = apply_sandbox()
except SandboxUnavailable:
    # Uscire dal worker; il chiamante deve registrare una scansione non riuscita.
    raise SystemExit(70)

from integrity_guard.scanner import Scanner
# Solo ora leggere stdin, analizzare il contenuto e produrre il report.
```

Un successo restituisce `active: true`, `mechanism: "landlock+seccomp"`,
`landlock_abi` e `limitations`. Un'eccezione con `partial: true` segnala che
Landlock era già stato applicato prima del fallimento successivo. Il processo
deve terminare anche quando `partial` è falso. Il chiamante non deve importare
lo scanner, analizzare il documento o dichiarare riuscita la scansione dopo
un fallimento nell'installazione.

## Limiti espliciti

- I contenuti delle radici fidate rimangono leggibili: non conservarvi token,
  credenziali o dati dell'utente. Un runtime compromesso prima dell'avvio non
  viene corretto da questo confine.
- `stat` e altre operazioni di lettura dei metadati restano disponibili. Il
  filesystem e i processi non vengono nascosti con namespace.
- Landlock consente di riaprire in lettura le proprie pipe anonime attraverso
  `/proc/self/fd`; queste espongono i canali già assegnati al worker. L'accesso
  ai descriptor degli altri processi è limitato dalla gerarchia dei domini.
  Questa distinzione è descritta nella sezione
  [Special filesystems di Landlock](https://docs.kernel.org/userspace-api/landlock.html#special-filesystems).
- Memoria e variabili d'ambiente già presenti non vengono cancellate. Il processo
  deve nascere con un ambiente minimo e non deve caricare segreti prima
  dell'isolamento.
- Il supervisore conserva la responsabilità di memoria, CPU, timeout, dimensione
  dell'input e limite dell'output. Il filtro consente la lettura dei limiti ma
  ne impedisce la modifica dal worker.
- L'isolamento riguarda il processo di scansione dei documenti. Non sostituisce
  il controllo di approvazione MCP e non intercetta altre applicazioni del
  sistema che non usano il gate.

## Verifica

```bash
.venv/bin/python -m pytest backend/tests/test_linux_sandbox.py -q
```

Le prove avvengono in subprocessi reali. Verificano letture consentite e negate,
escape tramite symlink, impossibilità di modificare i file, blocco di socket e
connessioni, exec/fork, syscall alternative, chiusura di descriptor ereditati,
vincoli di stdio/thread/mapping e installazioni parziali. Analizzano inoltre
documenti TXT, PDF con testo e DOCX compressi, sia normali sia con istruzioni
sospette, importando lo scanner dopo l'applicazione dei filtri.

Su kernel incompatibili le prove di enforcement vengono esplicitamente saltate
con il motivo restituito dal probe. La validazione di un rilascio Linux deve
includere un host compatibile su cui queste prove siano effettivamente eseguite.
