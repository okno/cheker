# Cheker per Windows

Il pacchetto Windows x64 apre una finestra dedicata con la dashboard. Il motore di analisi gira nella distribuzione Linux predefinita di **WSL 2**: le protezioni Linux e i limiti dei formati rimangono gli stessi. Non è un motore di scansione nativo Windows.

## Stato della distribuzione

Anteprima in collaudo. Il primo EXE è compilato; le prove specifiche della finestra Windows sono in corso. I risultati Linux, anche quando conclusi, non costituiscono un collaudo della GUI Windows. Consultare [Validazione](VALIDAZIONE.md) per le prove attribuite a ciascun artefatto.

## Primo avvio

1. Estrai tutto il pacchetto ZIP in una cartella scrivibile, per esempio `D:\Cheker\app\windows`. EXE, DLL e cartella `linux` devono restare insieme.
2. Fai doppio clic su **Cheker.exe**. Al primo avvio servono alcuni minuti e una connessione Internet per installare le dipendenze Python fissate nel pacchetto.
3. La dashboard si collega automaticamente. Apri **File Scanner**, premi **Scegli file** e seleziona i documenti nelle cartelle Windows.
4. Consulta il rapporto di ogni file e i totali. Chiudendo la finestra si arresta il suo motore; i risultati salvati rimangono disponibili al prossimo avvio.

La guida `LEGGIMI.html` inclusa nel pacchetto è consultabile anche senza avviare il programma.

## Requisiti

- Windows x64 con .NET Framework 4.8 e WSL 2.
- Una distribuzione WSL configurata come predefinita, con Python 3.11 o successivo e il modulo `venv`.
- Microsoft Edge WebView2 Runtime.
- Una cartella scrivibile e accesso Internet per la prima installazione delle dipendenze. Dopo la preparazione, l'analisi dei documenti avviene localmente.

Per preparare WSL seguire la [guida Microsoft](https://learn.microsoft.com/windows/wsl/install). Per Debian il comando Windows è:

```powershell
wsl --install -d Debian
```

Il sistema può richiedere autorizzazione amministratore e riavvio. Aprire Debian almeno una volta e completare la configurazione dell'utente. Nella distribuzione Linux:

```bash
sudo apt update
sudo apt install python3 python3-venv
python3 --version
```

La versione deve essere almeno 3.11. Per selezionare la distribuzione predefinita, da Windows:

```powershell
wsl --set-default Debian
```

WebView2 è disponibile dal [sito Microsoft](https://developer.microsoft.com/microsoft-edge/webview2/#download-section). Il launcher mostra indicazioni quando non trova i prerequisiti; non installa automaticamente componenti di sistema né modifica impostazioni di sicurezza.

## Dati, cartelle e aggiornamenti

La cartella `data-linux` accanto all'EXE contiene i dati di questa installazione Windows. È distinta dai dati di altre installazioni e dalle anteprime Linux. `logs` contiene i registri di installazione e servizio; `profilo-interfaccia` è il profilo WebView2 locale. Queste cartelle non fanno parte del pacchetto distribuito né del repository.

Per caricare singoli file si usa il selettore Windows. Per sorvegliare cartelle o inserire un percorso si usa la forma Linux: normalmente `D:\Documenti` diventa `/mnt/d/Documenti`.

Le virtualenv Python non sono trasferibili. Estrarre il pacchetto nella destinazione definitiva prima del primo avvio. Per cambiare destinazione, estrarre una nuova copia; con tutte le finestre chiuse, conservare un backup e trasferire l'intera cartella dati nella nuova installazione. Non sovrapporre cartelle dati mentre un motore è in esecuzione.

## Diagnostica

| Messaggio | Intervento |
|---|---|
| WSL non risponde | Avviare la distribuzione, completare la configurazione e controllare che sia la predefinita. |
| Python o `venv` mancanti | Installarli nella distribuzione, poi premere **Riprova**. |
| Protezioni Linux non disponibili | Aggiornare WSL con `wsl --update`; il motore non aggira il controllo. |
| Windows non raggiunge il motore | Verificare il collegamento localhost secondo la [guida Microsoft alla rete WSL](https://learn.microsoft.com/windows/wsl/networking). |
| Pacchetto non verificabile | Estrarre nuovamente il pacchetto originale in una nuova cartella; conservare i dati e i log. |

I log `logs/installazione.log` e `logs/servizio.log` restano locali. Prima di condividerli controllarne il contenuto.

## Interfaccia e collegamento al motore

L'EXE è una finestra WinForms con WebView2. Un processo WSL prepara l'ambiente verificando il manifesto del rilascio e i moduli installati, esegue la diagnostica della sandbox e avvia il backend su una porta loopback libera. La finestra verifica la risposta HMAC del servizio anche dal lato Windows prima di aprire la dashboard.

Il token passa nella pipe privata del processo e viene inserito nella sessione WebView2 soltanto per l'origine locale verificata. Non viene passato negli argomenti del processo, nella query o nel frammento dell'URL. La finestra non espone oggetti nativi alla pagina; navigazioni e richieste fuori dall'origine dell'app sono bloccate. La chiusura invia al processo un comando di arresto e attende la terminazione del motore.

Questi controlli non proteggono da un amministratore del dispositivo o da un processo che possa modificare il programma e leggere i dati dell'utente. Il manifesto SHA-256 controlla i byte del pacchetto, non l'identità dell'editore. Questa anteprima **non ha firma Authenticode**: Windows può mostrare un avviso per un'applicazione non riconosciuta.

## Costruire il pacchetto

Sorgenti: [finestra C#](../windows/Cheker.cs), [ponte WSL](../windows/desktop_bridge.py), [builder](../windows/build_windows.py). La compilazione attuale richiede WSL con il compilatore .NET Framework x64 disponibile in Windows.

Il builder riceve un archivio Linux già qualificato, il suo SHA-256, il pacchetto NuGet ufficiale **Microsoft.Web.WebView2 1.0.4191.47** e una destinazione nuova. Verifica entrambi gli hash, copia le librerie necessarie e le licenze Microsoft, compila l'EXE e produce ZIP e manifesto. Il pacchetto SDK è disponibile su [NuGet](https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4191.47).

```bash
python3 windows/build_windows.py \
  --linux-release /percorso/mcp-integrity-guard-1.0.0-linux.tar.gz \
  --linux-sha256 SHA256_VERIFICATO_DEL_RILASCIO \
  --sdk-package /percorso/Microsoft.Web.WebView2.1.0.4191.47.nupkg \
  --output /percorso/nuovo/cheker-windows
```

La documentazione Microsoft descrive [WinForms con WebView2](https://learn.microsoft.com/microsoft-edge/webview2/get-started/winforms) e l'[inizializzazione degli script prima del documento](https://learn.microsoft.com/dotnet/api/microsoft.web.webview2.core.corewebview2.addscripttoexecuteondocumentcreatedasync). Il pacchetto non include un programma antivirus generale né promette il riconoscimento di ogni file malevolo. Per i formati effettivi e gli esiti bloccanti vedere il [manuale utente](MANUALE_UTENTE.md).
