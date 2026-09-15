# Cheker per Windows

Il pacchetto Windows x64 apre una finestra dedicata con la dashboard. Il motore di analisi gira nella distribuzione Linux predefinita di **WSL 2**: le protezioni Linux e i limiti dei formati rimangono gli stessi. Non è un motore di scansione nativo Windows.

## Stato della distribuzione

L’anteprima ZIP 4 include la wheel Linux qualificata **f426c5aa…** e il profilo XLSX statico. La prova della vera `MainWindow`, caricata dall’EXE in WinForms/WebView2, verifica un foglio ordinario, risultato `VALID`/`ALLOWED`, completezza, report, contatori e audit: **11 condizioni API positive**. Il caricamento usa `DataTransfer` ed eventi DOM: non prova il selettore file nativo, il doppio click o l’entry point normale. Lo screenshot mostra il contenuto WebView2, non la cornice della finestra. I processi della prova sono chiusi.

Il setup singolo revisione 2 incorpora lo stesso ZIP: **28 controlli del motore di installazione superati** e schermata iniziale mostrata, acquisita e verificata. Il pulsante **Installa e avvia** e il dialogo cartelle non sono stati azionati nel collaudo; l’installazione è stata esercitata tramite l’API del vero assembly. La precedente prova TXT e l’osservazione della finestra aperta tramite l’EXE normale appartengono allo ZIP 3 con backend 039e. Le prove sono distinte in [Validazione](VALIDAZIONE.md).

| Artefatto qualificato | SHA-256 |
|---|---|
| `cheker-setup-xlsx-preview-2.exe` | `ef1e25eaabaecc07ffc47851216aa41ba97c4e4ddfe4de6cb248d88cc64e7012` |
| `cheker-windows-anteprima-4.zip` | `b626390c9e169d48706a096e83743b5b81eea8df2370c6a5c83d1690db46fb81` |
| `Cheker.exe` contenuto nello ZIP 4 | `c0af87a4959da43751b80ed3a9075f1fc443a3d7d48a47aaf356375c8d22d51c` |

La [release v1.0.0-preview.2](https://github.com/okno/cheker/releases/tag/v1.0.0-preview.2) è pubblicata e include archivio Linux, ZIP Windows, setup singolo e checksum. La documentazione interna degli archivi conserva lo snapshot del freeze; questa guida e i manuali aggiornati sono disponibili separatamente sul web e nei sorgenti. I tre PDF aggiornati sono allegati separatamente alla stessa release, con checksum dedicati.

## Primo avvio con il setup singolo

Prima di avviare una nuova versione, chiudi eventuali finestre Cheker già aperte. L’app consente una sola istanza desktop per sessione Windows; lasciare aperta la versione precedente impedisce l’apertura della nuova.

1. Verifica i prerequisiti elencati sotto e la provenienza del setup. Il programma non installa automaticamente WSL, una distribuzione Linux, Python, WebView2 o .NET Framework.
2. Apri **cheker-setup-xlsx-preview-2.exe**. Scegli una cartella scrivibile. Se esiste l’unità D, viene proposto `D:\Cheker\app\windows`; altrimenti `%LOCALAPPDATA%\Cheker\app\windows`.
3. Premi **Installa e avvia**. Il setup estrae il pacchetto nella sottocartella `Cheker-XLSX-anteprima-4-b626390c9e16`, verifica i file e avvia **Cheker.exe**. La versione usa la propria cartella: non è un aggiornamento automatico dei dati di un’altra installazione.
4. Attendi la preparazione del motore Linux. Al primo avvio servono una connessione Internet e alcuni minuti per installare le dipendenze Python fissate nel pacchetto. Per gli avvii successivi usa **Cheker.exe** nella stessa cartella.
5. Nella dashboard apri **File Scanner**, scegli i documenti e consulta report e totali. Un XLSX con formule, immagini o parti fuori profilo può essere bloccato anche se innocuo; DOC e XLS legacy rimangono non supportati.

Il setup non richiede elevazione (`asInvoker`). La scelta della cartella non sposta i dati di altre versioni. Chiudi la finestra Cheker per arrestare il suo motore; i risultati restano nella cartella della versione.

## Alternativa: primo avvio dal pacchetto ZIP

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

Il setup singolo è separato dal pacchetto applicativo: [finestra del setup](../windows/Setup.cs) e [builder del setup](../windows/build_setup.py). Incorpora lo ZIP già verificato, senza ricompilare la wheel o la dashboard.

Il builder riceve un archivio Linux già qualificato, il suo SHA-256, il pacchetto NuGet ufficiale **Microsoft.Web.WebView2 1.0.4191.47** e una destinazione nuova. Verifica entrambi gli hash, copia le librerie necessarie e le licenze Microsoft, compila l'EXE e produce ZIP e manifesto. Il pacchetto SDK è disponibile su [NuGet](https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4191.47).

```bash
python3 windows/build_windows.py \
  --linux-release /percorso/mcp-integrity-guard-1.0.0-linux.tar.gz \
  --linux-sha256 SHA256_VERIFICATO_DEL_RILASCIO \
  --sdk-package /percorso/Microsoft.Web.WebView2.1.0.4191.47.nupkg \
  --output /percorso/nuovo/cheker-windows
```

La documentazione Microsoft descrive [WinForms con WebView2](https://learn.microsoft.com/microsoft-edge/webview2/get-started/winforms) e l'[inizializzazione degli script prima del documento](https://learn.microsoft.com/dotnet/api/microsoft.web.webview2.core.corewebview2.addscripttoexecuteondocumentcreatedasync). Il pacchetto non include un programma antivirus generale né promette il riconoscimento di ogni file malevolo. Per i formati effettivi e gli esiti bloccanti vedere il [manuale utente](MANUALE_UTENTE.md).
