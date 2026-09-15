# Primi passi con Cheker

Cheker analizza i documenti selezionati e conserva un report per ogni elaborazione. Per iniziare bastano un file di esempio e la console.

## Windows

Prima di procedere devono essere già disponibili WSL2 con una distribuzione predefinita, Python 3.11 o successivo con `venv` nella distribuzione, .NET Framework 4.8 e WebView2. Il setup non installa questi prerequisiti: consulta la [guida Windows](WINDOWS.md) per prepararli.

1. Chiudi le finestre Cheker delle versioni precedenti.
2. Scarica [l’installer Windows](https://github.com/okno/cheker/releases/download/v1.0.0-preview.2/cheker-setup-xlsx-preview-2.exe) dalla [release preview.2](https://github.com/okno/cheker/releases/tag/v1.0.0-preview.2) e aprilo.
3. Scegli una cartella scrivibile, usando **Sfoglia…** se vuoi cambiare quella proposta. Premi **Installa e avvia**: viene creata una cartella dedicata alla versione; i dati delle altre installazioni non vengono spostati.
4. Attendi la preparazione iniziale: servono Internet e alcuni minuti per le dipendenze Python. Se compare un errore, segui il messaggio e la guida Windows.
5. Nella console apri **File Scanner**, scegli **Carica file**, poi **Scegli file**. Seleziona uno o più documenti nel selettore: caricamento e analisi partono automaticamente. Puoi anche trascinarli nell’area indicata. Il limite è 10 MiB per file.
6. Attendi il completamento e leggi i report nel registro. **Aggiorna registro** ricarica l’elenco; non esegue una nuova scansione.

Per gli avvii successivi apri **Cheker.exe** nella cartella della versione.

## Capire il risultato

Le cinque categorie sono:

- **Valido ai controlli**: analisi completata senza anomalie rilevate.
- **Sospetto / infetto**: istruzioni sospette rilevate; non è una diagnosi antivirus.
- **Corrotto**: struttura del documento malformata.
- **Da verificare**: risultato che richiede una revisione.
- **Non analizzabile**: controllo non completato o formato fuori dal profilo supportato.

La somma delle categorie corrisponde a **File analizzati**. Sono elaborazioni salvate: ricaricare lo stesso contenuto aggiunge un report. I file unici contano invece i contenuti distinti.

La console registra l’esito. Per bloccare l’uso da parte di un agente, configura il lettore protetto seguendo il [manuale utente](MANUALE_UTENTE.md#9-usare-la-cli-e-collegare-un-agente).

Con **Non analizzabile**, leggi il motivo nel report, procura una copia in un formato supportato e analizzala nuovamente. DOC e XLS legacy non sono coperti; formule XLSX e contenuti che richiedono OCR restano bloccati. Un esito **Valido ai controlli** non garantisce l’assenza di ogni minaccia. Formati e limiti sono descritti nel [manuale utente](MANUALE_UTENTE.md).

## Linux

Verifica i [prerequisiti Linux](MANUALE_UTENTE.md#requisiti), inclusi Python con `venv`, Landlock e libseccomp. Scarica l’archivio Linux dalla stessa release, estrailo e apri il terminale nella cartella che contiene `mcp-integrity-guard`:

```bash
cd mcp-integrity-guard
bash install-linux.sh
bash start.sh
```

Attendi il completamento dell’installazione. La console si apre nel browser; usa **File Scanner** come descritto sopra.
