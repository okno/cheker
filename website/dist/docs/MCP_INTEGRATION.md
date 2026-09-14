# Lettura protetta dei file tramite MCP

Il server `integrity_guard.mcp_server` offre due strumenti reali: `scan_file` e `read_file`. Richiede Linux o WSL e l'applicazione MCP Integrity Guard già avviata. Usa il servizio locale per conservare i report nella stessa dashboard; non apre una seconda istanza del database di approvazione.

Il trasporto è MCP **stdio**, versione **2025-11-25**: messaggi JSON-RPC UTF-8, uno per riga; stdout contiene esclusivamente messaggi del protocollo. La chiusura di stdin termina il server. [Specifica ufficiale del trasporto](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

## Configurazione del client

Avviare prima l'applicazione:

```bash
bash /mnt/d/Cheker/app/start.sh
```

Nel client MCP configurare un server stdio. Sostituire `/home/utente/documenti-agente` con una directory esistente, scelta esplicitamente:

```json
{
  "mcpServers": {
    "integrity-guard-files": {
      "command": "/mnt/d/Cheker/app/runtime-linux/bin/python",
      "args": [
        "-I", "-m", "integrity_guard.mcp_server",
        "--data-dir", "/mnt/d/Cheker/app/data-linux",
        "--api-url", "http://127.0.0.1:8765",
        "--root", "/home/utente/documenti-agente"
      ]
    }
  }
}
```

Per lo sviluppo, il comando Python corrispondente è `/mnt/d/Cheker/dev/.venv/bin/python`. Il flag Python `-I` esclude la directory corrente e `PYTHONPATH` dalla ricerca dei moduli: un progetto non può sostituire il pacchetto installato attraverso il proprio nome. Il parametro `--root` può essere ripetuto, fino a 32 directory. Non esistono radici implicite; il client non può ampliarle attraverso messaggi MCP. Non inserire il token nella configurazione: il processo lo legge da `--data-dir/api-token`.

Il client invia `initialize`, riceve la versione supportata e completa la fase con `notifications/initialized`. Solo dopo questa notifica sono disponibili `tools/list` e `tools/call`; `ping` è ammesso anche prima. Le altre funzionalità MCP, comprese risorse, prompt, task e avvio di server esterni, non sono esposte. [Specifica ufficiale del ciclo di vita](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

## Strumenti

Entrambi accettano esclusivamente un oggetto con il campo obbligatorio `path`, una stringa contenente un percorso Linux assoluto:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/home/utente/documenti-agente/nota.txt"
    }
  }
}
```

| Strumento | Comportamento |
| --- | --- |
| `scan_file` | Invia al servizio locale una copia immutabile dei byte, fino a 10 MiB. Restituisce identificativo del report, SHA-256, esito, severità e conteggio dei rilievi. Non restituisce il contenuto del file. |
| `read_file` | Consegna il testo soltanto quando il report degli stessi byte è `VALID`, `ALLOWED` e completo. Il limite è 256 KiB; prima della consegna controlla nuovamente identità e contenuto del file. |

La lettura supporta UTF-8 nei formati `.txt`, `.md`, `.json`, `.json5`, `.yaml`, `.yml`, `.toml`, `.csv`, `.html`, `.htm`, `.xml`, `.py`, `.js`, `.ts`, `.sh`, `.ps1`. Un formato presente nell'elenco può comunque essere respinto se l'analisi non si conclude correttamente. PDF, DOCX, `.env` e `.log` sono utilizzabili solo con `scan_file`; nessuna conversione o estrazione viene consegnata al modello da questo server.

I risultati contengono `structuredContent` e la corrispondente rappresentazione JSON in un blocco di testo. Un documento sospetto, corrotto o non analizzabile produce `isError: true`. I risultati negati non includono testo sorgente, evidenze, titoli o posizioni dei rilievi: il payload sospetto non può rientrare nel modello attraverso il messaggio di errore. Il report completo resta nella dashboard. [Specifica ufficiale degli strumenti e degli errori](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Confine di sicurezza

- L'accesso ai file Linux usa descrittori di directory e `O_NOFOLLOW`. Link simbolici, attraversamenti fuori radice, dispositivi, pipe e radici sostituite sono respinti.
- La directory dati dell'applicazione e i nomi dei suoi file riservati sono esclusi. Anche gli hardlink verso questi file, copie contenenti il token API attuale e materiale con intestazione PEM di chiave privata sono bloccati.
- Prima dell'autenticazione, il server verifica una prova HMAC v2 su un nonce nuovo, legata all'indirizzo e alla porta effettivi del servizio. Una prova inoltrata da un'altra porta locale viene rifiutata. Il token e il file vengono inviati soltanto sulla **stessa connessione TCP** già verificata. Sono ammessi indirizzi HTTP loopback letterali; proxy ambientali, redirect e host remoti non vengono utilizzati. Questa verifica riguarda servizi nello stesso namespace di rete: non sostituisce TLS e non protegge da un amministratore che controlla inoltri o namespace di rete.
- Ogni lettura usa una nuova scansione. Un precedente report, un nome invariato o un file modificato dopo l'analisi non autorizzano la consegna.
- Nessun file sorgente viene eseguito, modificato, spostato o “sanificato”. I soli effetti persistenti sono i report e gli eventi di audit nell'applicazione.
- Le chiamate sono seriali, limitate a 60 al minuto. I messaggi in ingresso sono limitati a 64 KiB, le risposte API a 2 MiB e il timeout API è di 20 secondi. Dopo 10.000 richieste il client deve riconnettersi. La cancellazione di una chiamata già in corso richiede la chiusura del processo; le operazioni di rete restano limitate dal timeout.

Questa integrazione protegge i contenuti consegnati attraverso questi due strumenti. Non intercetta letture eseguite da altri strumenti, non certifica tutti i possibili prompt injection e non attesta il contenuto degli eseguibili configurati nei server MCP. `VALID` significa che i controlli implementati non hanno rilevato problemi e hanno concluso l'analisi. Segreti arbitrari contenuti in normali documenti autorizzati non possono essere riconosciuti universalmente: selezionare le radici con la stessa attenzione riservata all'accesso diretto dell'agente.
