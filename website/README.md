# Sito Cheker

Sito statico e manuali HTML della distribuzione. Per visualizzarlo localmente:

```bash
python3 -m http.server 8788 --bind 127.0.0.1 --directory website/dist
```

Aprire http://127.0.0.1:8788/. Le guide Markdown originali sono in `docs/`; `tools/render_docs.py` le rende con Markdown 3.10.3. Nessuna API amministrativa o elaborazione di documenti viene esposta dal sito.
