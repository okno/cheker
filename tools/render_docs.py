"""Render the public documentation whitelist into a static Cheker site.

Requires Markdown==3.10.3 in a separate documentation environment.
Only project-authored public Markdown is an input; never use this on uploads.
"""
from __future__ import annotations
import argparse
from html import escape
from pathlib import Path
import re
from urllib.parse import urlsplit, unquote
import markdown

DOCUMENTS = {
    'PRIMI_PASSI': 'Primi passi',
    'MANUALE_UTENTE': 'Manuale utente',
    'MANUALE_TECNICO': 'Manuale tecnico',
    'SVILUPPO': 'Sviluppo e rilascio',
    'ARCHITETTURA': 'Architettura',
    'MCP_INTEGRATION': 'Integrazione MCP',
    'LINUX_SANDBOX': 'Sandbox Linux',
    'SANITIZZAZIONE': 'Copia testuale HTML',
    'ESTRATTORI': 'Estrattori',
    'REQUISITI_COPERTURA': 'Copertura dei requisiti',
    'VALIDAZIONE': 'Validazione',
    'PERFORMANCE': 'Prestazioni',
    'WINDOWS': 'App Windows',
    'PROTEZIONI': 'Ricerca e protezioni',
}

def render(source: Path, site: Path) -> list[str]:
    destination=site/'dist'/'docs'
    destination.mkdir(parents=True, exist_ok=True)
    selected={key: source/'docs'/(key+'.md') for key in DOCUMENTS}
    selected['CONTRACT']=source/'CONTRACT.md'
    labels={**DOCUMENTS,'CONTRACT':'Contratto delle interfacce'}
    public={path.resolve(): key+'.html' for key,path in selected.items()}
    outputs=[]
    for key,path in selected.items():
        md=markdown.Markdown(extensions=['fenced_code','tables','toc','footnotes','sane_lists'])
        content=md.convert(path.read_text(encoding='utf-8'))
        def link(match):
            original=unquote(match.group(1)); parts=urlsplit(original)
            if parts.scheme or parts.netloc or original.startswith('#'):return match.group()
            target=(path.parent/parts.path).resolve()
            if target in public:url=public[target]
            elif target==source.resolve()/'README.md':url='../index.html'
            elif target.is_relative_to(source.resolve()):
                rel=target.relative_to(source.resolve()).as_posix()
                url='https://github.com/okno/cheker/blob/main/'+rel
            else:raise ValueError('Documentation link outside public source: '+str(path))
            if parts.fragment:url+='#'+parts.fragment
            return 'href="'+escape(url,quote=True)+'"'
        content=re.sub(r'href="([^"]+)"',link,content)
        navigation=''.join(f'<a href="{name}.html"'+(' aria-current="page"' if name==key else '')+f'>{escape(label)}</a>' for name,label in labels.items())
        title=escape(labels[key])
        pdf_link = f'<a href="{key}.pdf" download>Scarica PDF</a>' if (destination/(key+'.pdf')).is_file() else ''
        page=f'''<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title} · Cheker</title><meta name="description" content="{title} di Cheker: applicazione locale Linux per integrità MCP e analisi dei documenti."><link rel="stylesheet" href="../style.css"><link rel="stylesheet" href="docs.css"><link rel="icon" href="../assets/cheker-logomark.png"></head>
<body><a class="skip" href="#documento">Vai al documento</a><header class="header wrap"><a class="wordmark" href="../"><img class="brand-logo" src="../assets/cheker-logomark.png" width="44" height="44" alt="">cheker<span class="wordmark-dot">.</span></a><nav aria-label="Principale"><a href="../">Il progetto</a><a href="https://github.com/okno/cheker">GitHub ↗</a></nav></header>
<div class="docs-layout wrap"><aside class="doc-navigation"><details open><summary>Documentazione</summary><nav aria-label="Manuali">{navigation}</nav></details></aside><main class="document" id="documento"><div class="doc-tools"><a href="{key}.md" download>Scarica Markdown</a>{pdf_link}<button type="button" onclick="window.print()">Stampa / salva PDF</button></div>{content}</main></div><footer class="footer wrap"><a href="../">← Torna a Cheker</a><p>Documentazione di Cheker. Consultare la validazione per disponibilità e prove delle singole build.</p></footer></body></html>'''
        (destination/(key+'.html')).write_text(page,encoding='utf-8')
        (destination/(key+'.md')).write_bytes(path.read_bytes())
        outputs.append(key+'.html')
    return outputs

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--site-root',type=Path,required=True)
    args=parser.parse_args()
    print('\n'.join(render(args.source_root.resolve(),args.site_root.resolve())))
