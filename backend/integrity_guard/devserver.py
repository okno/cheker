"""Reloadable development server; environment is set by Start-Dev.ps1."""

from .api import create_app

app = create_app()
