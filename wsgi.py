"""WSGI entrypoint for production servers such as Gunicorn."""

from app import create_app


app = create_app()
