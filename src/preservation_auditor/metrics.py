from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .database import Database


METRIC_HELP = {
    "baselines_total": "Total de baselines imutaveis registrados.",
    "valid": "Arquivos que correspondem ao baseline.",
    "changed": "Arquivos com checksum divergente.",
    "missing": "Arquivos do baseline que nao foram encontrados.",
    "without_baseline": "Arquivos observados ainda sem baseline.",
    "errors": "Resultados inconclusivos ou erros de leitura.",
    "scan_complete": "Indica se a ultima varredura teve cobertura completa.",
    "last_run_duration_seconds": "Duracao da ultima varredura.",
    "last_success_timestamp_seconds": "Timestamp da ultima varredura conforme.",
}


def render_metrics(database: Database) -> str:
    values = database.latest_integrity_metrics()
    lines: list[str] = []
    for key, value in values.items():
        metric = f"scielo_preservation_aips_integrity_{key}"
        if key.startswith("last_") or key == "scan_complete" or key == "baselines_total":
            metric = f"scielo_preservation_{key}"
        lines.extend((
            f"# HELP {metric} {METRIC_HELP[key]}",
            f"# TYPE {metric} gauge",
            f"{metric} {value}",
        ))
    return "\n".join(lines) + "\n"


def serve(database: Database, host: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/metrics":
                body = render_metrics(database).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path in {"/health", "/ready"}:
                body = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, _format: str, *_args) -> None:
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()
