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

AUTO_BASELINE_METRIC_HELP = {
    "automatic_baselines_total": "Baselines registrados pelo fluxo automatico.",
    "replica_verifications_total": "Replicas confirmadas antes do baseline.",
    "last_run_ok": "Indica se a ultima execucao automatica registrou o baseline.",
    "last_run_timestamp_seconds": "Timestamp da ultima execucao automatica.",
    "last_run_duration_seconds": "Duracao da ultima execucao automatica.",
    "last_success_timestamp_seconds": "Timestamp do ultimo baseline automatico.",
}

REPLICA_METRIC_HELP = {
    "valid": "Replicas que correspondem as evidencias do baseline.",
    "missing": "Replicas registradas que nao foram encontradas.",
    "changed": "Replicas com tamanho ou checksum divergente.",
    "unknown": "Replicas cuja verificacao foi inconclusiva.",
    "scan_complete": "Indica se todas as replicas puderam ser consultadas.",
    "last_run_ok": "Indica se a ultima auditoria de replicas foi conforme.",
    "last_run_timestamp_seconds": "Timestamp da ultima auditoria de replicas.",
    "last_run_duration_seconds": "Duracao da ultima auditoria de replicas.",
    "last_success_timestamp_seconds": "Timestamp da ultima auditoria conforme.",
}

BAGIT_METRIC_HELP = {
    "total": "Pacotes BagIt descobertos na ultima auditoria.",
    "valid": "Pacotes BagIt estruturalmente validos.",
    "warnings": "Pacotes BagIt validos com ressalvas de preservacao.",
    "invalid": "Pacotes BagIt com uma ou mais falhas.",
    "missing_files": "Pacotes BagIt com arquivos declarados ausentes.",
    "checksum_mismatch": "Pacotes BagIt com checksum divergente.",
    "unlisted_files": "Pacotes BagIt com payload nao declarado.",
    "weak_algorithm": "Pacotes BagIt que declaram algoritmo fraco.",
    "unknown": "Pacotes BagIt cuja verificacao foi inconclusiva.",
    "scan_complete": "Indica se todos os BagIts puderam ser lidos.",
    "last_run_ok": "Indica se a ultima auditoria BagIt foi conforme.",
    "last_run_timestamp_seconds": "Timestamp da ultima auditoria BagIt.",
    "last_run_duration_seconds": "Duracao da ultima auditoria BagIt.",
    "last_success_timestamp_seconds": "Timestamp da ultima auditoria BagIt conforme.",
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
    for key, value in database.latest_auto_baseline_metrics().items():
        metric = f"scielo_preservation_baseline_auto_{key}"
        lines.extend((
            f"# HELP {metric} {AUTO_BASELINE_METRIC_HELP[key]}",
            f"# TYPE {metric} gauge",
            f"{metric} {value}",
        ))
    replica_values, provider_values = database.latest_replica_metrics()
    for key, value in replica_values.items():
        metric = f"scielo_preservation_replicas_{key}"
        lines.extend((
            f"# HELP {metric} {REPLICA_METRIC_HELP[key]}",
            f"# TYPE {metric} gauge",
            f"{metric} {value}",
        ))
        if key in {"valid", "missing", "changed", "unknown"}:
            lines.extend(
                '{}{{replica="{}"}} {}'.format(metric, provider, values[key])
                for provider, values in sorted(provider_values.items())
            )
    for key, value in database.latest_bagit_metrics().items():
        metric = f"scielo_preservation_bagits_{key}"
        lines.extend((
            f"# HELP {metric} {BAGIT_METRIC_HELP[key]}",
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
