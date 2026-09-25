from __future__ import annotations

import html
import json
import os
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .audit_log import log_event
from .database import Database
from .integrity import resource_id
from .models import AuditResult, Status


DOI_PATTERN = re.compile(r"^10\.\d{4,9}/[-._;()/:a-z0-9]+$", re.IGNORECASE)
AIP_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
MAX_LINKS_BYTES = 4 * 1024 * 1024


class LandingPageError(RuntimeError):
    pass


def _valid_doi(value: str) -> bool:
    if not DOI_PATTERN.fullmatch(value):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def load_links(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        if path.stat().st_size > MAX_LINKS_BYTES:
            raise LandingPageError("links_config_too_large")
        raw = json.loads(path.read_text(encoding="utf-8"))
        links = raw["links"]
    except LandingPageError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise LandingPageError("invalid_links_config") from error
    if not isinstance(links, list):
        raise LandingPageError("invalid_links_config")
    result: dict[str, str] = {}
    for item in links:
        if not isinstance(item, dict) or set(item) != {"doi", "aip_id"}:
            raise LandingPageError("invalid_links_config")
        doi = str(item["doi"]).lower()
        aip_id = str(item["aip_id"])
        if not _valid_doi(doi) or not AIP_ID_PATTERN.fullmatch(aip_id):
            raise LandingPageError("invalid_links_config")
        if doi in result:
            raise LandingPageError("duplicate_doi_link")
        result[doi] = aip_id
    return result


def _latest_datasets(database: Database) -> list[dict[str, Any]]:
    with database.connect() as connection:
        run = connection.execute(
            """SELECT runs.run_id, runs.finished_at FROM audit_runs AS runs
               WHERE runs.kind = 'doi'
                 AND runs.finished_at IS NOT NULL
                 AND runs.scan_complete = 1
                 AND EXISTS (
                     SELECT 1 FROM audit_results AS results
                     WHERE results.run_id = runs.run_id
                       AND results.control = 'doi.landing_page'
                 )
               ORDER BY runs.finished_at DESC LIMIT 1"""
        ).fetchone()
        if run is None:
            raise LandingPageError("doi_audit_not_available")
        rows = connection.execute(
            """SELECT status, error_code, checked_at, evidence_json
               FROM audit_results WHERE run_id = ? AND control = 'doi.landing_page'""",
            (run["run_id"],),
        ).fetchall()
    datasets = []
    for row in rows:
        evidence = json.loads(row["evidence_json"])
        if evidence.get("parent_doi") or evidence.get("resource_type") != "Dataset":
            continue
        metadata = evidence.get("public_metadata")
        doi = str(evidence.get("doi") or "").lower()
        if isinstance(metadata, dict) and _valid_doi(doi):
            datasets.append({
                "doi": doi, "doi_status": row["status"],
                "doi_error_code": row["error_code"], "checked_at": row["checked_at"],
                "dataset_status": evidence.get("state") or "unknown",
                "metadata": metadata,
            })
    return sorted(datasets, key=lambda item: item["doi"])


def _normalized_name(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")


def _aip_package_name(relative_path: str, aip_id: str) -> str | None:
    name = Path(relative_path).name
    for extension in (".tar.gz", ".tar.bz2", ".tar.xz", ".7z", ".zip", ".tar"):
        if name.lower().endswith(extension):
            name = name[:-len(extension)]
            break
    suffix = "-" + aip_id.lower()
    if not name.lower().endswith(suffix):
        return None
    return _normalized_name(name[:-len(suffix)])


def sync_doi_aip_links(
    database: Database, datasets: list[dict[str, Any]], logger, run_id: str,
) -> dict[str, int]:
    patterns = {
        record["doi"]: re.compile(
            r"^{}(?:-?v(?:ersion)?-?[0-9][a-z0-9-]*)?$".format(
                re.escape(_normalized_name("doi-" + record["doi"]))
            )
        )
        for record in datasets
    }
    summary = {"candidates": 0, "linked": 0, "unmatched": 0, "ambiguous": 0}
    log_event(logger, action="job.doi_aip_link_sync", result="started",
              resource="doi_aip_link", run_id=run_id)
    for candidate in database.automatic_link_candidates():
        summary["candidates"] += 1
        package_name = _aip_package_name(
            str(candidate["relative_path"]), str(candidate["aip_id"])
        )
        if package_name is None:
            summary["unmatched"] += 1
            continue
        matches = [doi for doi, pattern in patterns.items() if pattern.fullmatch(package_name)]
        if len(matches) != 1:
            summary["ambiguous" if matches else "unmatched"] += 1
            continue
        database.save_doi_aip_link(doi=matches[0], aip_id=str(candidate["aip_id"]))
        summary["linked"] += 1
    log_event(logger, action="job.doi_aip_link_sync", result="success",
              resource="doi_aip_link", run_id=run_id, extra=summary)
    return summary


def _preservation(database: Database, aip_id: str | None) -> dict[str, Any]:
    empty = {
        "code": "pending", "label": "Verificacao pendente", "aip_linked": False,
        "local_integrity": "not_available", "replicas_verified": 0,
        "replicas_expected": 3, "last_checked_at": None,
    }
    if not aip_id:
        return empty
    with database.connect() as connection:
        baseline = connection.execute(
            """SELECT e.event_id, e.resource_id, e.registered_at,
                      COUNT(r.id) AS replicas
               FROM baseline_events AS e
               LEFT JOIN replica_verifications AS r ON r.event_id = e.event_id
               WHERE e.aip_id = ? GROUP BY e.event_id""", (aip_id,),
        ).fetchone()
        if baseline is None:
            return {**empty, "aip_linked": True}
        integrity_run = connection.execute(
            """SELECT run_id, finished_at FROM audit_runs
               WHERE kind = 'integrity' AND finished_at IS NOT NULL
               ORDER BY finished_at DESC LIMIT 1"""
        ).fetchone()
        integrity = None if integrity_run is None else connection.execute(
            """SELECT status FROM audit_results
               WHERE run_id = ? AND control = 'aip.local_integrity' AND resource_id = ?""",
            (integrity_run["run_id"], baseline["resource_id"]),
        ).fetchone()
        replica_run = connection.execute(
            """SELECT run_id, finished_at FROM audit_runs
               WHERE kind = 'replica_integrity' AND finished_at IS NOT NULL
               ORDER BY finished_at DESC LIMIT 1"""
        ).fetchone()
        replica_rows = [] if replica_run is None else connection.execute(
            """SELECT status, evidence_json FROM audit_results
               WHERE run_id = ? AND control = 'aip.replica_integrity'""",
            (replica_run["run_id"],),
        ).fetchall()
    replica_statuses = [
        row["status"] for row in replica_rows
        if json.loads(row["evidence_json"]).get("aip_id") == aip_id
    ]
    integrity_status = integrity["status"] if integrity else "not_available"
    checked_dates = [baseline["registered_at"]]
    if integrity_run:
        checked_dates.append(integrity_run["finished_at"])
    if replica_run and replica_statuses:
        checked_dates.append(replica_run["finished_at"])
    has_failure = integrity_status in {"FAIL", "UNKNOWN"} or any(
        value in {"FAIL", "UNKNOWN"} for value in replica_statuses
    )
    verified = (
        sum(value == "PASS" for value in replica_statuses)
        if replica_statuses else int(baseline["replicas"])
    )
    if has_failure:
        code, label = "failure", "Falha de preservacao"
    elif integrity_status == "PASS" and verified == 3:
        code, label = "preserved", "Preservado"
    elif verified == 3:
        code, label = "preserved_with_alerts", "Preservado com alertas"
    else:
        code, label = "pending", "Verificacao pendente"
    return {
        "code": code, "label": label, "aip_linked": True,
        "local_integrity": integrity_status.lower(),
        "replicas_verified": verified, "replicas_expected": 3,
        "last_checked_at": max(value for value in checked_dates if value),
    }


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".landing-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _page_path(output: Path, doi: str) -> Path:
    prefix, suffix = doi.split("/", 1)
    return output / prefix / suffix / "index.html"


def _render_page(record: dict[str, Any], contact: str) -> str:
    metadata = record["metadata"]
    preservation = record["preservation"]
    esc = lambda value: html.escape(str(value), quote=True)
    creators = "".join("<li>{}</li>".format(esc(value)) for value in metadata.get("creators", []))
    rights = "".join(
        "<li>{}</li>".format(esc(item.get("name") or item.get("uri") or "Nao informada"))
        for item in metadata.get("rights", []) if isinstance(item, dict)
    ) or "<li>Nao informada</li>"
    payload = json.dumps(record, ensure_ascii=False, sort_keys=True).replace("<", "\\u003c")
    return """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{title} — SciELO Data</title><style>
body{{font:16px/1.55 system-ui,sans-serif;margin:0;color:#202124;background:#f7f8fa}}main{{max-width:900px;margin:auto;padding:2rem}}
article{{background:white;padding:2rem;border-radius:10px;box-shadow:0 1px 4px #0002}}dt{{font-weight:700}}dd{{margin:0 0 1rem}}
.status{{display:inline-block;padding:.4rem .75rem;border-radius:999px;background:#e7f4ea;font-weight:700}}footer{{margin-top:2rem;color:#5f6368}}
</style></head><body><main><article><header><p>SciELO Data · Preservacao digital</p><h1>{title}</h1>
<p class="status">{preservation_label}</p></header><dl><dt>DOI</dt><dd><a href="https://doi.org/{doi_url}">{doi}</a></dd>
<dt>Autores</dt><dd><ul>{creators}</ul></dd><dt>Resumo</dt><dd>{abstract}</dd><dt>Licenca</dt><dd><ul>{rights}</ul></dd>
<dt>Publicador</dt><dd>{publisher}</dd><dt>Ano de publicacao</dt><dd>{publication_year}</dd><dt>Versao</dt><dd>{version}</dd>
<dt>Status do dataset</dt><dd>{dataset_status}</dd><dt>Auditoria do DOI</dt><dd>{doi_status}</dd>
<dt>Integridade local</dt><dd>{integrity}</dd>
<dt>Replicas verificadas</dt><dd>{replicas} de {expected}</dd><dt>Ultima verificacao</dt><dd>{checked}</dd>
<dt>Contato</dt><dd><a href="mailto:{contact}">{contact}</a></dd></dl>
<footer>Este status representa a ultima verificacao automatizada conhecida e nao constitui garantia de disponibilidade continua.</footer>
</article></main><script type="application/json" id="preservation-record">{payload}</script></body></html>""".format(
        title=esc(metadata.get("title") or record["doi"]), doi=esc(record["doi"]),
        doi_url=quote(record["doi"], safe="/"), creators=creators,
        abstract=esc(metadata.get("abstract") or "Nao informado"), rights=rights,
        publisher=esc(metadata.get("publisher") or "Nao informado"),
        publication_year=esc(metadata.get("publication_year") or "Nao informado"),
        version=esc(metadata.get("version") or "Nao informada"),
        dataset_status=esc(record["dataset_status"]), doi_status=esc(record["doi_status"]),
        integrity=esc(preservation["local_integrity"]),
        replicas=preservation["replicas_verified"], expected=preservation["replicas_expected"],
        checked=esc(preservation["last_checked_at"] or "Pendente"), contact=esc(contact),
        preservation_label=esc(preservation["label"]), payload=payload,
    )


class LandingPageGenerator:
    def __init__(self, database: Database, logger):
        self.database = database
        self.logger = logger

    def generate(self, *, output: Path, links_config: Path | None, contact: str) -> dict:
        run_id = str(uuid.uuid4())
        started = time.monotonic()
        self.database.create_run(run_id, "landing_pages", datetime.now(timezone.utc).isoformat())
        log_event(self.logger, action="job.landing_page_generation", result="started",
                  resource="public_landing_page", run_id=run_id)
        try:
            if not EMAIL_PATTERN.fullmatch(contact):
                raise LandingPageError("invalid_contact")
            links = load_links(links_config)
            records = _latest_datasets(self.database)
            if not records:
                raise LandingPageError("dataset_metadata_not_available")
            link_summary = sync_doi_aip_links(self.database, records, self.logger, run_id)
            automatic_links = self.database.doi_aip_links()
            automatic_links.update(links)
            results = []
            index_items = []
            for record in records:
                record["preservation"] = _preservation(
                    self.database, automatic_links.get(record["doi"])
                )
                page = _page_path(output, record["doi"])
                _atomic_write(page, _render_page(record, contact))
                _atomic_write(page.with_name("status.json"), json.dumps(
                    record, ensure_ascii=False, indent=2, sort_keys=True
                ) + "\n")
                relative = page.relative_to(output).as_posix()
                index_items.append((record["metadata"].get("title") or record["doi"], relative,
                                    record["preservation"]["label"]))
                results.append(AuditResult(
                    "landing.static_page", "doi", resource_id(record["doi"]), Status.PASS,
                    "LOW", {"doi": record["doi"],
                            "preservation_status": record["preservation"]["code"],
                            "aip_linked": record["preservation"]["aip_linked"]},
                ))
            links_html = "".join(
                '<li><a href="{}">{}</a> — {}</li>'.format(
                    html.escape(relative, quote=True), html.escape(title), html.escape(status)
                ) for title, relative, status in index_items
            )
            _atomic_write(output / "index.html", """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Preservacao — SciELO Data</title></head>
<body><main><h1>Status de preservacao do SciELO Data</h1><ul>{}</ul></main></body></html>""".format(links_html))
            self.database.save_results(run_id, results)
            self.database.finish_run(run_id, status="PASS", scan_complete=True,
                                     duration_seconds=time.monotonic() - started)
            log_event(self.logger, action="job.landing_page_generation", result="success",
                      resource="public_landing_page", run_id=run_id,
                      extra={"records_processed": len(results),
                             "output_files": len(results) * 2 + 1,
                             "automatic_links": link_summary["linked"]})
            return {"run_id": run_id, "generated": len(results), "scan_complete": True,
                    "automatic_links": link_summary}
        except Exception as error:
            self.database.finish_run(run_id, status="FAIL", scan_complete=False,
                                     duration_seconds=time.monotonic() - started)
            log_event(self.logger, action="job.landing_page_generation", result="failure",
                      resource="public_landing_page", run_id=run_id,
                      extra={"error_type": type(error).__name__})
            raise
