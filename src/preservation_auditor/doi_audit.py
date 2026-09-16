from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .audit_log import log_event
from .database import Database
from .integrity import resource_id
from .models import AuditResult, Status


DATACITE_API = "https://api.datacite.org/dois"
ALLOWED_LANDING_HOSTS = {"doi.org", "data.scielo.org"}
MAX_LANDING_BYTES = 8 * 1024 * 1024
MAX_DATACITE_BYTES = 64 * 1024 * 1024
MAX_REDIRECTS = 6
USER_AGENT = "SciELO-Preservation-Auditor/0.1 (+https://github.com/scieloorg/preservation-auditor)"


class DoiAuditError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LandingMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}
        self.licenses: list[str] = []
        self.text: list[str] = []
        self.titles: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {str(key).lower(): str(value or "") for key, value in attrs}
        if tag.lower() == "meta":
            key = (attributes.get("name") or attributes.get("property") or "").lower()
            content = attributes.get("content", "").strip()
            if key and content:
                self.meta.setdefault(key, []).append(content)
        elif tag.lower() == "link" and "license" in attributes.get("rel", "").lower():
            if attributes.get("href"):
                self.licenses.append(attributes["href"])
        elif tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        value = data.strip()
        if value:
            self.text.append(value)
            if self._in_title:
                self.titles.append(value)


def _read_response(response, maximum: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length:
        try:
            if int(length) > maximum:
                raise DoiAuditError("response_too_large")
        except ValueError as error:
            raise DoiAuditError("invalid_content_length") from error
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise DoiAuditError("response_too_large")
    return body


def _open_json(url: str, timeout: float = 30) -> dict:
    request = Request(url, headers={"Accept": "application/vnd.api+json", "User-Agent": USER_AGENT})
    try:
        with build_opener().open(request, timeout=timeout) as response:
            raw = json.loads(_read_response(response, MAX_DATACITE_BYTES).decode("utf-8"))
    except (HTTPError, URLError, OSError, ValueError, UnicodeError) as error:
        raise DoiAuditError("datacite_unavailable") from error
    if not isinstance(raw, dict):
        raise DoiAuditError("invalid_datacite_response")
    return raw


def iter_datacite_dois(prefix: str, page_size: int = 1000) -> Iterable[dict]:
    page = 1
    while True:
        query = urlencode({
            "prefix": prefix,
            "page[size]": page_size,
            "page[number]": page,
        })
        payload = _open_json("{}?{}".format(DATACITE_API, query))
        data = payload.get("data")
        if not isinstance(data, list):
            raise DoiAuditError("invalid_datacite_response")
        for item in data:
            if isinstance(item, dict):
                yield item
        total_pages = int(payload.get("meta", {}).get("totalPages", page))
        if page >= total_pages or not data:
            break
        page += 1


def _fetch_landing(doi: str, timeout: float = 30) -> dict:
    url = "https://doi.org/{}".format(quote(doi, safe="/"))
    opener = build_opener(NoRedirect())
    redirects: list[str] = []
    insecure_redirect = False
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(url)
        if parsed.hostname not in ALLOWED_LANDING_HOSTS:
            return {"error": "DOI_REDIRECT_FORBIDDEN", "redirects": redirects}
        if parsed.scheme not in {"http", "https"}:
            return {"error": "DOI_REDIRECT_FORBIDDEN", "redirects": redirects}
        if parsed.scheme == "http":
            insecure_redirect = True
        request = Request(url, headers={"Accept": "text/html", "User-Agent": USER_AGENT})
        try:
            with opener.open(request, timeout=timeout) as response:
                body = _read_response(response, MAX_LANDING_BYTES)
                content_type = response.headers.get("Content-Type", "")
                link_header = response.headers.get("Link", "")
                final_url = response.geturl()
                status = response.status
        except HTTPError as error:
            if error.code in {301, 302, 303, 307, 308}:
                location = error.headers.get("Location")
                if not location:
                    return {"error": "DOI_REDIRECT_INVALID", "redirects": redirects}
                url = urljoin(url, location)
                redirects.append(url)
                continue
            return {
                "error": "DOI_LANDING_UNAVAILABLE" if error.code >= 500 else "DOI_LANDING_HTTP_ERROR",
                "http_status": error.code, "redirects": redirects,
            }
        except (URLError, OSError, TimeoutError, DoiAuditError):
            return {"error": "DOI_LANDING_UNAVAILABLE", "redirects": redirects}
        if status != 200 or "text/html" not in content_type.lower():
            return {"error": "DOI_LANDING_INVALID_RESPONSE", "http_status": status,
                    "redirects": redirects}
        if urlparse(final_url).hostname != "data.scielo.org":
            return {"error": "DOI_REDIRECT_FORBIDDEN", "redirects": redirects}
        try:
            html = body.decode("utf-8", errors="strict")
        except UnicodeError:
            return {"error": "DOI_LANDING_INVALID_RESPONSE", "redirects": redirects}
        parser = LandingMetadataParser()
        parser.feed(html)
        text = " ".join(parser.text).lower()
        return {
            "http_status": status, "final_url": final_url, "redirects": redirects,
            "insecure_redirect": insecure_redirect,
            "title": bool(
                parser.meta.get("dc.title") or parser.meta.get("og:title") or parser.titles
            ),
            "creators": len(parser.meta.get("dc.creator", [])),
            "abstract": bool(parser.meta.get("dc.description") or parser.meta.get("description")),
            "license": bool(parser.licenses) or 'rel="license"' in link_header.lower(),
            "doi": any(doi.lower() in value.lower() for value in parser.meta.get("dc.identifier", []))
                   or doi.lower() in html.lower(),
            "contact": "support" in text or "contato" in text or "contact" in text,
            "status": "published" in text or "publicado" in text,
        }
    return {"error": "DOI_REDIRECT_LIMIT", "redirects": redirects}


def _has_contact(attributes: dict) -> bool:
    return any(
        isinstance(item, dict) and item.get("contributorType") == "ContactPerson"
        for item in attributes.get("contributors", [])
    )


def audit_doi(item: dict, landing_fetcher: Callable[[str], dict] = _fetch_landing) -> AuditResult:
    attributes = item.get("attributes", {})
    doi = str(attributes.get("doi") or item.get("id") or "").lower()
    evidence: dict = {
        "doi": doi,
        "state": attributes.get("state"),
        "is_active": bool(attributes.get("isActive")),
        "resource_type": attributes.get("types", {}).get("resourceTypeGeneral"),
    }
    missing_datacite: list[str] = []
    checks = {
        "title": bool(attributes.get("titles")),
        "creators": bool(attributes.get("creators")),
        "abstract": any(
            isinstance(value, dict) and value.get("descriptionType") == "Abstract"
            and value.get("description") for value in attributes.get("descriptions", [])
        ),
        "license": bool(attributes.get("rightsList")),
        "contact": _has_contact(attributes),
        "status": bool(attributes.get("state")) and bool(attributes.get("isActive")),
    }
    missing_datacite.extend(key for key, present in checks.items() if not present)
    landing = landing_fetcher(doi)
    evidence["datacite_fields"] = checks
    evidence["landing"] = landing
    error = landing.get("error")
    if error == "DOI_LANDING_UNAVAILABLE":
        return AuditResult(
            "doi.landing_page", "doi", resource_id(doi), Status.UNKNOWN,
            "HIGH", evidence, error,
        )
    failures: list[str] = []
    warnings: list[str] = []
    if not attributes.get("isActive") or attributes.get("state") != "findable":
        failures.append("DOI_NOT_FINDABLE")
    if error:
        failures.append(str(error))
    if missing_datacite:
        failures.append("DOI_METADATA_MISSING")
        evidence["missing_datacite_fields"] = missing_datacite
    if not error:
        required_landing = ("title", "creators", "abstract", "license", "doi", "contact", "status")
        missing_landing = [key for key in required_landing if not landing.get(key)]
        if missing_landing:
            failures.append("DOI_LANDING_FIELDS_MISSING")
            evidence["missing_landing_fields"] = missing_landing
        if landing.get("insecure_redirect"):
            warnings.append("DOI_INSECURE_REDIRECT")
    evidence["errors"] = sorted(set(failures))
    evidence["warnings"] = sorted(set(warnings))
    status = Status.FAIL if failures else Status.WARNING if warnings else Status.PASS
    code = sorted(failures)[0] if failures else sorted(warnings)[0] if warnings else None
    return AuditResult(
        "doi.landing_page", "doi", resource_id(doi), status,
        "HIGH" if failures else "MEDIUM" if warnings else "LOW", evidence, code,
    )


class DoiAuditor:
    def __init__(self, database: Database, logger):
        self.database = database
        self.logger = logger

    def check(
        self, *, prefix: str, workers: int = 4, max_dois: int = 0,
        source: Iterable[dict] | None = None,
        landing_fetcher: Callable[[str], dict] = _fetch_landing,
    ) -> tuple[str, list[AuditResult], bool]:
        run_id = str(uuid.uuid4())
        started = time.monotonic()
        self.database.create_run(run_id, "doi", datetime.now(timezone.utc).isoformat())
        log_event(self.logger, action="job.doi_check", result="started",
                  resource="doi_prefix", run_id=run_id, extra={"prefix": prefix})
        try:
            records: list[dict] = []
            records_source = (
                source if source is not None else
                iter_datacite_dois(prefix, page_size=min(1000, max_dois or 1000))
            )
            for item in records_source:
                records.append(item)
                if max_dois and len(records) >= max_dois:
                    break
            results: list[AuditResult] = []
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(audit_doi, item, landing_fetcher): item
                    for item in records
                }
                for future in as_completed(futures):
                    results.append(future.result())
            complete = bool(results) and all(item.status != Status.UNKNOWN for item in results)
            self.database.save_results(run_id, results)
            if not results or not complete or any(item.status == Status.FAIL for item in results):
                status = "FAIL"
            elif any(item.status == Status.WARNING for item in results):
                status = "WARNING"
            else:
                status = "PASS"
            self.database.finish_run(
                run_id, status=status, scan_complete=complete,
                duration_seconds=time.monotonic() - started,
            )
            log_event(
                self.logger, action="job.doi_check", result=status.lower(),
                resource="doi_prefix", run_id=run_id,
                extra={
                    "prefix": prefix, "records_processed": len(results),
                    "pass": sum(item.status == Status.PASS for item in results),
                    "warnings": sum(item.status == Status.WARNING for item in results),
                    "fail": sum(item.status == Status.FAIL for item in results),
                    "unknown": sum(item.status == Status.UNKNOWN for item in results),
                    "scan_complete": complete,
                },
            )
            return run_id, results, complete
        except Exception as error:
            self.database.finish_run(
                run_id, status="FAIL", scan_complete=False,
                duration_seconds=time.monotonic() - started,
            )
            log_event(
                self.logger, action="job.doi_check", result="failure",
                resource="doi_prefix", run_id=run_id,
                extra={"prefix": prefix, "error_type": type(error).__name__},
            )
            raise
