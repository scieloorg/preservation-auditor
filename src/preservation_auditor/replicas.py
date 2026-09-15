from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


REQUIRED_REPLICAS = {"digitalocean", "minio", "wasabi"}
REPLICA_FIELDS = {
    "name",
    "endpoint_url",
    "bucket",
    "region",
    "access_key_env",
    "secret_key_env",
    "session_token_env",
    "checksum_metadata_key",
    "require_checksum_metadata",
    "allow_http",
}
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
BUCKET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,61}[A-Za-z0-9]$")


class ReplicaVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReplicaTarget:
    name: str
    endpoint_url: str
    bucket: str
    region: Optional[str]
    access_key_env: Optional[str]
    secret_key_env: Optional[str]
    session_token_env: Optional[str]
    checksum_metadata_key: str
    require_checksum_metadata: bool
    allow_http: bool


@dataclass(frozen=True)
class ReplicaEvidence:
    name: str
    bucket: str
    object_key: str
    size_bytes: int
    checksum_verified: bool


def load_replica_targets(path: Path) -> List[ReplicaTarget]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReplicaVerificationError("invalid_replicas_config") from error

    if not isinstance(raw, dict) or set(raw) != {"replicas"}:
        raise ReplicaVerificationError("invalid_replicas_config")
    replicas = raw.get("replicas")
    if not isinstance(replicas, list):
        raise ReplicaVerificationError("invalid_replicas_config")

    targets: List[ReplicaTarget] = []
    for item in replicas:
        if not isinstance(item, dict):
            raise ReplicaVerificationError("invalid_replica_entry")
        if set(item) - REPLICA_FIELDS:
            raise ReplicaVerificationError("unknown_replica_config_field")
        if any(not isinstance(item.get(field), str) for field in (
            "name", "endpoint_url", "bucket"
        )):
            raise ReplicaVerificationError("invalid_replica_config_type")
        for field in (
            "region", "access_key_env", "secret_key_env",
            "session_token_env", "checksum_metadata_key",
        ):
            if field in item and item[field] is not None and not isinstance(
                item[field], str
            ):
                raise ReplicaVerificationError("invalid_replica_config_type")
        for field in ("require_checksum_metadata", "allow_http"):
            if field in item and type(item[field]) is not bool:
                raise ReplicaVerificationError("invalid_replica_config_type")
        try:
            target = ReplicaTarget(
                name=str(item["name"]).lower(),
                endpoint_url=str(item["endpoint_url"]),
                bucket=str(item["bucket"]),
                region=str(item["region"]) if item.get("region") else None,
                access_key_env=(
                    str(item["access_key_env"])
                    if item.get("access_key_env") else None
                ),
                secret_key_env=(
                    str(item["secret_key_env"])
                    if item.get("secret_key_env") else None
                ),
                session_token_env=(
                    str(item["session_token_env"])
                    if item.get("session_token_env") else None
                ),
                checksum_metadata_key=str(
                    item.get("checksum_metadata_key", "sha256")
                ).lower(),
                require_checksum_metadata=bool(
                    item.get("require_checksum_metadata", False)
                ),
                allow_http=bool(item.get("allow_http", False)),
            )
        except KeyError as error:
            raise ReplicaVerificationError("missing_replica_config_field") from error
        _validate_target(target)
        targets.append(target)

    names = [target.name for target in targets]
    if len(names) != len(set(names)) or set(names) != REQUIRED_REPLICAS:
        raise ReplicaVerificationError("required_replicas_not_configured")
    return targets


def _validate_target(target: ReplicaTarget) -> None:
    parsed = urlparse(target.endpoint_url)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        raise ReplicaVerificationError("invalid_replica_endpoint")
    if parsed.scheme == "http" and not target.allow_http:
        raise ReplicaVerificationError("insecure_replica_endpoint")
    if not BUCKET_PATTERN.fullmatch(target.bucket):
        raise ReplicaVerificationError("invalid_replica_bucket")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ReplicaVerificationError("replica_endpoint_must_not_have_path")
    if not target.region:
        raise ReplicaVerificationError("missing_replica_region")
    if not target.checksum_metadata_key.isascii():
        raise ReplicaVerificationError("invalid_checksum_metadata_key")
    if not target.access_key_env or not target.secret_key_env:
        raise ReplicaVerificationError("missing_replica_credential_environment")
    for env_name in (
        target.access_key_env, target.secret_key_env, target.session_token_env
    ):
        if env_name and not ENV_NAME_PATTERN.fullmatch(env_name):
            raise ReplicaVerificationError("invalid_credential_environment_name")


def _credential(env_name: Optional[str]) -> Optional[str]:
    if env_name is None:
        return None
    value = os.environ.get(env_name)
    if not value:
        raise ReplicaVerificationError("missing_replica_credentials")
    return value


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


class S3HeadClient:
    def __init__(self, target: ReplicaTarget):
        self.target = target
        self.access_key = _credential(target.access_key_env)
        self.secret_key = _credential(target.secret_key_env)
        self.session_token = _credential(target.session_token_env)
        if not self.access_key or not self.secret_key:
            raise ReplicaVerificationError("missing_replica_credentials")

    def head_object(self, *, Bucket: str, Key: str) -> Dict[str, Any]:
        parsed = urlparse(self.target.endpoint_url)
        canonical_uri = "/{}/{}".format(
            quote(Bucket, safe="-_.~"), quote(Key, safe="/-_.~")
        )
        request_url = "{}://{}{}".format(
            parsed.scheme, parsed.netloc, canonical_uri
        )
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(b"").hexdigest()
        headers = {
            "host": parsed.netloc,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if self.session_token:
            headers["x-amz-security-token"] = self.session_token
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(
            "{}:{}\n".format(name, headers[name].strip())
            for name in sorted(headers)
        )
        canonical_request = "\n".join((
            "HEAD",
            canonical_uri,
            "",
            canonical_headers,
            signed_headers,
            payload_hash,
        ))
        credential_scope = "{}/{}/s3/aws4_request".format(
            date_stamp, self.target.region
        )
        string_to_sign = "\n".join((
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ))
        date_key = _sign(
            ("AWS4" + self.secret_key).encode("utf-8"), date_stamp
        )
        region_key = _sign(date_key, self.target.region or "")
        service_key = _sign(region_key, "s3")
        signing_key = _sign(service_key, "aws4_request")
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        authorization = (
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}"
        ).format(self.access_key, credential_scope, signed_headers, signature)
        request_headers = dict(headers)
        request_headers["authorization"] = authorization
        request = Request(request_url, method="HEAD", headers=request_headers)

        class RejectRedirects(HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None

        tls_context = ssl.create_default_context()
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = build_opener(HTTPSHandler(context=tls_context), RejectRedirects())
        try:
            with opener.open(request, timeout=20) as response:
                metadata_prefix = "x-amz-meta-"
                metadata = {
                    name.lower()[len(metadata_prefix):]: value
                    for name, value in response.headers.items()
                    if name.lower().startswith(metadata_prefix)
                }
                length = response.headers.get("Content-Length")
                return {
                    "ContentLength": int(length) if length is not None else None,
                    "Metadata": metadata,
                }
        except HTTPError as error:
            if error.code == 404:
                raise ReplicaVerificationError("replica_not_found") from error
            raise ReplicaVerificationError(
                "replica_request_failed:HTTPError"
            ) from error
        except (URLError, TimeoutError, ValueError) as error:
            raise ReplicaVerificationError(
                "replica_request_failed:{}".format(type(error).__name__)
            ) from error


def create_s3_client(target: ReplicaTarget) -> S3HeadClient:
    return S3HeadClient(target)


def verify_replicas(
    targets: List[ReplicaTarget],
    *,
    object_key: str,
    expected_size: int,
    expected_checksum: str,
    client_factory: Callable[[ReplicaTarget], Any] = create_s3_client,
    object_keys: Optional[Dict[str, str]] = None,
) -> List[ReplicaEvidence]:
    evidence: List[ReplicaEvidence] = []
    if object_keys is not None and set(object_keys) != {t.name for t in targets}:
        raise ReplicaVerificationError("invalid_replica_object_keys")
    for target in targets:
        key = object_keys[target.name] if object_keys is not None else object_key
        try:
            response = client_factory(target).head_object(
                Bucket=target.bucket, Key=key
            )
        except ReplicaVerificationError as error:
            if str(error).split(":", 1)[0] == "replica_not_found":
                raise ReplicaVerificationError(
                    "replica_not_found:{}".format(target.name)
                ) from error
            raise ReplicaVerificationError(
                "replica_head_failed:{}:{}".format(
                    target.name, type(error).__name__
                )
            ) from error
        except Exception as error:
            raise ReplicaVerificationError(
                "replica_head_failed:{}:{}".format(
                    target.name, type(error).__name__
                )
            ) from error

        size = response.get("ContentLength")
        if not isinstance(size, int) or size != expected_size:
            raise ReplicaVerificationError(
                "replica_size_mismatch:{}".format(target.name)
            )
        metadata = response.get("Metadata") or {}
        remote_checksum = metadata.get(target.checksum_metadata_key)
        if remote_checksum is not None:
            remote_checksum = str(remote_checksum).lower()
            if remote_checksum != expected_checksum:
                raise ReplicaVerificationError(
                    "replica_checksum_mismatch:{}".format(target.name)
                )
        elif target.require_checksum_metadata:
            raise ReplicaVerificationError(
                "replica_checksum_missing:{}".format(target.name)
            )

        evidence.append(ReplicaEvidence(
            name=target.name,
            bucket=target.bucket,
            object_key=key,
            size_bytes=size,
            checksum_verified=remote_checksum is not None,
        ))
    return evidence
