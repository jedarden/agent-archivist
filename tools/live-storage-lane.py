#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Live five-axis storage-compatibility instrument lane.

The community qualification kit's (docs/notes/community-qualification-kit.md)
equivalent live lane: five write-shaped instruments over the five capability
axes -- conditional create, stored checksum, versioning, server-side
encryption, and multipart commit/abort sessions -- executed against a real
S3 endpoint over path-style SigV4, plus reader read-backs that reconcile the
physical history the writes left behind.

The driver holds no endpoints, hostnames, bucket names, or credentials
(SP-006): every identifier arrives as a CLI argument, and every credential
arrives through the environment (CFG-029), loaded from its per-role store
into the environment only and never printed. The per-operation transcript
written to --transcript carries statuses, response headers of interest, and
latencies -- never request authorization material.

An instrument that errors reduces to the weakest honest finding; the
reduction onto the five-axis tokens happens in this driver's ``reduce_*``
helpers and mirrors archivist_storage::probe's fail-closed rules: an
unestablished fact reports the weakest value the model has, never a guess.

Usage:
    LIVE_RAW_ACCESS_KEY=... LIVE_RAW_SECRET_KEY=... \\
    LIVE_BR_ACCESS_KEY=... LIVE_BR_SECRET_KEY=... \\
    python3 tools/live-storage-lane.py \\
        --endpoint https://<host>:<port> --bucket <bucket> \\
        --region <region> --prefix <run/prefix/> \\
        --profile-tag '<profile>[live,<seam>]' \\
        --transcript <path>.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# SigV4 (path-style), pure stdlib.


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _uri_encode(value: str, encode_slash: bool) -> str:
    safe = "" if encode_slash else "/"
    return urllib.parse.quote(value, safe=safe)


class SigV4:
    """One signing context: credentials + region + service."""

    def __init__(self, access_key: str, secret_key: str, region: str) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = "s3"

    def sign(
        self,
        method: str,
        path: str,
        query: list[tuple[str, str]],
        headers: dict[str, str],
        payload: bytes,
    ) -> dict[str, str]:
        amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        date_stamp = amz_date[:8]
        payload_hash = _sha256_hex(payload)

        signed = dict(headers)
        signed["x-amz-date"] = amz_date
        signed["x-amz-content-sha256"] = payload_hash

        canonical_uri = _uri_encode(path, encode_slash=False) or "/"
        pairs = sorted(
            (_uri_encode(k, True), _uri_encode(v, True)) for k, v in query
        )
        canonical_query = "&".join(f"{k}={v}" for k, v in pairs)

        lowered = {n.lower(): v for n, v in signed.items()}
        header_names = sorted(lowered)
        canonical_headers = "".join(f"{n}:{lowered[n].strip()}\n" for n in header_names)
        signed_headers = ";".join(header_names)
        canonical_request = "\n".join(
            [method, canonical_uri, canonical_query, canonical_headers,
             signed_headers, payload_hash]
        )

        scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        string_to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical_request.encode())]
        )
        k_date = _hmac(("AWS4" + self.secret_key).encode(), date_stamp)
        k_region = _hmac(k_date, self.region)
        k_service = _hmac(k_region, self.service)
        k_signing = _hmac(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

        signed["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return signed


# ---------------------------------------------------------------------------
# Error-body helper.


def error_code(body: bytes) -> str | None:
    match = re.search(rb"<Code>([^<]+)</Code>", body)
    return match.group(1).decode() if match else None


def parse_xml(body: bytes) -> ET.Element | None:
    try:
        return ET.fromstring(body)
    except ET.ParseError:
        return None


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def find_text(root: ET.Element, name: str) -> str | None:
    for el in root.iter():
        if _strip_ns(el.tag) == name and el.text is not None:
            return el.text
    return None


def find_all(root: ET.Element, name: str) -> list[ET.Element]:
    return [el for el in root.iter() if _strip_ns(el.tag) == name]


# ---------------------------------------------------------------------------
# The lane.


class Lane:
    def __init__(self, endpoint: str, bucket: str, raw: SigV4, br: SigV4,
                 transcript_path: str | None = None) -> None:
        self.netloc = urllib.parse.urlsplit(endpoint).netloc
        self.tls = urllib.parse.urlsplit(endpoint).scheme == "https"
        self.bucket = bucket
        self.raw = raw
        self.br = br
        self.transcript: list[dict] = []
        self.transcript_path = transcript_path
        self.ssl_context = ssl.create_default_context()

    def request(
        self,
        op: str,
        role: str,
        method: str,
        key: str,
        query: list[tuple[str, str]] | None = None,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        query = query or []
        signer = self.raw if role == "raw" else self.br
        path = f"/{self.bucket}/{key}" if key else f"/{self.bucket}/"
        signed = signer.sign(method, path, query, headers or {}, body)
        target = _uri_encode(path, encode_slash=False)
        if query:
            pairs = sorted((_uri_encode(k, True), _uri_encode(v, True)) for k, v in query)
            target += "?" + "&".join(f"{k}={v}" for k, v in pairs)

        conn_cls = (
            http.client.HTTPSConnection if self.tls else http.client.HTTPConnection
        )
        started = time.monotonic()
        conn = conn_cls(self.netloc, timeout=30, context=self.ssl_context) if self.tls \
            else conn_cls(self.netloc, timeout=30)
        try:
            conn.request(method, target, body=body, headers=signed)
            resp = conn.getresponse()
            resp_body = resp.read()
            status = resp.status
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        finally:
            conn.close()
        elapsed_ms = int((time.monotonic() - started) * 1000)

        interesting = {
            k: v
            for k, v in resp_headers.items()
            if k in ("etag", "x-amz-version-id", "x-amz-server-side-encryption", "content-type")
        }
        entry = {
            "op": op,
            "role": role,
            "method": method,
            # The handoff transcript is evidence, not a private request dump.
            # Keep operation shape while never serializing the bucket key,
            # prefix, upload id, or query values.
            "query_names": sorted(name for name, _ in query),
            "request_headers_logged": {
                k: v
                for k, v in (headers or {}).items()
                if k.lower() in ("if-none-match", "x-amz-server-side-encryption")
            },
            "signed_header_names": sorted(
                n for n in signed if n.lower() not in ("authorization", "host")
            ),
            "status": status,
            "response_headers": {
                name: value
                for name, value in interesting.items()
                if name not in ("etag", "x-amz-version-id")
            },
            "etag_present": "etag" in interesting,
            "version_id_present": "x-amz-version-id" in interesting,
            "error_code": error_code(resp_body),
            "body_len": len(resp_body),
            "body_sha256": _sha256_hex(resp_body),
            "latency_ms": elapsed_ms,
        }
        self.transcript.append(entry)
        if self.transcript_path:
            with open(self.transcript_path, "a") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return status, resp_headers, resp_body

    # -- instruments ---------------------------------------------------------

    def calibration_list(self, prefix: str):
        status, _, body = self.request(
            "calibration-list", "raw", "GET", "", query=[("list-type", "2"), ("prefix", prefix)]
        )
        root = parse_xml(body) if status == 200 else None
        count = find_text(root, "KeyCount") if root is not None else None
        return {"status": status, "key_count": count, "parse_failed": root is None}

    def conditional_create(self, key: str):
        s1, _, _ = self.request(
            "conditional-create-fresh", "raw", "PUT", key,
            headers={"If-None-Match": "*"},
        )
        s2, _, b2 = self.request(
            "conditional-create-repeat", "raw", "PUT", key,
            headers={"If-None-Match": "*"},
        )
        return {"fresh": s1, "repeat": s2, "repeat_error": error_code(b2)}

    def checksum(self, key: str, payload: bytes):
        status, headers, _ = self.request("checksum-put", "raw", "PUT", key, body=payload)
        return {"status": status, "etag": headers.get("etag"),
                "version_id": headers.get("x-amz-version-id")}

    def versioning(self, key: str):
        s1, h1, _ = self.request("versioning-put-1", "raw", "PUT", key, body=b"versioning-live-v1")
        s2, h2, _ = self.request("versioning-put-2", "raw", "PUT", key, body=b"versioning-live-v2")
        status, _, body = self.request(
            "versioning-list", "br", "GET", key, query=[("versions", "")]
        )
        versions = []
        parse_failed = False
        if status == 200:
            root = parse_xml(body)
            if root is None:
                parse_failed = True
            else:
                for v in find_all(root, "Version"):
                    versions.append({
                        "is_latest": find_text(v, "IsLatest"),
                        "version_id": (find_text(v, "VersionId") or "")[:12] + "…",
                    })
        return {
            "put_1": s1, "put_1_version_id": h1.get("x-amz-version-id"),
            "put_2": s2, "put_2_version_id": h2.get("x-amz-version-id"),
            "list_status": status, "versions": versions,
            "versions_parse_failed": parse_failed,
        }

    def server_side_encryption(self, sse_key: str, plain_key: str):
        s1, h1, _ = self.request(
            "sse-put", "raw", "PUT", sse_key,
            body=b"sse-live",
            headers={"x-amz-server-side-encryption": "AES256"},
        )
        s2, h2, _ = self.request("sse-plain-put", "raw", "PUT", plain_key, body=b"sse-plain-live")
        s3, _, b3 = self.request("bucket-encryption-get", "br", "GET", "", query=[("encryption", "")])
        return {
            "sse_put_status": s1, "sse_echo": h1.get("x-amz-server-side-encryption"),
            "plain_put_status": s2, "plain_echo": h2.get("x-amz-server-side-encryption"),
            "bucket_encryption_status": s3, "bucket_encryption_error": error_code(b3),
        }

    def multipart_commit(self, key: str):
        s1, _, b1 = self.request(
            "mp-create", "raw", "POST", key, query=[("uploads", "")]
        )
        root = parse_xml(b1) if s1 == 200 else None
        upload_id = find_text(root, "UploadId") if root is not None else None
        if upload_id is None:
            return {"create": s1}
        s2, h2, b2 = self.request(
            "mp-upload-part", "raw", "PUT", key,
            query=[("partNumber", "1"), ("uploadId", upload_id)],
            body=b"committed-part",
        )
        # S3 returns the part's ETag in the response header; some
        # implementations also echo it in the body. Accept either.
        part_etag = h2.get("etag")
        if part_etag is None:
            match = re.search(rb"<ETag>([^<]+)</ETag>", b2)
            part_etag = match.group(1).decode() if match else None
        if s2 != 200 or part_etag is None:
            return {"create": s1, "part": s2, "part_etag_observed": part_etag is not None}
        complete_body = (
            "<CompleteMultipartUpload>"
            f"<Part><PartNumber>1</PartNumber><ETag>{part_etag}</ETag></Part>"
            "</CompleteMultipartUpload>"
        ).encode()
        s3, h3, b3 = self.request(
            "mp-complete", "raw", "POST", key, query=[("uploadId", upload_id)],
            body=complete_body,
        )
        return {
            "create": s1, "part": s2, "complete": s3,
            "complete_etag": h3.get("etag") or (
                find_text(parse_xml(b3), "ETag") if s3 == 200 and parse_xml(b3) is not None else None
            ),
            "complete_version_id": h3.get("x-amz-version-id"),
        }

    def multipart_abort(self, key: str, prefix: str):
        s1, _, b1 = self.request("mp-abort-create", "raw", "POST", key, query=[("uploads", "")])
        root = parse_xml(b1) if s1 == 200 else None
        upload_id = find_text(root, "UploadId") if root is not None else None
        if upload_id is None:
            return {"create": s1}
        s2, _, _ = self.request(
            "mp-abort-part", "raw", "PUT", key,
            query=[("partNumber", "1"), ("uploadId", upload_id)],
            body=b"abandoned-part",
        )
        s3, _, b3 = self.request("mp-abort", "raw", "DELETE", key, query=[("uploadId", upload_id)])
        s4, _, b4 = self.request("mp-abort-repeat", "raw", "DELETE", key, query=[("uploadId", upload_id)])
        s5, _, b5 = self.request(
            "mp-open-list", "raw", "GET", "", query=[("uploads", ""), ("prefix", prefix)]
        )
        open_root = parse_xml(b5) if s5 == 200 else None
        open_count = len(find_all(open_root, "Upload")) if open_root is not None else None
        return {
            "create": s1, "part": s2, "abort": s3,
            "abort_error": error_code(b3),
            "abort_repeat": s4, "abort_repeat_error": error_code(b4),
            "open_uploads_after": open_count,
        }

    def read_back(self, prefix: str):
        s1, _, b1 = self.request(
            "readback-list", "br", "GET", "", query=[("list-type", "2"), ("prefix", prefix)]
        )
        list_root = parse_xml(b1) if s1 == 200 else None
        current_keys = (
            [find_text(c, "Key") for c in find_all(list_root, "Contents")]
            if list_root is not None else None
        )
        s2, _, b2 = self.request(
            "readback-versions", "br", "GET", "", query=[("versions", ""), ("prefix", prefix)]
        )
        ver_root = parse_xml(b2) if s2 == 200 else None
        version_count = len(find_all(ver_root, "Version")) if ver_root is not None else None
        version_detail = [
            {
                "key": (find_text(v, "Key") or "")[-48:],
                "is_latest": (find_text(v, "IsLatest") or "").lower(),
                "version_id": (find_text(v, "VersionId") or "")[:12] + "…",
            }
            for v in (find_all(ver_root, "Version") if ver_root is not None else [])
        ]
        return {
            "list_status": s1, "current_keys": current_keys,
            "versions_status": s2, "version_count": version_count,
            "version_detail": version_detail,
            "parse_failed": list_root is None or ver_root is None,
        }

    def teardown(self, prefix: str):
        """Abort every multipart session the lane left open under the run
        prefix. A 404 NoSuchUpload on abort maps to idempotent success --
        the physical fact the live B2 run established for teardown paths."""
        s1, _, b1 = self.request(
            "teardown-list-open", "raw", "GET", "", query=[("uploads", ""), ("prefix", prefix)]
        )
        root = parse_xml(b1) if s1 == 200 else None
        uploads = [
            (find_text(u, "Key") or "", find_text(u, "UploadId") or "")
            for u in (find_all(root, "Upload") if root is not None else [])
        ]
        aborted = []
        for key, upload_id in uploads:
            s, _, b = self.request(
                "teardown-abort", "raw", "DELETE", key, query=[("uploadId", upload_id)]
            )
            code = error_code(b)
            aborted.append({
                "key_tail": key[-40:],
                "status": s,
                "error": code,
                "idempotent_success": s in (200, 204) or code == "NoSuchUpload",
            })
        s2, _, b2 = self.request(
            "teardown-verify", "raw", "GET", "", query=[("uploads", ""), ("prefix", prefix)]
        )
        root2 = parse_xml(b2) if s2 == 200 else None
        return {
            "open_before": len(uploads),
            "aborted": aborted,
            "open_after": (len(find_all(root2, "Upload")) if root2 is not None else None),
        }


# ---------------------------------------------------------------------------
# Fail-closed reduction onto the five-axis tokens.


def reduce_conditional_create(obs: dict) -> str:
    if obs.get("fresh") == 200 and obs.get("repeat") == 412:
        return "supported"
    return "unavailable"


def reduce_checksum(single_etag: str | None, multipart_etag: str | None) -> str:
    md5_form = re.compile(r'^"[0-9a-f]{32}"$')
    if single_etag and md5_form.match(single_etag):
        if multipart_etag and md5_form.match(multipart_etag):
            return "md5"
        return "provider_specific"
    if single_etag or multipart_etag:
        return "provider_specific"
    return "unavailable"


def reduce_versioning(read_back: dict, echo_obs: dict) -> str:
    # Physical history over repeated writes: one key holding >= 2 versions
    # with exactly one current is the observed enabled case. The read-back's
    # prefix-wide versions listing is the primary evidence; the PUT response's
    # version-id echo is the secondary one (some layers accept the writes and
    # version the store without echoing an id).
    per_key: dict[str, list[str]] = {}
    for v in read_back.get("version_detail") or []:
        per_key.setdefault(v["key"], []).append(v["is_latest"])
    for flags in per_key.values():
        if len(flags) >= 2 and flags.count("true") == 1:
            return "enabled"
    if echo_obs.get("put_1_version_id") and echo_obs.get("put_2_version_id") \
            and len(echo_obs.get("versions", [])) >= 2:
        return "enabled"
    if per_key and all(len(f) == 1 for f in per_key.values()) \
            and read_back.get("versions_status") == 200:
        return "disabled"
    return "unknown"


def reduce_sse(obs: dict) -> str:
    if obs.get("sse_echo"):
        return "verified"
    return "unavailable"


def reduce_multipart(commit: dict, abort: dict) -> str:
    if commit.get("complete") == 200 and abort.get("abort") in (200, 204):
        return "verified"
    return "not_a_profile"


def tokens_from_observations(results: dict) -> dict:
    return {
        "conditional_create": reduce_conditional_create(results["conditional_create"]),
        "stored_checksum": reduce_checksum(
            results["checksum"].get("etag"),
            results["multipart_commit"].get("complete_etag"),
        ),
        "versioning": reduce_versioning(results["read_back"], results["versioning"]),
        "server_side_encryption": reduce_sse(results["sse"]),
        "multipart_commit_abort": reduce_multipart(
            results["multipart_commit"], results["multipart_abort"]
        ),
    }


def report_line(profile_tag: str, tokens: dict) -> str:
    return (
        f"storage-compatibility profile={profile_tag} "
        f"conditional_create={tokens['conditional_create']} "
        f"stored_checksum={tokens['stored_checksum']} "
        f"versioning={tokens['versioning']} "
        f"server_side_encryption={tokens['server_side_encryption']} "
        f"multipart_commit_abort={tokens['multipart_commit_abort']}"
    )


def redacted_observations(results: dict) -> dict:
    """Retain qualification facts without retaining infrastructure names.

    The reducer needs status and presence/count facts, but a handoff must not
    carry the live bucket's keys, prefixes, upload ids, or response bodies.
    This shape is deliberately explicit so a newly added instrument cannot
    accidentally inherit a raw recursive serializer.
    """
    calibration = results["calibration"]
    conditional = results["conditional_create"]
    checksum = results["checksum"]
    versioning = results["versioning"]
    sse = results["sse"]
    multipart_commit = results["multipart_commit"]
    multipart_abort = results["multipart_abort"]
    read_back = results["read_back"]
    teardown = results["teardown"]
    return {
        "calibration": {
            "status": calibration.get("status"),
            "key_count": calibration.get("key_count"),
            "parse_failed": calibration.get("parse_failed"),
        },
        "conditional_create": {
            "fresh": conditional.get("fresh"),
            "repeat": conditional.get("repeat"),
            "repeat_error": conditional.get("repeat_error"),
        },
        "checksum": {
            "status": checksum.get("status"),
            "etag_present": checksum.get("etag") is not None,
            "version_id_present": checksum.get("version_id") is not None,
        },
        "versioning": {
            "put_1": versioning.get("put_1"),
            "put_2": versioning.get("put_2"),
            "put_1_version_id_present": versioning.get("put_1_version_id") is not None,
            "put_2_version_id_present": versioning.get("put_2_version_id") is not None,
            "list_status": versioning.get("list_status"),
            "versions_count": len(versioning.get("versions") or []),
            "versions_parse_failed": versioning.get("versions_parse_failed"),
        },
        "sse": {
            "sse_put_status": sse.get("sse_put_status"),
            "sse_echo_present": sse.get("sse_echo") is not None,
            "plain_put_status": sse.get("plain_put_status"),
            "plain_echo_present": sse.get("plain_echo") is not None,
            "bucket_encryption_status": sse.get("bucket_encryption_status"),
            "bucket_encryption_error": sse.get("bucket_encryption_error"),
        },
        "multipart_commit": {
            "create": multipart_commit.get("create"),
            "part": multipart_commit.get("part"),
            "complete": multipart_commit.get("complete"),
            "complete_etag_present": multipart_commit.get("complete_etag") is not None,
            "complete_version_id_present": multipart_commit.get("complete_version_id") is not None,
        },
        "multipart_abort": {
            "create": multipart_abort.get("create"),
            "part": multipart_abort.get("part"),
            "abort": multipart_abort.get("abort"),
            "abort_error": multipart_abort.get("abort_error"),
            "abort_repeat": multipart_abort.get("abort_repeat"),
            "abort_repeat_error": multipart_abort.get("abort_repeat_error"),
            "open_uploads_after": multipart_abort.get("open_uploads_after"),
        },
        "read_back": {
            "list_status": read_back.get("list_status"),
            "current_count": len(read_back.get("current_keys") or []),
            "versions_status": read_back.get("versions_status"),
            "version_count": read_back.get("version_count"),
            "version_detail_count": len(read_back.get("version_detail") or []),
            "parse_failed": read_back.get("parse_failed"),
        },
        "teardown": {
            "open_before": teardown.get("open_before"),
            "aborted_count": len(teardown.get("aborted") or []),
            "aborted_success_count": sum(
                1 for item in teardown.get("aborted") or []
                if item.get("idempotent_success")
            ),
            "open_after": teardown.get("open_after"),
        },
    }


def reduce_from_transcript(path: str, profile_tag: str) -> int:
    """Re-reduce a retained transcript's lane-complete record without a new
    live run: the observations are the evidence, the reductions are
    bookkeeping on them."""
    record = None
    with open(path) as handle:
        for line in handle:
            entry = json.loads(line)
            if entry.get("op") == "lane-complete":
                record = entry
    if record is None:
        print("no lane-complete record in transcript", file=sys.stderr)
        return 2
    results = record["observations"]
    # New handoffs contain the already-reduced tokens because their
    # observations are intentionally redacted. Retain compatibility with
    # older private transcripts that carried the reducer inputs.
    tokens = record.get("tokens") or tokens_from_observations(results)
    print(json.dumps({"observations": results, "tokens": tokens}, indent=2, sort_keys=True))
    print(report_line(profile_tag, tokens))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint")
    parser.add_argument("--bucket")
    parser.add_argument("--region")
    parser.add_argument("--prefix", help="run prefix, must end with /")
    parser.add_argument("--profile-tag")
    parser.add_argument("--transcript")
    parser.add_argument(
        "--from-transcript",
        help="re-reduce a retained transcript instead of executing the lane",
    )
    args = parser.parse_args()

    if args.from_transcript:
        if not args.profile_tag:
            print("--profile-tag is required with --from-transcript", file=sys.stderr)
            return 2
        return reduce_from_transcript(args.from_transcript, args.profile_tag)

    missing = [
        name
        for name in ("LIVE_RAW_ACCESS_KEY", "LIVE_RAW_SECRET_KEY",
                     "LIVE_BR_ACCESS_KEY", "LIVE_BR_SECRET_KEY")
        if not os.environ.get(name)
    ]
    for required in ("--endpoint", "--bucket", "--region", "--prefix",
                     "--profile-tag", "--transcript"):
        if getattr(args, required.lstrip("-").replace("-", "_")) is None:
            missing.append(f"argument {required}")
    if missing:
        print(f"missing environment credentials or required arguments: {', '.join(missing)}",
              file=sys.stderr)
        return 2
    if not args.prefix.endswith("/"):
        print("--prefix must end with /", file=sys.stderr)
        return 2

    raw = SigV4(os.environ["LIVE_RAW_ACCESS_KEY"], os.environ["LIVE_RAW_SECRET_KEY"], args.region)
    br = SigV4(os.environ["LIVE_BR_ACCESS_KEY"], os.environ["LIVE_BR_SECRET_KEY"], args.region)
    open(args.transcript, "w").close()
    lane = Lane(args.endpoint, args.bucket, raw, br, transcript_path=args.transcript)
    stamp = secrets.token_hex(4)
    prefix = args.prefix

    results: dict[str, dict] = {}
    results["calibration"] = lane.calibration_list(prefix)
    cond_key = f"{prefix}cond-{stamp}"
    results["conditional_create"] = lane.conditional_create(cond_key)
    results["checksum"] = lane.checksum(f"{prefix}checksum-{stamp}", b"archivist-live-qual-checksum")
    results["versioning"] = lane.versioning(f"{prefix}versioned-{stamp}")
    results["sse"] = lane.server_side_encryption(
        f"{prefix}sse-{stamp}", f"{prefix}sse-plain-{stamp}"
    )
    results["multipart_commit"] = lane.multipart_commit(f"{prefix}mp-commit-{stamp}")
    results["multipart_abort"] = lane.multipart_abort(f"{prefix}mp-abort-{stamp}", prefix)
    results["read_back"] = lane.read_back(prefix)
    results["teardown"] = lane.teardown(prefix)

    tokens = tokens_from_observations(results)

    safe_results = redacted_observations(results)
    with open(args.transcript, "a") as handle:
        handle.write(json.dumps({"op": "lane-complete", "observations": safe_results,
                                 "tokens": tokens}, sort_keys=True) + "\n")
    print(json.dumps({"observations": safe_results, "tokens": tokens}, indent=2, sort_keys=True))
    print(report_line(args.profile_tag, tokens))
    return 0


if __name__ == "__main__":
    sys.exit(main())
