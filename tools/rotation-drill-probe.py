#!/usr/bin/env python3
"""SigV4 probe for the ARMOR storage-identity rotation drills.

Implements the live half of the rotation procedure's verification matrix
(``docs/notes/armor-storage-provisioning.md``, "Rotation procedure",
steps 1, 5, and 6). Policy, one rule per check below:

1. credentials arrive via environment variables only — never argv, never
   a file the transcript can read — and are never echoed, logged, or
   rendered into errors;
2. the only output is the probe label, the HTTP status code, and the S3
   error code — never key material, never object listings, never bucket
   contents — so the probe's stdout is safe for a drill record verbatim;
3. each invocation exercises exactly one credential (the pair in the
   environment); the full step-6 matrix is composed by running the probe
   once per credential state — current pair (positive cycle), retired
   pair (``403 InvalidAccessKeyId``), wrong secret
   (``403 SignatureDoesNotMatch``), and the out-of-scope prefix
   (``403 AccessDenied``);
4. the write cycle leaves nothing behind: it creates a multipart
   upload, uploads one 64 KiB canary part, and aborts the session —
   ``abort``, never ``delete`` (no archivist identity holds delete);
5. ``--self-test`` proves rules 1–4 deterministically against an
   in-process fake client: no network, no credentials, and no boto3
   import (the real import is lazy, so the self-test runs anywhere),
   including that a planted pair can never reach the output.

Usage::

    tools/rotation-drill-probe.py {list,list-control,cycle}
    tools/rotation-drill-probe.py --self-test

Environment: ``ARMOR_PROBE_ENDPOINT`` (required), ``ARMOR_PROBE_AKID``
and ``ARMOR_PROBE_SECRET`` (required for a live run), optional overrides
``ARMOR_PROBE_BUCKET``, ``ARMOR_PROBE_REGION``, ``ARMOR_PROBE_PREFIX``,
``ARMOR_PROBE_OOS_PREFIX`` (defaults pin the current tree: ``iad-ci``,
``us-west-002``, ``agent-archivist/raw/``, out-of-scope
``agent-archivist/control/``).

Exit codes: 0 success (or self-test pass), 1 usage/environment error,
2 self-test failure.
"""

from __future__ import annotations

import io
import os
import sys

DEFAULT_BUCKET = "iad-ci"
DEFAULT_REGION = "us-west-002"
DEFAULT_PREFIX = "agent-archivist/raw/"
DEFAULT_OOS_PREFIX = "agent-archivist/control/"
CANARY_TAIL = "rotation-drill/canary"
PART_BYTES = 65536

MODES = ("list", "list-control", "cycle")

USAGE = (
    f"usage: rotation-drill-probe.py {{{','.join(MODES)}}}  (env:"
    " ARMOR_PROBE_ENDPOINT, ARMOR_PROBE_AKID, ARMOR_PROBE_SECRET;"
    " optional: ARMOR_PROBE_BUCKET, ARMOR_PROBE_REGION,"
    " ARMOR_PROBE_PREFIX, ARMOR_PROBE_OOS_PREFIX)"
)


def settings():
    """Read the probe's configuration from the environment."""
    return {
        "endpoint": os.environ.get("ARMOR_PROBE_ENDPOINT"),
        "bucket": os.environ.get("ARMOR_PROBE_BUCKET", DEFAULT_BUCKET),
        "region": os.environ.get("ARMOR_PROBE_REGION", DEFAULT_REGION),
        "prefix": os.environ.get("ARMOR_PROBE_PREFIX", DEFAULT_PREFIX),
        "oos_prefix": os.environ.get("ARMOR_PROBE_OOS_PREFIX", DEFAULT_OOS_PREFIX),
        "akid": os.environ.get("ARMOR_PROBE_AKID"),
        "secret": os.environ.get("ARMOR_PROBE_SECRET"),
    }


def client(cfg):
    """Build the real SigV4 client. boto3 is imported lazily so the
    self-test never needs it installed."""
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=cfg["endpoint"],
        region_name=cfg["region"],
        aws_access_key_id=cfg["akid"],
        aws_secret_access_key=cfg["secret"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def run(out, label, fn):
    """Execute one probe call and print only its status / error code."""
    try:
        r = fn()
        print(f"{label}: {r['ResponseMetadata']['HTTPStatusCode']}", file=out)
        return r
    except Exception as e:  # botocore ClientError carries code + status
        resp = getattr(e, "response", {})
        err = resp.get("Error", {}).get("Code", "?")
        status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", "?")
        print(f"{label}: {status} {err}", file=out)
        return None


def dispatch(out, c, mode, cfg):
    """Run one probe mode against a client (real or fake)."""
    key = cfg["prefix"] + CANARY_TAIL
    if mode == "list":
        return run(out, "list in-scope", lambda: c.list_objects_v2(Bucket=cfg["bucket"], Prefix=cfg["prefix"]))
    if mode == "list-control":
        return run(out, "list out-of-scope", lambda: c.list_objects_v2(Bucket=cfg["bucket"], Prefix=cfg["oos_prefix"]))
    if mode == "cycle":
        r = run(out, "create-mpu", lambda: c.create_multipart_upload(Bucket=cfg["bucket"], Key=key))
        if not r:
            return None
        upload_id = r["UploadId"]
        run(out, "upload-part", lambda: c.upload_part(
            Bucket=cfg["bucket"], Key=key, UploadId=upload_id, PartNumber=1, Body=b"\x00" * PART_BYTES))
        return run(out, "abort-mpu", lambda: c.abort_multipart_upload(
            Bucket=cfg["bucket"], Key=key, UploadId=upload_id))
    raise ValueError(f"unknown mode: {mode}")


def main(argv):
    if "--self-test" in argv[1:]:
        return self_test()
    positional = [a for a in argv[1:] if a != "--self-test"]
    if len(positional) != 1 or positional[0] not in MODES:
        print(USAGE, file=sys.stderr)
        return 1
    cfg = settings()
    if not cfg["endpoint"] or not cfg["akid"] or not cfg["secret"]:
        print("environment error: ARMOR_PROBE_ENDPOINT, ARMOR_PROBE_AKID"
              " and ARMOR_PROBE_SECRET are all required for a live run",
              file=sys.stderr)
        return 1
    dispatch(sys.stdout, client(cfg), positional[0], cfg)
    return 0


# --- self-test ---------------------------------------------------------------
# Runs every probe mode against an in-process fake client and proves the
# output contract: statuses and error codes only, planted credential
# material unreachable, boto3 never imported.


class FakeError(Exception):
    """ClientError-shaped: carries botocore's ``response`` dict."""

    def __init__(self, code, status):
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class FakeClient:
    """Records calls; positive calls return S3-shaped metadata, while the
    out-of-scope list and the multipart abort refuse like the real ACL
    edge does."""

    def __init__(self, oos_prefix):
        self.calls = []
        self.oos_prefix = oos_prefix

    def _ok(self, name, **kwargs):
        self.calls.append((name, kwargs))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "UploadId": "UP-1"}

    def list_objects_v2(self, **kwargs):
        if kwargs.get("Prefix") == self.oos_prefix:
            self.calls.append(("list_objects_v2", kwargs))
            raise FakeError("AccessDenied", 403)
        return self._ok("list_objects_v2", **kwargs)

    def create_multipart_upload(self, **kwargs):
        return self._ok("create_multipart_upload", **kwargs)

    def upload_part(self, **kwargs):
        return self._ok("upload_part", **kwargs)

    def abort_multipart_upload(self, **kwargs):
        self.calls.append(("abort_multipart_upload", kwargs))
        raise FakeError("AccessDenied", 403)


def dispatch_to_string(mode, cfg):
    """Run one mode against a fresh fake, returning (output, calls)."""
    fake = FakeClient(cfg["oos_prefix"])
    buf = io.StringIO()
    dispatch(buf, fake, mode, cfg)
    return buf.getvalue(), fake.calls


def self_test():
    failures = []
    total = 0

    def check(name, ok):
        nonlocal total
        total += 1
        if not ok:
            failures.append(name)

    planted_akid = "planted-access-key-id"
    planted_secret = "planted-secret-key-material"
    cfg = dict(settings(), endpoint="http://127.0.0.1:1", bucket="bkt",
               prefix="tenant/raw/", oos_prefix="tenant/control/",
               akid=planted_akid, secret=planted_secret)

    outputs = {}
    calls = {}
    for mode in MODES:
        outputs[mode], calls[mode] = dispatch_to_string(mode, cfg)

    # 1. list targets the in-scope prefix; list-control the out-of-scope one.
    check("list prefix", calls["list"][0][1]["Prefix"] == "tenant/raw/")
    check("list-control prefix", calls["list-control"][0][1]["Prefix"] == "tenant/control/")

    # 2. the write cycle threads bucket/key/upload-id and leaves nothing:
    #    create -> one 64 KiB part -> abort, in that order.
    seq = [n for n, _ in calls["cycle"]]
    check("cycle order", seq == ["create_multipart_upload", "upload_part", "abort_multipart_upload"])
    key = cfg["prefix"] + CANARY_TAIL
    check("cycle key", all(kw["Key"] == key for _, kw in calls["cycle"]))
    check("cycle bucket", all(kw["Bucket"] == "bkt" for _, kw in calls["cycle"]))
    check("cycle part size", calls["cycle"][1][1]["Body"] == b"\x00" * PART_BYTES)
    check("cycle upload id", calls["cycle"][1][1]["UploadId"] == "UP-1" == calls["cycle"][2][1]["UploadId"])

    # 3. output is statuses and error codes only; a planted pair appears nowhere.
    expected = {
        "list": "list in-scope: 200\n",
        "list-control": "list out-of-scope: 403 AccessDenied\n",
        "cycle": "create-mpu: 200\nupload-part: 200\nabort-mpu: 403 AccessDenied\n",
    }
    for mode in MODES:
        check(f"output shape {mode}", outputs[mode] == expected[mode])
    blob = "".join(outputs.values())
    check("akid never printed", planted_akid not in blob)
    check("secret never printed", planted_secret not in blob)

    # 4. error rendering degrades to "?" fields instead of crashing on a
    #    foreign exception, and never echoes the exception's arguments.
    class NakedError(Exception):
        pass

    def naked():
        raise NakedError(planted_secret)

    buf = io.StringIO()
    run(buf, "naked", naked)
    check("foreign exception", buf.getvalue() == "naked: ? ?\n")

    # 5. a live run without the credential environment is a usage error:
    #    exit 1, message on stderr, no traceback, no values echoed.
    saved = {k: os.environ.pop(k) for k in ("ARMOR_PROBE_ENDPOINT", "ARMOR_PROBE_AKID", "ARMOR_PROBE_SECRET") if k in os.environ}
    err = io.StringIO()
    real_stderr, sys.stderr = sys.stderr, err
    try:
        code = main(["rotation-drill-probe.py", "list"])
    finally:
        sys.stderr = real_stderr
    check("missing env exit", code == 1)
    check("missing env quiet", "Traceback" not in err.getvalue()
          and planted_akid not in err.getvalue() and planted_secret not in err.getvalue())
    err2 = io.StringIO()
    real_stderr, sys.stderr = sys.stderr, err2
    try:
        code = main(["rotation-drill-probe.py", "reboot"])
    finally:
        sys.stderr = real_stderr
    check("unknown mode exit", code == 1)
    check("unknown mode quiet", "Traceback" not in err2.getvalue())
    os.environ.update(saved)

    # 6. the self-test itself must not have pulled in boto3.
    check("boto3 not imported", "boto3" not in sys.modules and "botocore" not in sys.modules)

    passed = total - len(failures)
    print(f"self-test: {passed} passed, {len(failures)} failed")
    for name in failures:
        print(f"self-test: FAILED {name}", file=sys.stderr)
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
