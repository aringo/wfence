#!/usr/bin/env python3
"""Fetch the Wordfence Intelligence v3 production vulnerability feed.

Writes a deterministically-compressed copy of the feed, a manifest describing
it, and a NOTICE file generated from the attribution data embedded in the feed
records themselves.

Standard library only, by design: this runs in CI with a live API credential in
the environment, and every third-party dependency is another package that could
read that environment.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_BASE = "https://www.wordfence.com/api/intelligence/v3"
FEED = "production"

# Wordfence's published default is one request per 30 minutes. We make one
# request per run, twice a day. Retries are deliberately few and slow so a
# transient failure never turns into hammering a rate-limited endpoint.
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 60
REQUEST_TIMEOUT = 300

# Refuse to publish if the record count collapses relative to the last good
# sync. A truncated or partially-served feed is worse than a stale one, because
# downstream tooling reads "absent" as "not vulnerable".
MIN_RECORDS = 1000
MAX_SHRINK_RATIO = 0.10

USER_AGENT = (
    "wordfence-db-mirror/1.0 (+https://github.com/{repo}; scheduled 12h cache)"
)


class SyncError(RuntimeError):
    """Fatal, non-retryable problem with the sync."""


def log(message: str) -> None:
    print(message, flush=True)


def fetch_feed(token: str, repo: str) -> bytes:
    """GET the production feed, returning raw (decompressed) response bytes."""
    url = f"{API_BASE}/vulnerabilities/{FEED}"
    request = urllib.request.Request(
        url,
        headers={
            # The token is only ever placed in a header on an outbound request.
            # It is never logged, never written to disk, and never interpolated
            # into a shell command.
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT.format(repo=repo or "wordfence-db-mirror"),
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )

    last_error: Exception | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            log(f"Requesting {url} (attempt {attempt}/{MAX_ATTEMPTS})")
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                payload = response.read()
                if response.headers.get("Content-Encoding") == "gzip":
                    log(f"Received {len(payload):,} bytes gzip-encoded; decompressing")
                    payload = gzip.decompress(payload)
                log(f"Received {len(payload):,} bytes of JSON")
                return payload
        except urllib.error.HTTPError as exc:
            # 401/403 mean the credential is wrong or revoked. Retrying cannot
            # fix that and only burns rate limit, so fail immediately.
            if exc.code in (401, 403):
                raise SyncError(
                    f"Authentication failed (HTTP {exc.code}). The "
                    "WORDFENCE_API_TOKEN secret is missing, malformed, or revoked. "
                    "Regenerate it under Integrations in the Wordfence dashboard."
                ) from exc
            if exc.code == 410:
                raise SyncError(
                    "HTTP 410 Gone: this feed version has been retired by Wordfence. "
                    f"Check whether {API_BASE} has been superseded."
                ) from exc
            if exc.code == 429:
                retry_after = exc.headers.get("Retry-After")
                delay = int(retry_after) if (retry_after or "").isdigit() else BACKOFF_SECONDS * attempt
                log(f"Rate limited (HTTP 429); sleeping {delay}s before retry")
                last_error = exc
                if attempt < MAX_ATTEMPTS:
                    time.sleep(delay)
                continue
            last_error = exc
            log(f"HTTP {exc.code} from API; will retry if attempts remain")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            log(f"Transport error: {exc.__class__.__name__}; will retry if attempts remain")

        if attempt < MAX_ATTEMPTS:
            time.sleep(BACKOFF_SECONDS * attempt)

    raise SyncError(f"Feed request failed after {MAX_ATTEMPTS} attempts: {last_error}")


def validate(records: object) -> dict:
    """Structural sanity check on the decoded feed."""
    if not isinstance(records, dict):
        raise SyncError(f"Expected a JSON object keyed by vulnerability id, got {type(records).__name__}")
    if len(records) < MIN_RECORDS:
        raise SyncError(f"Feed contained only {len(records)} records; refusing to publish a likely-truncated feed")

    required = {"id", "title", "software", "references", "copyrights"}
    sample_key = next(iter(records))
    sample = records[sample_key]
    if not isinstance(sample, dict):
        raise SyncError(f"Record {sample_key!r} is not an object")
    missing = required - set(sample)
    if missing:
        raise SyncError(f"Record {sample_key!r} is missing expected fields: {sorted(missing)}")
    return records


def check_shrinkage(count: int, manifest_path: Path, allow_shrink: bool = False) -> None:
    """Guard against a good cached copy being replaced by a degraded feed."""
    if not manifest_path.exists():
        return
    try:
        previous = json.loads(manifest_path.read_text())
        previous_count = int(previous["record_count"])
    except (json.JSONDecodeError, KeyError, ValueError, OSError):
        log("Previous manifest unreadable; skipping shrink check")
        return

    if previous_count <= 0:
        return
    shrink = (previous_count - count) / previous_count
    if shrink > MAX_SHRINK_RATIO:
        message = (
            f"Record count fell from {previous_count:,} to {count:,} "
            f"({shrink:.1%} drop, limit {MAX_SHRINK_RATIO:.0%})."
        )
        if allow_shrink:
            # Deliberate override. A plain re-run will NOT clear this check --
            # it compares against the committed manifest, which does not change
            # on a failed run -- so a legitimate upstream purge would otherwise
            # wedge the sync permanently.
            log(f"::warning::{message} Publishing anyway (--allow-shrink).")
            return
        raise SyncError(
            f"{message} Refusing to publish. If the drop is legitimate, re-run "
            "the workflow with the allow_shrink input set to true."
        )
    log(f"Shrink check passed: {previous_count:,} -> {count:,} records")


def collect_attribution(records: dict) -> tuple[list[str], list[dict]]:
    """Pull the copyright/license data Wordfence embeds in every record.

    Section 3.1 of the Intelligence terms conditions authorized copies on
    reproducing the copyright designation, the license, and the licenses of
    disclosed licensors. The feed carries all three per record, so we derive
    the NOTICE from the data rather than hand-maintaining it.
    """
    messages: dict[str, None] = {}
    licensors: dict[tuple[str, str, str], None] = {}

    for record in records.values():
        copyrights = record.get("copyrights")
        if not isinstance(copyrights, dict):
            continue
        for key, value in copyrights.items():
            if key == "message":
                if isinstance(value, str) and value.strip():
                    messages[value.strip()] = None
                continue
            if not isinstance(value, dict):
                continue
            entry = (
                str(value.get("notice", "")).strip(),
                str(value.get("license", "")).strip(),
                str(value.get("license_url", "")).strip(),
            )
            if any(entry):
                licensors[entry] = None

    return (
        sorted(messages),
        [
            {"notice": notice, "license": license_name, "license_url": license_url}
            for notice, license_name, license_url in sorted(licensors)
        ],
    )


def render_notice(messages: list[str], licensors: list[dict], count: int, fetched_at: str) -> str:
    lines = [
        "# NOTICE",
        "",
        "This repository redistributes the Wordfence Intelligence vulnerability",
        "database. The vulnerability intelligence itself is provided by",
        "**Wordfence Intelligence / Defiant, Inc.**",
        "",
        "Copyright and ownership of the underlying database remain with Defiant, Inc.",
        "and with the applicable owners of any Third-Party Materials it contains.",
        "This project claims no ownership of the vulnerability data and does not",
        "license it as its own work. It is redistributed pursuant to the Wordfence",
        "Intelligence Terms and Conditions.",
        "",
        f"Snapshot: {count:,} records, retrieved {fetched_at}.",
        "",
        "---",
        "",
        "## Attribution supplied by Wordfence with this data",
        "",
        "The statements below are reproduced verbatim from the `copyrights` field of",
        "the feed records. This file is regenerated on every sync, so it always",
        "reflects the attribution attached to the data actually being distributed.",
        "",
    ]

    if messages:
        for message in messages:
            lines.extend([f"> {message}", ""])
    else:
        lines.extend(["_No copyright message was present in this snapshot._", ""])

    lines.extend(["## Disclosed licensors and Third-Party Materials", ""])
    if licensors:
        for entry in licensors:
            if entry["notice"]:
                lines.append(f"- **{entry['notice']}**")
            if entry["license"]:
                suffix = f" — <{entry['license_url']}>" if entry["license_url"] else ""
                lines.append(f"  - License: {entry['license']}{suffix}")
        lines.append("")
        lines.extend([
            "Third-Party Materials remain subject to the rights and licenses of their",
            "respective holders. Wordfence's grant cannot convey rights it does not",
            "itself hold, so consult the licenses above before relying on any",
            "individual third-party record.",
            "",
        ])
    else:
        lines.extend(["_No separately disclosed licensors were present in this snapshot._", ""])

    lines.extend([
        "---",
        "",
        "Per-record `copyrights` fields are preserved intact in the distributed JSON.",
        "Do not strip them when deriving your own datasets.",
        "",
    ])
    return "\n".join(lines)


def write_gzip(path: Path, payload: bytes) -> None:
    """Write gzip with a fixed mtime so identical data yields identical bytes."""
    with open(path, "wb") as handle:
        with gzip.GzipFile(fileobj=handle, mode="wb", compresslevel=9, mtime=0) as gz:
            gz.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync the Wordfence Intelligence production feed")
    parser.add_argument("--data-dir", default="data", type=Path)
    parser.add_argument("--out-dir", default="dist", type=Path)
    parser.add_argument(
        "--allow-shrink",
        action="store_true",
        help="Publish even if the record count dropped past the shrink threshold. "
             "Required to recover after a legitimate upstream purge.",
    )
    args = parser.parse_args()

    token = os.environ.get("WORDFENCE_API_TOKEN", "").strip()
    if not token:
        raise SyncError(
            "WORDFENCE_API_TOKEN is not set. In GitHub Actions this must come from "
            "an encrypted repository secret passed via the step's `env:` block."
        )

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    args.data_dir.mkdir(parents=True, exist_ok=True)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    raw = fetch_feed(token, repo)

    try:
        records = validate(json.loads(raw))
    except json.JSONDecodeError as exc:
        raise SyncError(f"API returned malformed JSON: {exc}") from exc

    count = len(records)
    log(f"Validated {count:,} vulnerability records")

    manifest_path = args.data_dir / "manifest.json"
    check_shrinkage(count, manifest_path, allow_shrink=args.allow_shrink)

    # Canonicalise before hashing so "did the data change" is a question about
    # content, not about key ordering or whitespace from the API.
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    content_sha = hashlib.sha256(canonical).hexdigest()

    archive_path = args.out_dir / "wordfence-vulnerabilities-production.json.gz"
    write_gzip(archive_path, canonical)
    archive_bytes = archive_path.read_bytes()
    archive_sha = hashlib.sha256(archive_bytes).hexdigest()

    ratio = len(archive_bytes) / len(canonical) if canonical else 0
    log(
        f"Compressed {len(canonical):,} -> {len(archive_bytes):,} bytes "
        f"({ratio:.1%} of original)"
    )

    fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    messages, licensors = collect_attribution(records)
    log(f"Collected {len(messages)} copyright message(s), {len(licensors)} disclosed licensor(s)")

    notice = render_notice(messages, licensors, count, fetched_at)
    Path("NOTICE.md").write_text(notice)
    (args.out_dir / "NOTICE.md").write_text(notice)

    previous_sha = ""
    if manifest_path.exists():
        try:
            previous_sha = json.loads(manifest_path.read_text()).get("content_sha256", "")
        except (json.JSONDecodeError, OSError):
            pass
    changed = previous_sha != content_sha

    manifest = {
        "source": "Wordfence Intelligence",
        "source_url": f"{API_BASE}/vulnerabilities/{FEED}",
        "feed": FEED,
        "fetched_at": fetched_at,
        "record_count": count,
        "content_sha256": content_sha,
        "archive_filename": archive_path.name,
        "archive_sha256": archive_sha,
        "archive_bytes": len(archive_bytes),
        "uncompressed_bytes": len(canonical),
        "schedule": "every 12 hours",
        "attribution": "NOTICE.md",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (args.out_dir / f"{archive_path.name}.sha256").write_text(f"{archive_sha}  {archive_path.name}\n")

    log(f"Content {'changed' if changed else 'unchanged'} since last sync (sha256 {content_sha[:12]})")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as handle:
            handle.write(f"changed={'true' if changed else 'false'}\n")
            handle.write(f"record_count={count}\n")
            handle.write(f"fetched_at={fetched_at}\n")
            handle.write(f"content_sha256={content_sha}\n")
            handle.write(f"archive_sha256={archive_sha}\n")
            handle.write(f"archive_bytes={len(archive_bytes)}\n")
            handle.write(f"archive_filename={archive_path.name}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SyncError as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
