# Wordfence Vulnerability Database Mirror

A cached, compressed copy of the [Wordfence Intelligence](https://www.wordfence.com/products/wordfence-intelligence/)
production vulnerability feed, refreshed on a fixed schedule and published as a
release asset.

> **Data provided by Wordfence Intelligence / Defiant, Inc.**
> Copyright and ownership of the vulnerability data remain with Defiant, Inc. and
> with the applicable owners of any Third-Party Materials it contains. This
> project claims no ownership of that data. See [NOTICE.md](NOTICE.md).

## Read this first: what this is and is not

**This is a cached snapshot, not a live feed.** It is refreshed **every 12 hours**,
at **05:17 and 17:17 UTC**. Any copy you download can therefore be **up to 12
hours behind** Wordfence. If your use case needs vulnerability data the moment it
is published, do not use this mirror — query the Wordfence Intelligence API
directly with your own account.

The design is deliberately conservative about how often the upstream API is
touched:

- **Two API requests per day, total.** One authorized account fetches the feed on
  a schedule; every downstream consumer reads the cached copy. This replaces the
  pattern where N tools each hold a credential and poll independently.
  Wordfence's published default rate limit is one request per 30 minutes, so this
  sits far below it by construction.
- **Distributed compressed.** The feed is roughly 123 MB of raw JSON. It is
  published gzipped, which is a large reduction in transfer size for both you and
  anyone consuming this mirror.
- **Content-addressed.** A new release asset is only published when the data
  actually changed. `data/manifest.json` records the SHA-256 of the canonical
  content, so consumers can check whether anything is new without downloading the
  archive.

## Consuming the data

The `data-latest` tag is a rolling pointer — the asset is replaced in place on
every sync, so this URL is stable and always serves the most recent snapshot:

```bash
curl -fL -o wordfence-vulnerabilities-production.json.gz \
  https://github.com/aringo/wfence/releases/download/data-latest/wordfence-vulnerabilities-production.json.gz
```

Verify it before you trust it:

```bash
curl -fL -O https://github.com/aringo/wfence/releases/download/data-latest/wordfence-vulnerabilities-production.json.gz.sha256
shasum -a 256 -c wordfence-vulnerabilities-production.json.gz.sha256
```

Read it without unpacking to disk:

```python
import gzip, json

with gzip.open("wordfence-vulnerabilities-production.json.gz") as fh:
    vulns = json.load(fh)

# Keyed by Wordfence vulnerability UUID.
for vuln_id, record in vulns.items():
    for software in record["software"]:
        print(software["type"], software["slug"], record.get("cve"), record["title"])
```

### Checking for updates cheaply

`data/manifest.json` is committed to this repository and is a few hundred bytes.
Fetch it, compare `content_sha256` against what you last ingested, and only pull
the archive when it differs:

```bash
curl -fsSL https://raw.githubusercontent.com/aringo/wfence/main/data/manifest.json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["content_sha256"])'
```

```json
{
  "source": "Wordfence Intelligence",
  "feed": "production",
  "fetched_at": "2026-08-19T17:17:03Z",
  "record_count": 131875,
  "content_sha256": "…",
  "archive_sha256": "…",
  "schedule": "every 12 hours"
}
```

## Attribution and licensing

The vulnerability data is redistributed under the [Wordfence Intelligence Terms
and Conditions](https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/),
which grant a perpetual, worldwide, royalty-free license to reproduce, prepare
derivative works of, sublicense, and distribute the Service — conditioned
(Section 3.1) on reproducing the copyright designation, the license, and the
licenses of disclosed licensors.

Two things follow, and both are enforced mechanically rather than by good
intentions:

1. **[NOTICE.md](NOTICE.md) is generated from the data itself.** Every feed record
   carries a `copyrights` object with the copyright message and the notice,
   license, and license URL of each disclosed licensor. The sync job extracts all
   distinct values on every run and rewrites NOTICE.md. If Wordfence changes its
   attribution requirements or adds a licensor, this mirror follows automatically
   instead of drifting out of compliance.
2. **Per-record `copyrights` fields are preserved intact** in the distributed
   JSON. If you derive your own dataset from this one, carry them through.

### If you build on this data, you inherit two conditions

Both licensors grant broad redistribution rights, and both attach conditions
that travel with the data to *you*, not just to this repository:

**Defiant** (all 38,950 records) authorizes copies "provided that you include a
hyperlink to this vulnerability record and reproduce Defiant's copyright
designation and this license in any such copy." The hyperlink is already in each
record's `references` array as
`https://www.wordfence.com/threat-intel/vulnerabilities/id/<id>`. Every sync
verifies that every record still carries it and records the count as
`records_with_canonical_link` in the manifest. **If your tool displays a
vulnerability, display that link with it.**

**MITRE** (the ~36,000 records with CVE data) grants CVE reuse "provided that you
reproduce MITRE's copyright designation and this license in any such copy."

In practice: keep the `copyrights` object on any record you store or re-emit, and
surface the Wordfence record link wherever you surface the vulnerability. Both
conditions are cheap to satisfy and are the entire price of the license.

**Third-Party Materials.** Wordfence distinguishes information it owns from
Third-Party Materials, which remain subject to their own rights holders and
licenses. Wordfence's grant cannot convey rights it does not itself hold, so
records containing vendor advisories or other externally-authored material may
carry additional restrictions. The licensors NOTICE.md lists are the place to
start.

This repository's own code — the sync script and workflow — is separate from the
data and is covered by [LICENSE](LICENSE). The license on the code does not, and
cannot, apply to the vulnerability database.

## Setup

1. Generate an API token in the **Integrations** section of your Wordfence
   account dashboard.
2. Add it as an encrypted repository secret named `WORDFENCE_API_TOKEN`
   (*Settings → Secrets and variables → Actions → New repository secret*):
   ```bash
   gh secret set WORDFENCE_API_TOKEN --repo aringo/wfence
   ```
   Paste the token at the prompt so it never enters your shell history.
3. Trigger the first run: `gh workflow run sync-wordfence-db.yml`

If you fork this, update the repository guard in
[.github/workflows/sync-wordfence-db.yml](.github/workflows/sync-wordfence-db.yml)
to your own `owner/repo` — it is pinned to `aringo/wfence` so that a fork cannot
dispatch a run expecting the upstream secret.

### How the credential is protected

- The token lives only in an encrypted GitHub Actions secret. It is never
  committed, and never distributed with the data — that distinction is the whole
  point of this architecture. Consumers get `wordfence-vulnerabilities-production.json.gz`;
  they do not get, and do not need, a Wordfence credential.
- It is passed to the sync step through the step's `env:` block, **not**
  interpolated into a `run:` script. The `${{ secrets.* }}` form inside `run:`
  substitutes the plaintext into the shell command text before execution, where
  it can surface through the process table or a shell trace. As an environment
  variable it stays in the process environment.
- The sync script never logs, prints, or writes the token. It exists only as an
  `Authorization` header on one outbound HTTPS request.
- `permissions:` is least-privilege (`contents: write` only), and
  `actions/checkout` is pinned to a commit SHA so a repointed tag cannot swap
  code into a job holding the credential.
- The workflow runs only on `schedule` and `workflow_dispatch`, never on
  `pull_request` or `pull_request_target`, so no fork-authored code executes in a
  context with access to the secret. A repository guard blocks fork dispatches.
- Rotate the token by regenerating it in the Wordfence dashboard and re-running
  `gh secret set`. No consumer is affected — they never had it.

## Reliability

The sync refuses to publish degraded data rather than overwriting a good cached
copy with a bad one:

- Fewer than 1,000 records is treated as a truncated response and rejected.
- A drop of more than 10% in record count versus the last successful sync is
  rejected. Downstream tooling reads "absent" as "not vulnerable", so a silently
  truncated feed is more dangerous than a stale one: a partial download would
  answer "no known vulnerability" for every record it happens to be missing,
  whereas a stale-but-complete copy has a bounded, knowable 12-hour gap.

  This check compares against the committed manifest, so re-running does **not**
  clear it. If a large drop is genuinely legitimate, dispatch the workflow with
  the `allow_shrink` input set to `true`; that run publishes with a warning and
  establishes the new baseline, after which scheduled runs resume normally.
- Responses are structurally validated before anything is written.
- HTTP 401/403 fail immediately without retrying, since retrying a bad credential
  only burns rate limit.
- HTTP 429 honors `Retry-After`; retries are few and slow by design.
