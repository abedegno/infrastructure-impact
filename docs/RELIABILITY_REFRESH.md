# Prepare release reliability evidence

The refresh CLI creates a local catalogue candidate and a separate pending-review
report. The published reliability view uses its packaged catalogue. Use the
candidate and report together when reviewing additions or conflicts.

## Offline import and preparation

Pass original response body bytes and the timestamp of the original retrieval,
including its timezone. On macOS the examples below use `/private/tmp`; use an
equivalent directory outside Git on other systems.

```sh
python -m infrastructure_impact.reliability_refresh_cli import-capture \
  --source cisco-c9200-rommon \
  --input /private/tmp/c9200-rommon.html \
  --retrieved-at "$ORIGINAL_RETRIEVED_AT" \
  --cache-dir /private/tmp/reliability-refresh-cache

python -m infrastructure_impact.reliability_refresh_cli prepare \
  --cache-dir /private/tmp/reliability-refresh-cache \
  --output /private/tmp/reliability-candidate.json \
  --report /private/tmp/reliability-review.json
```

`prepare` defaults to the packaged catalogue. Use `--catalogue PATH` to start
from a different validated version 1 baseline. Give the baseline, candidate and
review report distinct paths. Both output parent directories must exist. Each
output is staged and then replaced atomically. If the candidate replacement
fails, the CLI restores the previous review or removes the new review. The
review report's candidate SHA-256 is the reliability preview's canonical JSON
digest and identifies the candidate used for validation.

| Source ID | Evidence read | Collection mode |
| --- | --- | --- |
| `cisco-c9200-rommon` | Catalyst 9200 IOS XE Dublin 17.12 Boot Loader Versions table | Offline import or policy-gated Cisco request |
| `cisco-c9300-rommon` | Catalyst 9300 IOS XE Dublin 17.12 ROMMON Versions table | Offline import or policy-gated Cisco request |
| `arista-eos-rss` | EOS 4.33 availability announcements in the software RSS channel | Offline import |

Cisco table rows state a version and model family. Their release and
announcement dates remain unknown. Arista items state announcement timestamps.
The candidate keeps the UTC announcement day and literal title. The report
retains the original `pubDate` with the RSS item locator. Binary release dates
and model applicability remain unknown. A revision's omitted versions are
evidence of a change to the observed document, and the older observations stay
in the candidate. Dates or scopes that conflict with retained facts appear in
the report with provenance for both observations. Coverage and independent
human review status are carried forward from the baseline.

## Cisco policy receipt

`collect` requires an explicit, current policy review for the chosen route.
Create the receipt after reviewing the current vendor terms and the intended
request. The CLI expects a JSON object with these fields.

| Field | Value |
| --- | --- |
| `schema_version` | `1` |
| `allowed_source_ids` | Explicit list of reviewed Cisco source IDs |
| `reviewed_at` | ISO 8601 timestamp with timezone, within the previous 30 days |
| `terms_url` | Reviewed public Cisco HTTPS terms URL |
| `terms_locator` | Section or other locator for the reviewed terms |
| `terms_sha256` | Lowercase SHA-256 of the reviewed terms capture |

```sh
python -m infrastructure_impact.reliability_refresh_cli collect \
  --source cisco-c9200-rommon \
  --cache-dir /private/tmp/reliability-refresh-cache \
  --policy-receipt /private/tmp/cisco-policy-receipt.json
```

A current, substantive Cisco robots response must allow the exact registered
path. The CLI uses direct HTTPS GETs and refuses redirects, authorization and
cookies. Use one shared cache for cooperating runs. It enforces at least one
second between Cisco requests, including robots, and uses a larger recognized
robots delay when present. The document body limit is 4 MiB. Access challenges,
denials, rate limits, policy failures and unsupported documents leave the
latest good revision in place. Collection is explicit. Arista remains offline
and this CLI has no schedule.

## Cache contract

The cache directory contains immutable response bodies under `bodies/<sha256>`
and one atomic JSON manifest per source ID. The manifest records the fixed URL,
first receipt time, `operator` or `network` origin, body size and media type for
each digest. Its revision list links transitions by predecessor digest,
including transitions back to previously seen bytes. The latest digest's
conditional HTTP validators and last check outcome are separate from the first
receipt. A byte-identical import or HTTP 200, and a verified HTTP 304, preserve the
first receipt and existing revision chain.

The CLI verifies body length, SHA-256 and supported source shape during
preparation and before accepting a 304. It rejects Git paths and symlinked
cache paths. A failed metadata write can leave an unreferenced body, which
preparation will ignore. Keep the cache outside Git and retain it alongside the
local review outputs for reproducible replay.
