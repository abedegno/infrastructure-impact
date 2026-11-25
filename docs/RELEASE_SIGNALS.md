# Switching release signals

This local research workflow covers Cisco IOS XE 17.12, Aruba AOS-CX 10.13
and Arista EOS 4.33 for 2024–2026. The 2026 sample is partial. Independent
human review is pending. The packaged dataset starts with coverage gaps and
an empty evidence inventory. See the
[feasibility study](research/2026-11-25-release-signals-feasibility.md)
for the source-access matrix and sample limitations.

## Generate a report

From the repository root or an installed environment, choose a private
working directory outside the repository. Keep captured documents, the
working dataset and generated reports there. Use public evidence and
remove any customer data from an optional staircase export before use.

```sh
signals_dir="$(mktemp -d)"
python -m infrastructure_impact.release_signals_cli init \
  --dataset "$signals_dir/dataset.json" --generated-at 2026-11-25T12:00:00Z
```

For an existing local capture, set the input path and use its actual
source URL, retrieval time and capture method. This example uses a saved
Arista software RSS response and assumes the operator retained those
bytes at the stated retrieval time.

```sh
python -m infrastructure_impact.release_signals_cli import-document \
  --dataset "$signals_dir/dataset.json" --parser arista-rss \
  --source-url https://www.arista.com/en/support/release-notes \
  --input "$signals_dir/arista-software-rss.xml" \
  --retrieved-at 2026-11-25T12:00:00Z --capture-method http_response
```

The Cisco `cisco-caveats` parser takes retained HTML from the reviewed
Catalyst 9300 17.12 caveat chapter. [Cisco caveats](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/caveats.html)

The Aruba `aruba-history` parser takes a complete local HTML rendering of
the AOS-CX 10.13.1040 release notes for 6300 and 6400 switches. Supply
the original PDF URL and `--capture-method rendered_capture`. The
recorded fingerprint describes the retained rendering.
[Aruba release notes](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/RN/rn_6300-6400_10-13-1040.pdf)

The three readers extract release announcements, release history and resolved
caveat disclosures from their matching URLs and reviewed layouts. Collectors
for formal withdrawals, deferments, corrective respins, field notices and
recommendations are deferred pending verification of public source layouts.
The schema supports those evidence types for future collectors. Feasibility
study excerpts stay outside the dataset. Record blocked,
incomplete and uncollected periods as coverage gaps.

After reviewing source-specific usage terms, operators may explicitly
collect the public Arista software RSS.

```sh
python -m infrastructure_impact.release_signals_cli collect-arista \
  --dataset "$signals_dir/dataset.json" --cache-dir "$signals_dir/arista-cache"
```

The collector is bounded and anonymous. Login redirects, access-denied
responses and challenge pages cannot provide release evidence. Use an
authorized source when access is restricted. Place the cache outside Git
worktrees. Captured RSS files use the retained-byte SHA-256 as the
filename. The dataset records the source URL,
retained-byte SHA-256, retrieval time, capture method and evidence locator.
Reobserving identical latest bytes advances the dataset cutoff and retains the
original document revision. Changed bytes create a new revision linked to the
previous one. Reports keep Arista announcements from earlier rolling RSS
snapshots and use the newest observation when an item reappears. Static
documents contribute facts from their latest retained revisions.

```sh
python -m infrastructure_impact.release_signals_cli report \
  --dataset "$signals_dir/dataset.json" --start 2024-01-01 --end 2026-11-25 \
  --json-output "$signals_dir/report.json" --csv-output "$signals_dir/report.csv"
```

Add `--upgrades /path/to/staircase.json` when you have a compatible
switching upgrade report. Target annotations preserve the original scenario,
policy and claim IDs. An annotation can describe chronology using retained
evidence while model applicability remains unresolved.

## Read the report locally

From the repository root, serve the existing static assets on loopback.

```sh
python -m http.server 8000 --bind 127.0.0.1 --directory web
```

Open `http://127.0.0.1:8000/release-signals.html` and choose the generated
JSON. The page accepts reports up to 4 MiB and reads the selected file
in memory. Vendor links in source receipts open on demand. The reader is
standalone and intended for explicit local use.

## Interpret the observations

- Annual rows show observed sample counts. Coverage outside retained source
  material is unknown, and the release denominator needed for withdrawal
  rates is unavailable. A zero sample count only describes the retained
  observations in that row. Conflicting dates in a single year can support one
  release, withdrawal, deferment or corrective respin count. When the available
  dates span years, the report withholds annual attribution and retains source
  receipts for conflicting dates outside the selected window.
- Explicit withdrawals and deferments record publisher actions. Confirmed
  corrective respins require publisher evidence linking a predecessor
  (`related_release`) to its replacement (`release`). The source receipt
  shows the predecessor followed by the replacement. A corrective respin
  can annotate upgrade targets for the predecessor and replacement.
  Field notices and recommendations provide additional context.
- Candidate pairs compare dated adjacent releases with matching platform
  scope. The 14-day and 30-day flags show sensitivity to the chosen
  interval. An unconfirmed pair describes timing alone. The short RSS
  window cannot backfill earlier periods.
- Bug IDs are disclosure counts. Vendor publication practices and source
  coverage both affect them, so they cannot establish software quality.
- An empty platform list means unresolved model scope. For upgrade target
  annotations, a later date describes chronology alone. An exact target
  match still requires separate evidence of model applicability. A target
  with no retained evidence has an unknown signal history.
