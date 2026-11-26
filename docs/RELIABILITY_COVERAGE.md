# Interpret release reliability coverage

The switching comparison's **Coverage gaps by model** view is derived from the
same accepted release-reliability report as the metrics. Its JSON and CSV exports
retain the publication, generation, catalogue fingerprint, source receipts and
fact locators. It does not collect data or change a coverage judgement.

For each explicitly named model, it lists observed version identities, dates
supported by original captures, dates supported only by research excerpts, and
versions without a release date. Repeated observations do not inflate inventory.
A dated observation resolves an older undated observation only for the same
model/version. Original dated evidence takes precedence over research-only dates
in the inventory; original evidence does not itself establish completeness.

Versions or notices without stated model scope remain unbound. Other-platform
observations remain separately visible. Announcement dates are retained as
announcements, never substituted for binary release dates. Undated versions
cannot be assigned to annual release totals. All underlying evidence and existing
period/metric coverage reasons accompany the export.

**Observed inventory is not a denominator.** An empty model inventory means no
qualifying model-bound observations were retained; it does not mean no releases
shipped. Complete release enumeration, original date/scope evidence and complete
signal history are still required for rates. Counts describe disclosure and
collection, not vendor quality. Independent human review remains pending.

## Offline export

Use a retained public `release-reliability.json` report. No database, credentials
or network access is needed. Output must differ from the input (including aliases).

```sh
python -m infrastructure_impact.reliability_coverage_cli \
  --input /private/tmp/release-reliability.json \
  --output /private/tmp/reliability-coverage.json
python -m infrastructure_impact.reliability_coverage_cli \
  --input /private/tmp/release-reliability.json \
  --output /private/tmp/reliability-coverage.csv --format csv
```

CSV includes model inventories, per-period metric reasons, unbound observations,
release/notice facts, source receipts and limitations. JSON embedded in CSV uses
the project's exact finite-number token convention for cross-runtime parity;
this changes numeric spelling, not values. CSV cells are spreadsheet-safe.
Unavailable legacy reports produce an explicitly unavailable coverage view.
