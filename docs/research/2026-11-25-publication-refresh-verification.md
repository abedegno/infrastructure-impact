# Publication and reliability refresh verification

This milestone separates accepted Pages upload from deployment, reduces repeated
analysis decoding/validation work, and adds explicit local release-reliability
candidate preparation. No schedules, permissions, credentials, default source
activation, frozen studies or packaged catalogue facts change.

## Verification before release

- Pages:295 focused checks and12 subtests passed, plus the final 9-case isolation
  suite. Independent review passed producer/preview/failure/legacy gates and
  captured source/generation propagation. Live dependent-job execution is a
  release check, not inferred from local tests.
- Analysis:801 broader checks passed with one expected skip; three sandbox
  loopback-restricted monitor checks passed when rerun with loopback available.
  Codec/selector/delivery Node suites and formatting passed. The [matched public
  benchmark](2026-11-25-analysis-loading-performance.md) retained both complete
  selected-output hashes: 94.48→63.60 seconds for cold timed phases and 33.46→12.76
  for a repeated selection. Traffic and counts remained identical. The optimized
  run's memory peak was higher; payload size and browser memory remain limitations.
- Refresh:44focused tests passed after real-pilot and independent-review fixes.
  Scoped integration checks passed with the correct locked interpreter. Three
  independently hashed original public captures produced 8 Catalyst 9200,
  8 Catalyst 9300 and 2 Arista announcement observations. Candidate replay was
  byte-identical, retaining 51 release observations and 27 source receipts with no
  pending pilot conflicts. Packaged facts were unchanged and all rates unavailable.

The original-byte pilot used only existing captures; it made no vendor requests.
Invalid conditional validators, malformed identities, conflicting observations and
filesystem aliases have explicit regressions. Human review remains pending.
Full release CI, final whole-branch review and live publication are separate gates.

## Activation boundary

The new [refresh CLI](../RELIABILITY_REFRESH.md) is explicit and does not publish
its candidate. Cisco network collection needs the documented current policy
receipt and an allowed robots response. Arista remains offline, and no Aruba
route is activated. No reviewed policy approval is fabricated by the pilot.
Historical denominator and notice gaps remain unknown. Counts describe publisher
disclosure and collection, not vendor security quality.
