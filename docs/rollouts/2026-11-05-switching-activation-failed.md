# v0.9.0 controlled activation failure — 5 November 2026

Status: **source published; controlled run cancelled; runtime pin rolled back**.
This dated receipt supplements the historical 4 November proposal without
rewriting its measurements or claiming a successful activation.

The approved source `a50b4ace4291118e5466245da3a9534391056258` merged through
PR 21 and was published as the immutable v0.9.0 tag/release. Controlled collector
run `42002705178` was cancelled at its 40-minute cap before Pages deployment.
The old runtime pin `5f15a88a956d783190a70aa1b99a3138aca24f76` was restored.
Public generation `5090cf350ad24619b468bdca7ad0eafc` remained served. No second
collector run or new recovery receipt is asserted.

The final completed benchmark import log was followed by a 2,290.600-second
silent interval before cancellation. There was no phase traceback, so the exact
failed runner stack and operation are unknown. A later public Cisco capture has
different bytes from the retained public snapshot and does not reproduce that
historical run exactly.

Offline diagnosis nevertheless established a severe scaling defect: a shared
CSAF CVSS score and remediation repeated their full product scopes in every
product claim. A current 866,539-byte public source with 1,529 products would
produce 729,431,775 compact bytes of unprojected claim data. That size was
calculated from serialized pieces without allocating the full expansion.
The earlier public snapshot independently contains the same topology with
1,522 products. The dedicated stage contained only 16 Cisco claims and did not
represent this workload. Unresolved-family claims still require extraction and
strict validation even when absent from selected comparison rows.

The replacement is the separately reviewed 0.9.1 candidate. The published 0.9.0
source and release assets remain immutable. Existing workflow timeouts, storage,
part/index/monitor/archive limits, schedules, permissions, source defaults and
recovery settings remain unchanged. Public captures and operational receipts
stay outside source history and release assets.
