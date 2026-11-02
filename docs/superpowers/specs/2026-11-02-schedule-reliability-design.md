# Separate website health from scheduled-service evidence

Status: approved by the maintainer on 2 November 2026. No behavior is changed by this document.

## Goal and observed problem

Make failed Actions runs explain which promise was missed: readable and fresh public data, an expected scheduled collection/health observation, or storage capacity. Preserve failures and uncertainty rather than making the workflow green by relaxing checks.

On 1 November, public-health checks passed in runs 41334146901 and 41355786206. Their operational checks failed the existing two-hour cadence grace. The collection declared for 12:43 had no observed successful scheduled run until a run created at 18:05:45. Later, the collection was current but successful monitor observations remained overdue. This establishes late/missing observations; it does not identify the original cron slot or the reason GitHub delivered events late.

Today the health workflow also executes the cadence report. Its overall failed conclusion then feeds the next report's successful-monitor calculation. A healthy public site can therefore remain inside a sequence of cadence-related failed monitor conclusions. These historical conclusions must remain visible; future health conclusions should describe health independently.

## Approaches

1. **Separate GitHub workflows (recommended draft).** Keep Pages/Actions and the existing collector. Make `monitor.yaml` report public health only; put cadence and storage review in a separate read-only operational workflow. This removes the feedback between cadence failures and future health outcomes, without claiming reliable trigger delivery.
2. **Only improve failure messages.** Smaller, but retains the shared outcome and feedback problem.
3. **Independent fallback trigger.** An external scheduler could dispatch a collection when needed, but requires an identified host/account, credential custody and an independent freshness check. GitHub scheduling another GitHub workflow is redundancy on the same platform, not an independent fallback.

The selected approach carries forward the maintainer's existing GitHub-only hosting preference. The maintainer explicitly approved this written design after its builder check reported no important unanswered questions.

## Proposed behavior

- `Public service health` keeps its current six-hour cron, manual dispatch, pinned runtime and bounded public HTML/data/fingerprint checks. Its result reflects those checks. Retain a public-health receipt and an explanatory summary even on failure.
- A separate `Service operations` workflow runs every six hours, independently of the health workflow's conclusion, with manual dispatch available. Use a distinct minute and explicitly document that neither its timing nor its execution is guaranteed. Its checks have read-only repository/action permissions and no evidence key or vault access.
- The operations workflow runs the operational report and metadata-only backup/storage review, retaining both receipts even when another check fails. It can obtain a new bounded public-health receipt for its own report; that receipt does not stand in for a successful scheduled health run.
- Continue observing `collect.yaml` and `monitor.yaml` history. Do not count the new operations workflow as a successful scheduled health run, and do not count manual runs as scheduled observations. Keep old failed conclusions in the observation window; explain the separation's activation date in the documentation.
- Preserve the two-hour cadence grace, 36-hour publication age limit, current collection/health cron times, storage budgets, original service/cadence anchors and history limits.
- Retain existing report fields. Add explicit stable failure codes and human-readable details naming the affected workflow, expected time, latest observed successful scheduled creation time and grace deadline. Unknown observations remain unknown. A delayed creation time is not attributed to an exact original cron slot.
- Keep nonzero operational exits for overdue successful-run observations or exceeded storage budgets. Successful website health must not clear these findings.
- Operational-control code must be tied to reviewed default-branch source, rather than depend on a collector pin that lacks a newly introduced helper. Document and test the rollout order; preserve the deliberate collector runtime pin.

## Verification and rollout

Use synthetic run histories and subprocess tests to prove that a healthy site with overdue collection yields successful public health and a failed operations check, and that a website failure still fails public health. Pin clear failure details, manual/scheduled distinctions, old failed history, unknown/truncated history and preserved thresholds/anchors. Verify workflow permissions, always-retained receipts and collector/deployment-template parity.

Run the full suite, formatting, clean-source export, installed-wheel acceptance and exact-commit CI. Review the whole change before rollout. Dispatch health and operations independently after deployment and retain their actual outcomes. Manual dispatch verifies behavior; only later real scheduled events can establish observed cadence. Do not reset anchors, manufacture a week of reliability, weaken gates or delete historical evidence.

## Fallback assessment and research expansion

No independent scheduler is available within the selected GitHub-only service. Document a manual recovery procedure and the evidence an independent watchdog would need; do not provision accounts or introduce credentials. If guaranteed dispatch becomes a requirement, agree the independent host/account first.

After operational separation is implemented and verified, prepare a separate, source-led expansion proposal. Prefer comparable infrastructure roles and explicit product/build/CVE statements, keep missing vendors visible, and preserve the frozen original study/review resources. Do not add vendor rankings, denominators, verified fix-delay claims or concealment conclusions without their evidence gates. Private inventory artifacts remain unavailable.
