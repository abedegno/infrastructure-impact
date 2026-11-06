# F5 PHP reviewed profile revision — 2026-11-05

The retained public [K000163821 PDF](https://my.f5.com/manage/MyF5_KnowledgeArticlePDF?article=K000163821) was reviewed in full before changing the parser: evaluated products, description, impact, all status tables and footnotes, recommended actions and related content. Fresh layout extraction from the authorized retained capture reproduced the approved fingerprints below and the earlier full extracted text. The affected table and footnotes were also checked visually. Raw vendor documents remain outside Git; committed tests use authored synthetic text.

## Source facts

The title scopes the advisory to CVE-2026-109618 and CVE-2026-109619. Fifteen unaffected product/service rows yield 30 claims. The two affected roles, BIG-IP APM data plane (Access profile, unauthenticated attacker) and BIG-IP all-modules control plane (Configuration utility, authenticated attacker), each have 21.x and 17.x rows, yielding eight affected claims. The 21.x vulnerable version remains `21.1.0`, with `21.1.0.4` in the fix column. The 17.x vulnerable expressions remain `17.5.0 - 17.5.1` and `17.1.0 - 17.1.3`. Evaluated versions remain limited by End of Technical Support; the evaluated-products list is not the affected-products list.

The current 17.x fix-column expressions, in publisher order, are:

1. `17.5.1.11`
2. `17.1.3.7`
3. `17.5.1.10 + Hotfix-BIGIP-17.5.1.10.0.37.35-ENG`
4. `17.1.3.6 + Hotfix-BIGIP-17.1.3.6.0.9.20-ENG`

Footnote 4 binds each engineering hotfix to its stated base version. Its superscript is not part of either literal version. These combinations remain publisher fix-column statements; no automatic minor-branch matching, download validation or independent availability claim is added.

Footnote 5 explains that the listed fixed BIG-IP versions contain backported fixes for both title CVEs although PHP reports `5.4.45`, and that package revision ordering need not track release ordering. This is source-bound context on affected claims, not evidence about an installed package. The example PHP build timestamp establishes neither a product release date nor download availability. The related CVE-2026-115560 link does not expand the title scope.

The full guidance describes appliance mitigations, Configuration utility access restrictions and backend application/WAF protections, including compatibility and incomplete-protection caveats. Those instructions do not create additional appliance fixes or assessments. The table's CVSS and general branch-versioning prose remain outside this narrowly scoped parser repair.

## Compatibility and selection

The older raw PHP PDF is unavailable locally. This review compares current source facts with the existing implemented profile; it does not claim a complete historical prose diff. Product/branch/version/authentication/lifecycle facts agree. The current fix pairs and backport/versioning context are the only additional normalized semantics identified for this repair. The original profile retains its original separate hotfix entries and order without applying current-source context retroactively. The OpenSSH K000140222 profile remains unchanged.

A supported revision requires one complete evaluated/critical/guidance tuple. Mixing old and current critical/guidance sections is unsupported, even when individual hashes are known. Article route, identity, title, day-precision date ordering, document boundaries and size budgets retain their existing guards. Unreviewed revisions remain visible failures and preserve the last accepted record.

| Section | Original PHP | Current PHP |
| --- | --- | --- |
| Evaluated | `7cb03fe23b90bd7a28da49d7608a60e4a180a3a97cd97b7cbe2d52d37a35c7f9` | `7cb03fe23b90bd7a28da49d7608a60e4a180a3a97cd97b7cbe2d52d37a35c7f9` |
| Critical | `30cd5b9e0634a9737eaeca1d0f1fabd2a7098f426bf36bc76802eee7a6d41ef0` | `a672d9082bf84be5b3a8f49349d0c09238cd71f32bad4a3727efc1f190e2b7c3` |
| Guidance | `fc93fd20fae798a2acaa4a4ef91585d29920cd7c7bde5ecd82602e91d742726e` | `e33dda8738adc8c10013ea90706e003ed78cc301f76b957fc59bbfe7ec1242a4` |

Historical release/hotfix inventory, official CVE reconciliation, installed exposure, human evidence-review acceptance and hosted activation remain unestablished. No frozen study binding or review resource is changed.
