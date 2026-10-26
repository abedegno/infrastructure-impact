# Arista CloudVision release-train evidence

Reviewed and captured from the public browser on 2026-10-26. The official
[CloudVision Life Cycle Policy](https://www.arista.com/en/support/product-documentation/cloudvision-life-cycle-policy)
has a CloudVision Software Lifecycle panel with six dated CloudVision Portal
release trains. Its initial-release column is distinct from its end-of-support
column. These are major train dates, not patch-level security-fix dates.

A direct HTTP request returned a Client Challenge HTML page with status 200.
A normal Chrome session displayed the public panel without a login or a manual
challenge. The visible panel was captured as browser DOM evidence into the private
local vault, using the same envelope and normalized release-history schema as Aruba.
No browser evidence was uploaded to the hosted collector or published on Pages.

The parser requires that exact product panel and table. It rejects other product
panels, changed headings/rows, and initial-release dates later than the panel's
own Last Updated date. Undated aggregate older-train notices produce no invented
dates. `version_granularity: release_train` prevents treating these dates as patch
release observations. The contract does not establish historical download
availability, a product/CVE relationship, or intentional non-disclosure.

Unattended collection of this page remains disabled. Its HTTP client challenge
is recognized as access verification, rather than a successful document or an
unexplained parser layout error.
