# Reviewing source access gaps

Use the **Product cohorts** view for current component-reference coverage across
all collected vendors. A source with component references is not a complete SBOM;
a vendor with none remains unknown. Vendor source-error counts cover all that
vendor's configured sources and must not be attributed to a particular family.
Exact cohort source bindings keep Panorama, PAN-OS and unrelated products separate.

## Compare retrieval environments

The manual **Reviewed source access** GitHub workflow tests four exact, reviewed
public URLs from an Ubuntu runner: Cisco UCS Rack HTML and PDF, the existing NX-OS
HTML release notes, and the Aruba EdgeConnect Orchestrator remediation PDF on the
current HPE documentation host. It requires no evidence-vault key and never opens
or restores the collector's database. Only bounded response metadata is retained.

```sh
python -m checks.source_access --output /tmp/source-access.json
```

The probe uses an ordinary anonymous GET with the collector's user-agent, a
25-second timeout and 3 MB response cap. It does not rotate identities, execute
challenges or synchronize browser authentication. Redirects remain subject to the
vendor's HTTPS policy. A successful response requires content and parser review;
it is not a historical availability observation or proof of an advisory's scope.
The workflow does not modify the collector configuration or mark sources healthy.

The first [runner probe](https://github.com/abedegno/infrastructure-impact/actions/runs/40479366882)
on 27 October 2026 at 09:15 UTC returned HTTP 403 for all four routes. The HTML
alternative therefore did not resolve the hosted Cisco gap. These are four
point-in-time observations, not proof of their cause or historical access.

A failed request from a restricted local environment may reflect that environment,
not the publisher. Compare the runner receipt and normal collector health rather
than inferring the cause of a 403 or transport error. The workflow job can succeed
while recording inaccessible sources: its purpose is to measure and retain the
gaps. Unexpected software errors fail the job.

## Reviewed alternatives, still requiring access and content review

The [Cisco UCS Rack 4.2(3) HTML counterpart](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/b_release-notes-for-cisco-ucs-rack-server-software-release-4_2_3.html)
is discoverable through the publisher. The existing narrow parser handles the PDF,
not the HTML. A search-engine rendering is not interchangeable with a retained
collector response. Both direct local requests returned 403 on 27 October 2026;
that observation does not establish universal inaccessibility or intentional
withholding.

The [Aruba Orchestrator remediation guide](https://arubanetworking.hpe.com/techdocs/sdwan-PDFs/docs/advisories/orch_resolution_to_cve-2024-6387_latest.pdf)
is a source lead. Its indexed content distinguishes self-hosted operating systems
and deployment models, and includes example package-update output. It must not be
promoted to an appliance component inventory, an AOS-CX statement or a new
security finding. Direct local access also failed. No automatic parser or failing
scheduled source has been added for this guide.

For a newly accessible source: retain and inspect the exact public response,
check product, build, service and date scope, implement a bounded parser with
layout-change rejection, then add a scheduled source. Keep earlier failures and
first capture time intact. Never upload an operator's existing private captures
as a substitute for runner collection.
