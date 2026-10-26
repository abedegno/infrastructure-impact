# Additional component references

Reviewed 26 October 2026. These are component references, not CVE applicability
assessments or complete software bills of materials.

## Juniper

The public [Junos OS Evolved 24.2R1 authentication release note](https://www.juniper.net/documentation/us/en/software/junos/release-notes/24.2/junos-evo-release-notes-24.2r1/topics/new-features/feature-descriptions/authentication-access-control.html)
describes an OpenSSH upgrade for an explicit ACX/PTX model list. The parser binds
the destination version to the named release and retains that model scope. The
prior version in the same sentence is not a second current version. This cannot
be generalized to Junos OS, SRX firewalls or every Juniper router. A change in
the listed platform scope requires review before comparing component revisions.

## HPE

The [iLO 6 1.57 enhancement page](https://support.hpe.com/hpesc/public/docDisplay?docId=sd00004028en_us&page=GUID-C4AB7B5A-16C4-4C37-9C86-17365FE3B258.html)
describes an OpenSSL upgrade. The display page returned a session-check shell to
the anonymous HTTP client. The existing HPE canonical document API, with the
exact published page identifier, returned the enhancement article:

`https://support.hpe.com/hpesc/public/api/document/sd00004028en_us?page=GUID-C4AB7B5A-16C4-4C37-9C86-17365FE3B258.html`

The reviewed parser requires that exact route, the enhancement heading, the iLO
release identity and literal upgrade syntax. It selects the destination component
version only. This is not evidence for other iLO generations, supported server
model completeness, backport status, CVE applicability or public fix availability.
The bare article has no precise publisher date; no day is invented from the
separate book's month-level publication label.

Known HPE session-check shells are now classified as access-verification gaps.
Their HTTP 200 status is not treated as document content. No session API is called,
login synchronization executed or browser credentials exported by the collector.

## Aruba and Arista: reviewed limits

Aruba's public ClearPass release notes contain component-upgrade statements, but
the two exact 6.10.0/6.10.3 pages tested returned HTTP 403 to the ordinary client.
The advertised AOS 10 and NetEdit hardening PDFs also returned 403. Cached search
extracts are not substituted for retained publisher evidence or enabled as
successful component baselines. This leaves a component-source access gap.

Arista's [published open-source index](https://www.arista.com/en/support/product-documentation/gpl)
lists source distributions by EOS release. The ordinary client received a client
challenge; the published links lead to large source archives. The index alone is
not a package manifest and upstream affected-version prose in a security advisory
is not a shipped-component inventory. No component versions are invented from
those references. Existing Arista product/CVE applicability statements remain
separately available.

The two new sources are scheduled independently of the existing PAN-OS/Panorama
references. Different products, software branches and URLs are never before/after
pairs. Same-source component-reference changes remain investigation leads, not
findings of an undisclosed security fix or intentional concealment.
