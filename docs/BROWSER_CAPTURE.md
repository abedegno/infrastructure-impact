# Browser-assisted release-history evidence

Use this operator workflow for a reviewed **public** article that works in a
normal browser but is unavailable to the HTTP collector. It does not install a
browser collector, solve access challenges, export browser credentials, or change
scheduled source health. GitHub Actions remains HTTP-only.

1. Open the official source in a normal browser and inspect the main article.
   Verify the URL, product, hardware platform and version context. Stop if the
   page is a login, access challenge, or unrelated document. Never capture an
   account page or private content.
2. Read `examples/browser-capture/export-article.js`, then run it in the page's
   DevTools console. Invoke `exportImpactArticle` with the vendor ID and browser
   name as shown in the example. It downloads a JSON envelope containing exactly
   one selected visible article's rendered HTML, observation time and SHA-256.
   The default selector is `main article`; inspect a different selector before
   using it. Descendants are preserved, so inspect the capture before importing.
3. Save the envelope outside the Git checkout, for example in private `data/`.
   Import it into the operator vault:

   ```sh
   impact research import-browser-capture data/impact-browser-capture.json \
     --expected-version 10.13.1031
   impact research browser-captures
   impact audit
   ```

The importer validates the strict `schemas/browser-capture-v1.json` contract,
official HTTPS domain, timezone-aware observation time, bounded file size,
rendered-content fingerprint and installed vendor parser. Unknown metadata fields
are rejected. A hash detects a changed capture; it does not authenticate its
publisher or prove that a browser generated it. Capture metadata is supplied by
the operator.

The original evidence bytes are the **capture envelope**, with media type
`application/vnd.infrastructure-impact.browser-capture+json`. They are not the
vendor's HTTP response. `rendered_sha256` separately fingerprints the UTF-8
rendered article. The source URL and capture/import times remain traceable in the
vault. Raw article HTML is never executed by the importer, returned in summaries,
or published. Browser captures remain private operator research; they are not
included in Pages, release assets or product assessments.

The optional plugin hook `parse_release_history` returns the strict
`schemas/release-history-v1.json` contract: product, platforms, branch, and dated
publisher release statements. The initial Aruba parser deliberately covers only
4100i / AOS-CX 10.13 consolidated Version history articles. Other layouts fail
closed until reviewed and tested. This contract does not require firmware hashes
that a history table does not publish.

An expected version is an operator query, not a publisher assertion. The report
flags an absent selected version, duplicate rows and conflicting dates. It never
borrows a neighbouring release's date. Even a present version does not establish
an exhaustive release history. Dates remain publisher claims, not verified
historical download availability, CVE linkage, or concealment findings. No fix
candidate is automatically registered or verified.

The [Aruba source investigation](research/aruba-release-evidence.md) illustrates
the access difference and a real missing selected-version row. An unattended
browser workflow would require separate testing of source coverage, browser
isolation, failure handling and provenance before being enabled.
