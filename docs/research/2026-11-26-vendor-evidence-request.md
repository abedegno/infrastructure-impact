# Public release history and notice archive request

**Draft for independent human review. Research only.** No vendor has been contacted.

## Request to publishers

Please point us to your public, publisher-hosted release histories, platform
support tables and historical non-security notice archives for these products.

| Product and train | Platform families |
| --- | --- |
| Cisco IOS XE 17.12 | Catalyst 9200 and Catalyst 9300 |
| HPE Aruba Networking AOS-CX 10.13 | CX 6200 and CX 6300 |
| Arista EOS 4.33 | 720XP and 720DP |

The study window is 1 January 2024 through 31 December 2026, inclusive. For an
archive supplied before year-end, please give its actual coverage end and
as-of date. Include releases first available during the covered period and
notices first published, substantively revised or acted on during it. Where a
notice affects an earlier release, include the earlier release identity and
relevant dates or source references so we can place the action in context.

- **Release history and support.** Provide the original release or download
  availability date for each exact release and build, with explicit supported
  platform families, models or SKUs. Include lettered versions, maintenance
  rebuilds and historical listings for subsequently withdrawn releases. Identify
  models with minimum-version or hardware restrictions. If a date applies to a
  shared image, identify the releases and models it covers. Label release dates,
  availability announcement dates and documentation publication or update dates
  individually.
- **Notices and actions.** Provide the archive and detail records for relevant
  non-security field notices, customer advisories, withdrawals, removals from
  download and deferrals. Give the notice ID, first publication date, revision
  history, action and its effective date, affected versions and models,
  applicable deployment or configuration conditions, and any explicitly named
  replacement or fixed version. Include an action's public source even when it
  is documented separately from a notice. Identify whether the source describes
  a defect, a recommendation, a deferral before availability or withdrawal
  after availability, where the publisher makes that distinction.
- **Archive coverage.** State which product, platform, record types and dates
  each source covers, whether its enumeration is complete for that slice, and
  whether it includes superseded or delisted records. Identify the indexes,
  pages, partitions or export sets needed for full coverage, with expected counts
  if available. List retention limits, gaps and exclusions, including missing
  details or revision history. If you explicitly confirm that a complete slice
  contains zero records, cite that statement with its scope and period.
- **Access and terms.** Provide canonical public URLs and precise page, table
  or record locators. An anonymously readable index with documented pagination
  or a publisher-hosted CSV, JSON or documented public API is useful. Please
  link to the applicable terms for access, unattended retrieval, request limits,
  retention, citation and reuse of facts or excerpts. If a public export or
  reuse permission is available by request, please identify the public process.
  Only public references and exportable metadata are in scope.

## Specific gaps to resolve

### Cisco IOS XE 17.12 on Catalyst 9200 and 9300

- Please provide platform-bound release dates for all 16 currently undated
  family/version pairs covering 17.12.1, 17.12.2, 17.12.3, 17.12.4, 17.12.5,
  17.12.6, 17.12.7a and 17.12.8. Include any other shipped builds in scope.
  Please clarify the public release status of 17.12.7 and any explicitly
  documented relationship to 17.12.7a. The current tables enumerate versions.
  The dated ISSU references cover other Catalyst platforms.
  [Round 4](2026-11-25-round4-cisco.md) ·
  [Release-date supplement](2026-11-25-round4-coverage-cisco.md)
- Please identify the historical field-notice and software withdrawal or
  deferral archives for both families. Our review accounted for 11 IDs from
  the current 9300 index. For notices with conditional coverage, specify the
  model, running version and role or configuration. Examples include the
  Umbrella registration conditions in FN74221 and the embedded wireless
  controller role in FN72524. Please identify which date is authoritative for
  the initial publication of FN72416, where the header and revision table
  differ. [Round 4](2026-11-25-round4-cisco.md) ·
  [Notice follow-up](2026-11-26-reliability-cisco-followup.md)
- **Separate out-of-cohort control.** If there is a public record of a 17.9.6
  withdrawal, please supply the action date, exact platform and version scope,
  and any explicitly designated replacement. Withdrawal remains unverified.
  The public 17.9.6a reference to CSCwm57734 establishes a fix reference.
  [Control notes](2026-11-25-round4-cisco.md#withdrawal-control-and-access)

### HPE Aruba Networking AOS-CX 10.13 on CX 6200 and 6300

- Please provide the latest complete 6200 history, including 2025–2026 dates
  and the history through 10.13.1200. We have four dated 6200 rows from an early
  2024 subsection and 23 dated 6300 rows as research observations. For 6300,
  please reconcile the 10.13.1001, 10.13.1031 and 10.13.1161 navigation entries
  with the dated history, and clarify the availability and support status
  of 10.13.1101. Give explicit 6200 and 6300 model/SKU support and minimum
  versions where applicable. [Round 4](2026-11-25-round4-aruba.md) ·
  [Coverage supplement](2026-11-25-round4-coverage-aruba.md)
- Please identify public non-security customer advisory and software lifecycle
  action archives for 6200/6300. The public advisory route was observed with an
  out-of-scope example. The bounded follow-up produced no qualifying
  in-scope notices. [Round 4](2026-11-25-round4-aruba.md) ·
  [Follow-up](2026-11-26-reliability-peers-followup.md)

### Arista EOS 4.33 on 720XP and 720DP

- Please supply per-binary release dates and supported models for the eight
  observed identities (4.33.0F, 4.33.1F, 4.33.2F, 4.33.3F, 4.33.4M, 4.33.5M,
  4.33.11M and 4.33.11.2M) and any additional releases. The eight currently
  lack binary release dates and explicit binding to 720XP or 720DP. The EOS
  lifecycle matrix dates the start of the train. RSS timestamps for 4.33.11M
  and 4.33.11.2M date their announcements. We need publisher support tables
  that identify the covered hardware and releases. [Round 4](2026-11-25-round4-arista.md) ·
  [Coverage supplement](2026-11-25-round4-coverage-arista.md) ·
  [Follow-up](2026-11-26-reliability-peers-followup.md)
- Please supply the full archived notice list and public details or export
  beyond the sampled index pages and recent RSS window. For FN0103, which
  reports a deferral of 4.33.3F, please provide the effective action date and
  state whether it includes 720XP or 720DP. Identify any explicitly designated
  replacement. The public summary dates the notice and specifies “all
  supported platforms.” [Round 4](2026-11-25-round4-arista.md)

## Optional export template

The files contain CSV headers only. Your published format and field definitions
are welcome. Use ISO calendar dates or timestamps with an offset where available.
Preserve source precision and leave unknown values blank. Where the publisher
documents conflicting dates, include both with their distinct labels and
locators. For each date or scope value, cite the authoritative public record.

| File | Row and field conventions |
| --- | --- |
| [Release history](../examples/vendor-evidence-releases.csv) | One row per exact release/build and explicitly supported model or family. Retain suffixes and minimum-version or hardware conditions. Use source status when documented. Release and announcement dates have separate source references. |
| [Notice and action history](../examples/vendor-evidence-notices.csv) | One row per notice or revision, scope and action. Keep initial publication, revision and effective action dates distinct. Split records when affected versions, models or conditions differ. Leave action and replacement fields blank if unspecified. |
| [Archive coverage](../examples/vendor-evidence-coverage.csv) | One row per archive or export slice and record type. State the platform scope, covered period, as-of date, complete/partial/unknown coverage, expected and provided sources, and counts where available. Give the unit for any counts in the publisher's coverage statement. |

On receipt we will log retrieval time, access outcomes and the source portions
actually retrieved against the expected archive. We will compute SHA-256
fingerprints for the material we retain and record the fingerprinted object
type. Independent human review is pending. Release totals and historical
incident coverage remain unknown wherever completeness is unresolved.
