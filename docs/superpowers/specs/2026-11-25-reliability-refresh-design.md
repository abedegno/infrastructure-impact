# Incremental release-reliability preparation

The approved next step makes reliability evidence refreshable without silently
publishing new facts. The current production root reads a pinned packaged catalogue.
Existing release-signal readers and cache/staging patterns are reusable; the older
signal dataset is distinct from the normalized catalogue and must not be confused
with it.

Add a standalone explicit-path CLI and small reader/transport/application modules.
An exact source registry initially covers Cisco Catalyst 9200/9300 IOS XE 17.12
ROMMON version tables and Arista EOS 4.33 software RSS. Cisco version columns state
identity and model, not release date; Arista states availability announcement date,
not binary release date or study models. Preserve these distinctions. No live
Aruba or Arista route is activated: recorded challenge/robots gaps remain blocked.
The Cisco routes were substantive and allowed in the prior packet, but any new
network collection requires an explicit current local policy-review receipt and a
fresh allowed robots decision. A CLI policy gate never overrides robots or access.

Use a fixed allowlist, public HTTPS without credentials/cookies/environment proxy,
redirect refusal, bounded body/time, conservative throttling and conditional GET.
Cache immutable original bytes by SHA-256 outside every Git checkout. Maintain
per-source revision receipts and a latest-good pointer, with HTTP validators and
last-check outcomes separate from original retrieval. Byte-identical 200/304 checks
never create new source timestamps or revisions. Revalidate cached bytes on 304
and replay. Access, parse, policy or network failure preserves last good evidence.

Support offline original-byte import with explicit source ID/retrieval timestamp,
label its operator origin in the cache envelope, and deterministic preparation
against an explicit baseline catalogue. Retain rolling-feed observations and older
source revisions. New semantic facts add original-byte source receipts, quotes and
locators. Changed/conflicting dates or scope go to a separate pending review report;
never overwrite historical facts or infer withdrawal from omission. Keep schemas
closed: HTTP/revision metadata stays in the cache/report envelope, catalogue uses
existing v1 normalization. Preserve existing coverage judgements and never assert
complete enumeration/date/signal coverage from a rolling source or successful GET.

Alternatives: modifying the pinned packet builder would mix reproducible research
with ongoing state; reusing the existing database transport would couple this small
public operation to the private advisory vault; writing directly to packaged/live
facts would cross the review/publication boundary. Use a separate candidate and
review report. No schedule, hosted configuration, source default activation,
permissions, secrets, packaged catalogue or existing studies change.

Tests cover conditional retrieval/replay, revision/atomicity, source shape and scope,
unknown dates/coverage, conflicts, outside-Git cache rules and failure preservation.
Initial proof can replay known public captures; unavailable source/policy conditions
are reported honestly. Human review stays pending. The standing autonomous execution
preference applies; hosted activation remains a concrete separately approved step.
