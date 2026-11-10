# Cisco 17.12.1 release reference layout

The optional exact-route adapter for
`https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-dublin-17-12-1/model.html`
supports the software metadata layout reviewed offline on 10 November 2026.
The public capture is 120,943 bytes, SHA-256
`2f6c9f50a4dededb423e5ba80a4873e194310499d7911b7b34f22d8aded79ba6`.
Raw vendor bytes remain outside Git.

Exact title and h1 identify Cisco IOS XE Dublin 17.12.1. One
`div.support-birth-cert[data-owner=ID]` directly owns one
`div.data-wrapper.software-data-wrapper`. Its direct `birth-cert-table` tables
(`col1`, `col2`) own `tbody/tr/th/td` fields. Series must be `Cisco IOS XE 17`
and Product Type must be `Cisco IOS XE`. The single Release Date belongs to
`col2` and reads `28-JUL-2023`, reported as `2023-07-28`. End-of-Sale and
End-of-Support dates are separate lifecycle facts and never supply release dates.
Duplicate labels/wrappers, foreign identities, nested/unowned fields, concealed
selected evidence and malformed date values fail closed. Telemetry filler and
lifecycle notice rows do not supply selected facts; active content is checked in
the selected identity/date rows and their ancestors.

The earlier project-authored named-section layout remains supported for
compatibility. The new fixture is also project-authored, not a raw vendor page.
This repair does not enable the optional source, establish broader historical
coverage or change advisory affectedness, defaults or hosted activation.
