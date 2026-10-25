# Security policy

This policy covers vulnerabilities in Infrastructure Impact's collectors, storage,
publication, API, dashboard and distribution. CVEs affecting vendor products belong
in the relevant vendor's disclosure process; ordinary data corrections belong in
the data-correction issue form.

## Report privately

Use **Security → Report a vulnerability** on the project's GitHub repository when
private vulnerability reporting is enabled. Include affected version/commit,
reproduction steps, expected and observed behavior, impact and a minimal sanitized
proof. Do not include credentials, customer data or private source captures.

If the private-report option is unavailable, open an issue titled **Private security
contact requested**, without vulnerability details, and wait for a maintainer to
provide a private channel. Do not publish exploit details merely because the
private-report feature is unavailable.

This is a volunteer project. Response times are not guaranteed. Maintainers will
coordinate validation, a fix and disclosure with the reporter where possible.

## Supported versions

During 0.x development, security fixes target the latest release and the default
branch. Older releases have no promised backport support. Report suspected issues
even if you are unsure whether the affected revision is supported.

## Relevant boundaries

Vendor plugins are trusted installed Python code, not sandboxed extensions. The
reader is designed to serve sanitized public generations without the private vault.
There are no public write or collection-trigger endpoints. Run an instance behind
appropriate access controls when its publication should remain private; the source
code license does not make a deployment private or authenticate its users.
