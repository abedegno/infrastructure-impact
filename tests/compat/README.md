# Archived hosted-helper compatibility evidence

`hosted_job_v011.py` is byte-identical first-party Infrastructure Impact code from
`ops/hosted_job.py` at immutable commit
`57b76f7db3486588538dc93b3752327730643cce` (v0.11.0), licensed under this project's
Apache License 2.0; see the repository `LICENSE` and `NOTICE`.

SHA-256: `9999089977439f4ca147de292c000d824808852641c5da1432afb6993b8c60f1`.

Do not edit or format this archived file. Its exact bytes establish which
previously approved helper the new workflow may run in ordinary legacy mode
before the separately approved source-pin activation. It is regression evidence,
not a second production implementation, vendor-source capture, recovery archive,
or authorization to downgrade evidence/publication semantics after activation.

Portable tests execute this real helper against authored synthetic encrypted
recovery data and current storage interfaces. Optional integration tests also run
its exact original package when the old Git object is locally available; they
skip explicitly if that object is unavailable and never fetch it from a network.
No real vault, recovery asset, customer data or secret is stored here.
