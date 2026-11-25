# Pages artifact visibility and deployment isolation

The approved milestone fixes recurring publication failure without repeating
collection. Accepted uploads have repeatedly failed immediate Pages discovery.
The pinned deploy-pages v5.0.1 implementation performs one artifact listing.
Upstream https://github.com/actions/deploy-pages/issues/451 describes the matching
same-job visibility race and separate-job mitigation. This fits our observations;
the internal GitHub service cause is not independently proven.

Keep the pinned official actions, artifact name and acceptance checks. Separate
upload/acceptance from configure/deploy/health using dependent jobs in ordinary
collection and exact-artifact recovery. Deploy only after successful producer
completion and successful upload with a nonempty artifact ID. Capture the validated
runtime source commit as a job output; health uses that source rather than a later
mutable pin. Recovery carries the verifier's generation. Existing workflow-wide
concurrency prevents recovery-pointer advancement between jobs.

Alternatives: arbitrary sleep is not an acceptance boundary; recollection wastes
acquisition and changes the artifact; replacing the official action or invoking a
private API adds maintenance. A REST readiness poll would need actions permission
absent from normal collection. Job separation follows the official supported
pattern without new dependencies or permissions.

No schedules, permission declarations, secrets, source activation, recovery limits
or producer acceptance policy change. Keep preview unable to publish, authenticated
failure cleanup, and legacy/helper compatibility. Both jobs keep the protected
Pages environment. This design is within the approved Pages fix; the standing
opt-out avoids another approval loop. Collector activation remains separately gated.
