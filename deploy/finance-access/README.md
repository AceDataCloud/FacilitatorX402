# Silicon Valley financial access

The Kubernetes 1.32 cluster uses this native fail-closed policy in the existing
`acedatacloud` namespace. Install it only with the trusted administrator after
checking compilation status. The ordinary worker publisher has named worker
resource permissions and named non-financial Secret reads. It has no Secret
list, financial workload mutation, ServiceAccount token or RBAC authority.

Only `system:serviceaccount:acedatacloud:finance-publisher` may update the
Facilitator and reconciliation workload. It is a trusted financial release
identity; ordinary CI must never receive its credential. Controller exceptions
are restricted to Pod/ReplicaSet creation by the named system controllers.

RBAC blocks GET/LIST of signing Secrets; admission blocks indirect mounts,
private env references, financial identities, host paths and privileged access.
It is installed independently of normal releases. A human cluster administrator
remains the explicit trust boundary.

Before enabling signing, verify actual worker and financial tokens with direct
RBAC denial checks and server-side dry-runs: unchanged worker allowed; signing
Secret volume/env, financial identity, hostPath and privileged container denied;
paused Facilitator update allowed only under the financial publisher. Keep
Facilitator replicas at zero and reconciliation suspended until payment readiness
and user-authorized E2E are complete.
