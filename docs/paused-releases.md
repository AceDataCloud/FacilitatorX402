# Paused releases and payment restoration

Production has been authorized to serve Base exact, Base upto and Solana exact.
The workflow explicitly selects those three rails for push and manual releases,
so a routine code release does not leave the restored service paused. Other rails
and scheduled reconciliation remain disabled.

The underlying templates retain paused defaults: zero web replicas, suspended
reconciliation, false rail flags and no signer private-key references. A standalone
release still defaults to paused unless the explicit restore parameters are set.

## Stage an image while payments remain paused

`KUBE_CONTEXT=<context> FACILITATOR_RELEASE_MODE=paused BUILD_NUMBER=<built-image-tag> bash deploy/release.sh`
is the explicit staging operation. Do not set `FACILITATOR_RESTORE_RAILS` for this
command. It snapshots the previous configuration, suspends reconciliation,
scales the web workload to zero and waits for its Pods to terminate. If an existing
reconciliation Pod is present, staging fails and tells the operator to stop its
Job. It then applies the paused web and reconciliation templates with the new
image. It does not create database preflight, migration or reconciliation Jobs
and does not call a public health endpoint. No database login or signing private
key is required for this operation.

A staging release does not prove readiness for payment. Keep the external
Gateway payment flag disabled and its settlement scheduler paused until the
separate restoration checks pass.

## Restore selected payment rails

Restore only after an authorized operator verifies new signer addresses and private keys, required gas, the Facilitator database role and
network path, pending-payment handling, migrations and the Gateway payment
configuration. This release does not transfer funds, unlock a database account
or install signing keys.

A restoration command requires all three values:

```sh
KUBE_CONTEXT=<context> \
FACILITATOR_RELEASE_MODE=restore \
CONFIRM_FACILITATOR_PAYMENT_RESTORE=yes \
FACILITATOR_RESTORE_RAILS=base-exact \
BUILD_NUMBER=<built-image-tag> bash deploy/release.sh
```

`FACILITATOR_RESTORE_RAILS` is a comma-separated exact allowlist: `base-exact`,
`base-upto`, `solana-exact`, `solana-recurring`, `arbitrum-exact`.
There is no `all` alias or implicit default. `solana-recurring` also requires
`solana-exact`. Unknown modes, missing confirmation, unsupported rails and a rail
list on a paused release fail before Kubernetes changes.

The renderer enables only the selected rails and adds required private-key
Secret references only for their signers. The committed templates retain the
paused defaults. Restoration briefly quiesces the existing web Pods for database
preflight and migrations, then deploys two web replicas. It checks public metadata
but never creates a reconciliation smoke Job or resumes the reconciliation
CronJob. Review original payment identities and pending state before a separate
authorized reconciliation action. Afterwards, validate a fresh
controlled payment, terminal receipt and unique billing. Do not replay a
historical signed payment as a restoration test.

## Failure and rollback

Every release failure after quiescing restores the previous image/configuration
with **zero replicas, all rails disabled, no signer private-key references and
suspended reconciliation**. It never restarts the previous payment configuration,
even if it was active before release. The release cleans up only the temporary
Jobs it created. A failed restoration requires a new explicit operator decision.
Database schema migrations are not reversed by application rollback.

These are application-release safeguards. Do not give ordinary
application processes `x402-private` or mount whole Secret objects. Independent
CronJobs and restricted field injection keep their signing material out of the
Backend web process.

Both entry points require an explicit Kubernetes context and image version;
`latest` is rejected. The workflow passes its configured context once. Rendering
finishes for all application resources before apply, and apply failures propagate
to the existing release wrapper, including its failure-pause handler.
