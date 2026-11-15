# Paused releases and payment restoration

A code release must not restore payment signing after an incident. The committed
Deployment has zero replicas. The reconciliation CronJob is suspended. All rail
enablement flags are false and neither template references a signer private key.
The production workflow pins `FACILITATOR_RELEASE_MODE=paused` for both push and
manual runs.

## Stage an image while payments remain paused

`BUILD_NUMBER=<built-image-tag> bash deploy/release.sh` is the default staging
operation. It snapshots the previous configuration, suspends reconciliation,
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

Restore only after an authorized operator verifies signing isolation, new signer
addresses and private keys, required gas, the Facilitator database role and
network path, pending-payment handling, migrations and the Gateway payment
configuration. This release does not transfer funds, unlock a database account
or install signing keys.

A restoration command requires all three values:

```sh
FACILITATOR_RELEASE_MODE=restore \
CONFIRM_FACILITATOR_PAYMENT_RESTORE=yes \
FACILITATOR_RESTORE_RAILS=base-exact \
BUILD_NUMBER=<built-image-tag> bash deploy/release.sh
```

`FACILITATOR_RESTORE_RAILS` is a comma-separated exact allowlist: `base-exact`,
`base-upto`, `solana-exact`, `solana-recurring`, `skale-exact`, `arbitrum-exact`.
There is no `all` alias or implicit default. `solana-recurring` also requires
`solana-exact`. Unknown modes, missing confirmation, unsupported rails and a rail
list on a paused release fail before Kubernetes changes.

The renderer enables only the selected rails and adds required private-key
Secret references only for their signers. The committed templates retain the
paused defaults. Restoration runs database preflight and migrations, deploys
two web replicas, and runs one reconciliation smoke Job while its CronJob is
still suspended. Only successful smoke and metadata checks resume scheduling.
That smoke Job can reconcile existing payments; review their original identities
and pending state before authorizing restoration. Afterwards, validate a fresh
controlled payment, terminal receipt and unique billing. Do not replay a
historical signed payment as a restoration test.

## Failure and rollback

Every release failure after quiescing restores the previous image/configuration
with **zero replicas, all rails disabled, no signer private-key references and
suspended reconciliation**. It never restarts the previous payment configuration,
even if it was active before release. The release cleans up only the temporary
Jobs it created. A failed restoration requires a new explicit operator decision.
Database schema migrations are not reversed by application rollback.

These are application-release safeguards. Cluster permissions and admission
policy must independently prevent other CI identities, old manifests or manual
Jobs from accessing wallet secrets or bypassing the stopped financial boundary.
