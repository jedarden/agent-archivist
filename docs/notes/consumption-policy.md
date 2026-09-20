# Consumption-policy-v1 administration

`consumption-policy-v1` is governance evidence for the derived-content
consumer boundary. It is separate from risk assessment and use approval:
the policy says which classifier and rule-set evidence is current, how fresh
that evidence must be, and which purpose may reach which consumer class. It
never grants access to raw objects.

The offline tenant governance identity signs two closed RFC 8785 records:

- an immutable policy at
  `tenants/<tenant>/v1/control/consumption-policies/<policy_digest>.json`;
- a monotonic current pointer at
  `tenants/<tenant>/v1/control/consumption-policies/current.json`.

The policy binds `policy_version`, issue and effective instants, classifier
and rule-set allowlists, `assessment_not_before`, `max_assessment_age_seconds`,
purpose-to-consumer-class mappings, `max_approval_lifetime_seconds`, and the
immediately preceding policy digest. The pointer signs the version, digest,
tenant, and effective instant. A reader verifies the pointer and named policy
against the pinned governance public key before following predecessor links.

Version one is the genesis record and has a null predecessor. Each later
record must have a strictly higher version and name the digest of the prior
record; the digest chain, rather than a guessed sequence distance, detects
missing or altered history. An equal or lower pointer is a rollback and a
mismatched predecessor is discontinuous. Unknown classifier kinds, unsupported
rule-set digests, malformed closed members, altered signatures, missing
records, and a clock more than five minutes uncertain all deny evaluation. A
policy scheduled for a future effective instant also denies until that instant.

The implementation and policy-only repository boundary live in
[`archivist-auth::consumption_policy`](../../crates/archivist-auth/src/consumption_policy.rs);
the wire shape is [`consumption-policy.json`](../../schemas/v1/consumption-policy.json).
