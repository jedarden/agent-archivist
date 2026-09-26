// SPDX-License-Identifier: Apache-2.0

//! GENERATED FILE - DO NOT EDIT.
//!
//! Schema-derived bindings for the `schemas/v1` wire family: the schema URN
//! space, the closed enum token sets with their bearing and fail-closed
//! metadata, the pinned version and plan constants, and the reserved-field
//! and member-name lists. Emitted from the checked-in JSON Schemas by
//! `tools/bindingsgen.py`.
//!
//! Regenerate with `python3 tools/bindingsgen.py` in the same commit as any
//! schema change. `tools/bindingsgen.py --verify` byte-compares this file
//! against a fresh regeneration in the definition-of-done fast lane, so a
//! hand edit or an unregenerated schema change fails the gate. The module
//! is crate-private: the public surface of `archivist-protocol` does not
//! grow. `vocabulary` sources its closed-enum token slices here, and
//! `envelope` sources its pinned versions, canonical byte cap, reserved-
//! field list, and member-name list; their tests pin the hand-written
//! mappings against these values.
//!
//! Formatting is rustfmt-skipped (the attribute lives on the module
//! declaration in lib.rs) so regeneration is byte-exact and independent of
//! any formatter version.

/// The URN prefix every schema of the family shares, derived from the
/// `$id` values themselves.
pub(crate) const SCHEMA_URN_PREFIX: &str = "urn:agent-archivist:schema:v1:";

/// The canonical schema URN of `schemas/v1/cli-doctor.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CLI_DOCTOR: &str = "urn:agent-archivist:schema:v1:cli-doctor";

/// Pinned const of `schema` in `schemas/v1/cli-doctor.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CLI_DOCTOR_SCHEMA: &str = "archivist.cli-result/v1";

/// The `closedShape` metadata of `schemas/v1/cli-doctor.json`.
pub(crate) const CLI_DOCTOR_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/cli-doctor.json`.
pub(crate) const CLI_DOCTOR_META_COMPATIBILITY: &str = "member additions are additive within v1 per plan Section 7.1 (CLI-015); redefining or removing a member, or a new namespace, is a v2 event";

/// The `floats` metadata of `schemas/v1/cli-doctor.json`.
pub(crate) const CLI_DOCTOR_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/cli-doctor.json`.
pub(crate) const CLI_DOCTOR_META_NAMESPACE: &str = "archivist.cli-result/v1";

/// The `namespaceField` metadata of `schemas/v1/cli-doctor.json`.
pub(crate) const CLI_DOCTOR_META_NAMESPACE_FIELD: &str = "schema";

/// The `unknownFields` metadata of `schemas/v1/cli-doctor.json`.
pub(crate) const CLI_DOCTOR_META_UNKNOWN_FIELDS: &str = "reject";

/// Every top-level member name `schemas/v1/cli-doctor.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CLI_DOCTOR_FIELD_NAMES: [&str; 5] = [
    "checks",
    "evidence",
    "generated_at",
    "schema",
    "verdict",
];

/// Closed enum tokens of `check-verdicts/client_linkage` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CLIENT_LINKAGE_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/client_linkage` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CLIENT_LINKAGE_BEARING: &str = "structural";

/// Whether the `check-verdicts/client_linkage` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CLIENT_LINKAGE_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/clock_sanity` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CLOCK_SANITY_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/clock_sanity` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CLOCK_SANITY_BEARING: &str = "structural";

/// Whether the `check-verdicts/clock_sanity` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CLOCK_SANITY_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/configuration` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CONFIGURATION_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/configuration` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CONFIGURATION_BEARING: &str = "structural";

/// Whether the `check-verdicts/configuration` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_CONFIGURATION_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/lock_ownership` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_LOCK_OWNERSHIP_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/lock_ownership` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_LOCK_OWNERSHIP_BEARING: &str = "structural";

/// Whether the `check-verdicts/lock_ownership` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_LOCK_OWNERSHIP_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/permissions` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_PERMISSIONS_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/permissions` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_PERMISSIONS_BEARING: &str = "structural";

/// Whether the `check-verdicts/permissions` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_PERMISSIONS_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/server_readiness` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SERVER_READINESS_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/server_readiness` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SERVER_READINESS_BEARING: &str = "structural";

/// Whether the `check-verdicts/server_readiness` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SERVER_READINESS_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/source_readability` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SOURCE_READABILITY_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/source_readability` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SOURCE_READABILITY_BEARING: &str = "structural";

/// Whether the `check-verdicts/source_readability` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SOURCE_READABILITY_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/spool_space` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SPOOL_SPACE_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/spool_space` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SPOOL_SPACE_BEARING: &str = "structural";

/// Whether the `check-verdicts/spool_space` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SPOOL_SPACE_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/sqlite_integrity` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SQLITE_INTEGRITY_TOKENS: &[&str] = &["ok"];

/// Bearing of the `check-verdicts/sqlite_integrity` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SQLITE_INTEGRITY_BEARING: &str = "structural";

/// Whether the `check-verdicts/sqlite_integrity` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_CHECK_VERDICTS_SQLITE_INTEGRITY_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `evidence/lock` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_EVIDENCE_LOCK_TOKENS: &[&str] = &["free", "held"];

/// Bearing of the `evidence/lock` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_EVIDENCE_LOCK_BEARING: &str = "structural";

/// Whether the `evidence/lock` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_EVIDENCE_LOCK_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `verdict` in `schemas/v1/cli-doctor.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_DOCTOR_VERDICT_TOKENS: &[&str] = &["ok"];

/// Bearing of the `verdict` enum in `schemas/v1/cli-doctor.json`.
pub(crate) const ENUM_CLI_DOCTOR_VERDICT_BEARING: &str = "structural";

/// Whether the `verdict` enum in `schemas/v1/cli-doctor.json` is declared fail-closed.
pub(crate) const ENUM_CLI_DOCTOR_VERDICT_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/cli-inventory.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CLI_INVENTORY: &str = "urn:agent-archivist:schema:v1:cli-inventory";

/// Pinned const of `schema` in `schemas/v1/cli-inventory.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CLI_INVENTORY_SCHEMA: &str = "archivist.cli-result/v1";

/// The `closedShape` metadata of `schemas/v1/cli-inventory.json`.
pub(crate) const CLI_INVENTORY_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/cli-inventory.json`.
pub(crate) const CLI_INVENTORY_META_COMPATIBILITY: &str = "member additions are additive within v1 per plan Section 7.1 (CLI-015); redefining or removing a member, or a new namespace, is a v2 event";

/// The `floats` metadata of `schemas/v1/cli-inventory.json`.
pub(crate) const CLI_INVENTORY_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/cli-inventory.json`.
pub(crate) const CLI_INVENTORY_META_NAMESPACE: &str = "archivist.cli-result/v1";

/// The `namespaceField` metadata of `schemas/v1/cli-inventory.json`.
pub(crate) const CLI_INVENTORY_META_NAMESPACE_FIELD: &str = "schema";

/// The `unknownFields` metadata of `schemas/v1/cli-inventory.json`.
pub(crate) const CLI_INVENTORY_META_UNKNOWN_FIELDS: &str = "reject";

/// Every top-level member name `schemas/v1/cli-inventory.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CLI_INVENTORY_FIELD_NAMES: [&str; 6] = [
    "generated_at",
    "overall",
    "schema",
    "sources_without_scan",
    "statuses",
    "totals",
];

/// Closed enum tokens of `overall` in `schemas/v1/cli-inventory.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_INVENTORY_OVERALL_TOKENS: &[&str] = &[
    "missing",
    "unsupported",
    "failed",
    "partial",
    "current",
    "backfilled",
];

/// Bearing of the `overall` enum in `schemas/v1/cli-inventory.json`.
pub(crate) const ENUM_CLI_INVENTORY_OVERALL_BEARING: &str = "structural";

/// Whether the `overall` enum in `schemas/v1/cli-inventory.json` is declared fail-closed.
pub(crate) const ENUM_CLI_INVENTORY_OVERALL_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `scope-status/coverage` in `schemas/v1/cli-inventory.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_INVENTORY_SCOPE_STATUS_COVERAGE_TOKENS: &[&str] = &[
    "missing",
    "unsupported",
    "failed",
    "partial",
    "current",
    "backfilled",
];

/// Bearing of the `scope-status/coverage` enum in `schemas/v1/cli-inventory.json`.
pub(crate) const ENUM_CLI_INVENTORY_SCOPE_STATUS_COVERAGE_BEARING: &str = "structural";

/// Whether the `scope-status/coverage` enum in `schemas/v1/cli-inventory.json` is declared fail-closed.
pub(crate) const ENUM_CLI_INVENTORY_SCOPE_STATUS_COVERAGE_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/cli-output.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CLI_OUTPUT: &str = "urn:agent-archivist:schema:v1:cli-output";

/// Pinned const of `schema` in `schemas/v1/cli-output.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CLI_OUTPUT_SCHEMA: &str = "archivist.cli-output/v1";

/// The `closedShape` metadata of `schemas/v1/cli-output.json`.
pub(crate) const CLI_OUTPUT_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/cli-output.json`.
pub(crate) const CLI_OUTPUT_META_COMPATIBILITY: &str = "appending per-command result schemas and new command tokens is compatible (docs/notes/cli.md Section 8); changing the envelope member set, redefining a member, or a new namespace is a v2 event";

/// The `floats` metadata of `schemas/v1/cli-output.json`.
pub(crate) const CLI_OUTPUT_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/cli-output.json`.
pub(crate) const CLI_OUTPUT_META_NAMESPACE: &str = "archivist.cli-output/v1";

/// The `namespaceField` metadata of `schemas/v1/cli-output.json`.
pub(crate) const CLI_OUTPUT_META_NAMESPACE_FIELD: &str = "schema";

/// The `unknownFields` metadata of `schemas/v1/cli-output.json`.
pub(crate) const CLI_OUTPUT_META_UNKNOWN_FIELDS: &str = "reject";

/// Every top-level member name `schemas/v1/cli-output.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CLI_OUTPUT_FIELD_NAMES: [&str; 4] = [
    "command",
    "generated_at",
    "result",
    "schema",
];

/// The canonical schema URN of `schemas/v1/cli-run.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CLI_RUN: &str = "urn:agent-archivist:schema:v1:cli-run";

/// Pinned const of `schema` in `schemas/v1/cli-run.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CLI_RUN_SCHEMA: &str = "archivist.cli-result/v1";

/// The `closedShape` metadata of `schemas/v1/cli-run.json`.
pub(crate) const CLI_RUN_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/cli-run.json`.
pub(crate) const CLI_RUN_META_COMPATIBILITY: &str = "member additions are additive within v1 per plan Section 7.1 (CLI-015); redefining or removing a member, or a new namespace, is a v2 event";

/// The `floats` metadata of `schemas/v1/cli-run.json`.
pub(crate) const CLI_RUN_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/cli-run.json`.
pub(crate) const CLI_RUN_META_NAMESPACE: &str = "archivist.cli-result/v1";

/// The `namespaceField` metadata of `schemas/v1/cli-run.json`.
pub(crate) const CLI_RUN_META_NAMESPACE_FIELD: &str = "schema";

/// The `unknownFields` metadata of `schemas/v1/cli-run.json`.
pub(crate) const CLI_RUN_META_UNKNOWN_FIELDS: &str = "reject";

/// Every top-level member name `schemas/v1/cli-run.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CLI_RUN_FIELD_NAMES: [&str; 5] = [
    "generated_at",
    "plan",
    "pressure",
    "reconcile",
    "schema",
];

/// Closed enum tokens of `pressure-verdict/reasons` in `schemas/v1/cli-run.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_RUN_PRESSURE_VERDICT_REASONS_TOKENS: &[&str] = &[
    "spool_cap",
    "free_floor",
    "draining",
];

/// Bearing of the `pressure-verdict/reasons` enum in `schemas/v1/cli-run.json`.
pub(crate) const ENUM_CLI_RUN_PRESSURE_VERDICT_REASONS_BEARING: &str = "structural";

/// Whether the `pressure-verdict/reasons` enum in `schemas/v1/cli-run.json` is declared fail-closed.
pub(crate) const ENUM_CLI_RUN_PRESSURE_VERDICT_REASONS_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/cli-status.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CLI_STATUS: &str = "urn:agent-archivist:schema:v1:cli-status";

/// Pinned const of `schema` in `schemas/v1/cli-status.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CLI_STATUS_SCHEMA: &str = "archivist.cli-result/v1";

/// The `closedShape` metadata of `schemas/v1/cli-status.json`.
pub(crate) const CLI_STATUS_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/cli-status.json`.
pub(crate) const CLI_STATUS_META_COMPATIBILITY: &str = "member additions are additive within v1 per plan Section 7.1 (CLI-015); redefining or removing a member, or a new namespace, is a v2 event";

/// The `floats` metadata of `schemas/v1/cli-status.json`.
pub(crate) const CLI_STATUS_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/cli-status.json`.
pub(crate) const CLI_STATUS_META_NAMESPACE: &str = "archivist.cli-result/v1";

/// The `namespaceField` metadata of `schemas/v1/cli-status.json`.
pub(crate) const CLI_STATUS_META_NAMESPACE_FIELD: &str = "schema";

/// The `unknownFields` metadata of `schemas/v1/cli-status.json`.
pub(crate) const CLI_STATUS_META_UNKNOWN_FIELDS: &str = "reject";

/// Every top-level member name `schemas/v1/cli-status.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CLI_STATUS_FIELD_NAMES: [&str; 6] = [
    "generated_at",
    "last_capture_at",
    "schema",
    "sources",
    "spool",
    "state",
];

/// Closed enum tokens of `state-verdict/integrity` in `schemas/v1/cli-status.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_STATUS_STATE_VERDICT_INTEGRITY_TOKENS: &[&str] = &["ok", "degraded"];

/// Bearing of the `state-verdict/integrity` enum in `schemas/v1/cli-status.json`.
pub(crate) const ENUM_CLI_STATUS_STATE_VERDICT_INTEGRITY_BEARING: &str = "structural";

/// Whether the `state-verdict/integrity` enum in `schemas/v1/cli-status.json` is declared fail-closed.
pub(crate) const ENUM_CLI_STATUS_STATE_VERDICT_INTEGRITY_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/cli-verify-state.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CLI_VERIFY_STATE: &str = "urn:agent-archivist:schema:v1:cli-verify-state";

/// Pinned const of `schema` in `schemas/v1/cli-verify-state.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CLI_VERIFY_STATE_SCHEMA: &str = "archivist.cli-result/v1";

/// The `closedShape` metadata of `schemas/v1/cli-verify-state.json`.
pub(crate) const CLI_VERIFY_STATE_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/cli-verify-state.json`.
pub(crate) const CLI_VERIFY_STATE_META_COMPATIBILITY: &str = "member additions are additive within v1 per plan Section 7.1 (CLI-015); redefining or removing a member, or a new namespace, is a v2 event";

/// The `floats` metadata of `schemas/v1/cli-verify-state.json`.
pub(crate) const CLI_VERIFY_STATE_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/cli-verify-state.json`.
pub(crate) const CLI_VERIFY_STATE_META_NAMESPACE: &str = "archivist.cli-result/v1";

/// The `namespaceField` metadata of `schemas/v1/cli-verify-state.json`.
pub(crate) const CLI_VERIFY_STATE_META_NAMESPACE_FIELD: &str = "schema";

/// The `unknownFields` metadata of `schemas/v1/cli-verify-state.json`.
pub(crate) const CLI_VERIFY_STATE_META_UNKNOWN_FIELDS: &str = "reject";

/// Every top-level member name `schemas/v1/cli-verify-state.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CLI_VERIFY_STATE_FIELD_NAMES: [&str; 5] = [
    "checks",
    "counts",
    "generated_at",
    "schema",
    "verdict",
];

/// Closed enum tokens of `check-verdicts/acknowledged_receipted` in `schemas/v1/cli-verify-state.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_ACKNOWLEDGED_RECEIPTED_TOKENS: &[&str] = &[
    "ok",
    "degraded",
];

/// Bearing of the `check-verdicts/acknowledged_receipted` enum in `schemas/v1/cli-verify-state.json`.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_ACKNOWLEDGED_RECEIPTED_BEARING: &str = "structural";

/// Whether the `check-verdicts/acknowledged_receipted` enum in `schemas/v1/cli-verify-state.json` is declared fail-closed.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_ACKNOWLEDGED_RECEIPTED_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/foreign_keys` in `schemas/v1/cli-verify-state.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_FOREIGN_KEYS_TOKENS: &[&str] = &[
    "ok",
    "degraded",
];

/// Bearing of the `check-verdicts/foreign_keys` enum in `schemas/v1/cli-verify-state.json`.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_FOREIGN_KEYS_BEARING: &str = "structural";

/// Whether the `check-verdicts/foreign_keys` enum in `schemas/v1/cli-verify-state.json` is declared fail-closed.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_FOREIGN_KEYS_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/live_bundles_present` in `schemas/v1/cli-verify-state.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_LIVE_BUNDLES_PRESENT_TOKENS: &[&str] = &[
    "ok",
    "degraded",
];

/// Bearing of the `check-verdicts/live_bundles_present` enum in `schemas/v1/cli-verify-state.json`.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_LIVE_BUNDLES_PRESENT_BEARING: &str = "structural";

/// Whether the `check-verdicts/live_bundles_present` enum in `schemas/v1/cli-verify-state.json` is declared fail-closed.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_LIVE_BUNDLES_PRESENT_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/schema_objects` in `schemas/v1/cli-verify-state.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_SCHEMA_OBJECTS_TOKENS: &[&str] = &[
    "ok",
    "degraded",
];

/// Bearing of the `check-verdicts/schema_objects` enum in `schemas/v1/cli-verify-state.json`.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_SCHEMA_OBJECTS_BEARING: &str = "structural";

/// Whether the `check-verdicts/schema_objects` enum in `schemas/v1/cli-verify-state.json` is declared fail-closed.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_SCHEMA_OBJECTS_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `check-verdicts/sqlite_integrity` in `schemas/v1/cli-verify-state.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_SQLITE_INTEGRITY_TOKENS: &[&str] = &[
    "ok",
    "degraded",
];

/// Bearing of the `check-verdicts/sqlite_integrity` enum in `schemas/v1/cli-verify-state.json`.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_SQLITE_INTEGRITY_BEARING: &str = "structural";

/// Whether the `check-verdicts/sqlite_integrity` enum in `schemas/v1/cli-verify-state.json` is declared fail-closed.
pub(crate) const ENUM_CLI_VERIFY_STATE_CHECK_VERDICTS_SQLITE_INTEGRITY_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `verdict` in `schemas/v1/cli-verify-state.json`.
/// Bearing `structural`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CLI_VERIFY_STATE_VERDICT_TOKENS: &[&str] = &["ok", "degraded"];

/// Bearing of the `verdict` enum in `schemas/v1/cli-verify-state.json`.
pub(crate) const ENUM_CLI_VERIFY_STATE_VERDICT_BEARING: &str = "structural";

/// Whether the `verdict` enum in `schemas/v1/cli-verify-state.json` is declared fail-closed.
pub(crate) const ENUM_CLI_VERIFY_STATE_VERDICT_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/common.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_COMMON: &str = "urn:agent-archivist:schema:v1:common";

/// Closed enum tokens of `artifact-kind` in `schemas/v1/common.json`.
/// Bearing `identity`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_ARTIFACT_KIND_TOKENS: &[&str] = &[
    "file-slice",
    "database-projection",
];

/// Bearing of the `artifact-kind` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_ARTIFACT_KIND_BEARING: &str = "identity";

/// Whether the `artifact-kind` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_ARTIFACT_KIND_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `checksum-algorithm` in `schemas/v1/common.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_CHECKSUM_ALGORITHM_TOKENS: &[&str] = &["sha256"];

/// Bearing of the `checksum-algorithm` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_CHECKSUM_ALGORITHM_BEARING: &str = "security";

/// Whether the `checksum-algorithm` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_CHECKSUM_ALGORITHM_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `id-source` in `schemas/v1/common.json`.
/// Bearing `identity`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_ID_SOURCE_TOKENS: &[&str] = &["upstream", "synthetic"];

/// Bearing of the `id-source` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_ID_SOURCE_BEARING: &str = "identity";

/// Whether the `id-source` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_ID_SOURCE_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `range-kind` in `schemas/v1/common.json`.
/// Bearing `identity`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_RANGE_KIND_TOKENS: &[&str] = &["byte", "event"];

/// Bearing of the `range-kind` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_RANGE_KIND_BEARING: &str = "identity";

/// Whether the `range-kind` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_RANGE_KIND_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `signature-algorithm` in `schemas/v1/common.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_SIGNATURE_ALGORITHM_TOKENS: &[&str] = &["ed25519"];

/// Bearing of the `signature-algorithm` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_SIGNATURE_ALGORITHM_BEARING: &str = "security";

/// Whether the `signature-algorithm` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_SIGNATURE_ALGORITHM_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `storage-outcome` in `schemas/v1/common.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_STORAGE_OUTCOME_TOKENS: &[&str] = &[
    "created",
    "already_present",
    "replaced_equivalent",
    "logically_committed_unknown_physical_result",
];

/// Bearing of the `storage-outcome` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_STORAGE_OUTCOME_BEARING: &str = "security";

/// Whether the `storage-outcome` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_STORAGE_OUTCOME_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `storage-profile` in `schemas/v1/common.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_STORAGE_PROFILE_TOKENS: &[&str] = &["zstd-v1"];

/// Bearing of the `storage-profile` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_STORAGE_PROFILE_BEARING: &str = "security";

/// Whether the `storage-profile` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_STORAGE_PROFILE_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `transport-encoding` in `schemas/v1/common.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_COMMON_TRANSPORT_ENCODING_TOKENS: &[&str] = &["identity", "zstd"];

/// Bearing of the `transport-encoding` enum in `schemas/v1/common.json`.
pub(crate) const ENUM_COMMON_TRANSPORT_ENCODING_BEARING: &str = "security";

/// Whether the `transport-encoding` enum in `schemas/v1/common.json` is declared fail-closed.
pub(crate) const ENUM_COMMON_TRANSPORT_ENCODING_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/consumption-policy.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONSUMPTION_POLICY: &str = "urn:agent-archivist:schema:v1:consumption-policy";

/// Closed enum tokens of `record-kind` in `schemas/v1/consumption-policy.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONSUMPTION_POLICY_RECORD_KIND_TOKENS: &[&str] = &[
    "immutable",
    "current-pointer",
];

/// Bearing of the `record-kind` enum in `schemas/v1/consumption-policy.json`.
pub(crate) const ENUM_CONSUMPTION_POLICY_RECORD_KIND_BEARING: &str = "security";

/// Whether the `record-kind` enum in `schemas/v1/consumption-policy.json` is declared fail-closed.
pub(crate) const ENUM_CONSUMPTION_POLICY_RECORD_KIND_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `record-type` in `schemas/v1/consumption-policy.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONSUMPTION_POLICY_RECORD_TYPE_TOKENS: &[&str] = &[
    "consumption-policy",
    "consumption-policy-pointer",
];

/// Bearing of the `record-type` enum in `schemas/v1/consumption-policy.json`.
pub(crate) const ENUM_CONSUMPTION_POLICY_RECORD_TYPE_BEARING: &str = "security";

/// Whether the `record-type` enum in `schemas/v1/consumption-policy.json` is declared fail-closed.
pub(crate) const ENUM_CONSUMPTION_POLICY_RECORD_TYPE_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/control-authority-rotation.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_AUTHORITY_ROTATION: &str = "urn:agent-archivist:schema:v1:control-authority-rotation";

/// Pinned const of `record_kind` in `schemas/v1/control-authority-rotation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_AUTHORITY_ROTATION_RECORD_KIND: &str = "immutable";

/// Pinned const of `record_type` in `schemas/v1/control-authority-rotation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_AUTHORITY_ROTATION_RECORD_TYPE: &str = "authority-rotation";

/// The `canonicalization` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_CANONICALIZATION: &str = "rfc8785";

/// The `chainRule` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_CHAIN_RULE: &str = "The predecessor signs: `authority_key_id` equals `previous_key_id` (VAL-002 cross-field check, re-made by every verifier), and the record's Ed25519 signature verifies against `previous_public_key` — a rotation record signed by the successor key it establishes would be circular and is rejected, because verification never trusts a key because a record asserts it. The object key's segment equals `previous_key_id` in lowercase canonical hex (VAL-002, ID-008), so the record is addressable from exactly the material a verifier already trusts: holding pinned root R, the verifier fetches `authority-rotations/<R>.json`, checks the signature against R's half, and gains the successor named by `key_id` — then repeats from there until it reaches the signer named by the record it is actually verifying. The walk terminates at the pinned root because each link names its predecessor, and every link is immutable and retained, so a key's validity is computable from the store's public material alone: the half established by link L verifies from L's `signed_at` until the `signed_at` of the link whose `previous_key_id` names it — or indefinitely, if no such link exists. The chain has no epoch sequence: the links themselves are the order, each retiring exactly the key the previous link established.";

/// The `closedShape` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_COMPATIBILITY: &str = "member additions, redefinitions, and new required members are all v2 namespace events — the closed shape is the compatibility rule for control records (docs/notes/control-trust-schemas.md). The only in-place appends this schema tolerates are new tokens inside already-closed enums (record_type in the envelope; key_algorithm through the shared common definition), each shipped together with the readers that understand it";

/// The `floats` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_NAMESPACE_FIELD: &str = "schema";

/// The `objectKey` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_OBJECT_KEY: &str = "schemas/v1/control-envelope.json#/$defs/authority-rotation-object-key";

/// The `overlapRule` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_OVERLAP_RULE: &str = "The signing overlap is the envelope's named rotation-verification constant — `rotationVerificationOverlapHours` (24, plan Section 5: key rotation accepts old and new keys for 24 hours), the same constant the linked-client and rotation records pin, anchored here at this record's `signed_at`. From that instant, either authority half may sign control records and receipt-key certifications, and a verifier accepts either: the predecessor's signature through `previous_public_key` in this record, the successor's through the chain this record extends. The window bounds signing acceptance, never the validity of what was already signed: a control record or receipt certification the predecessor signed inside the window — its own `signed_at` at or before this record's `signed_at` plus the overlap — verifies for as long as the records are retained, and one the predecessor signed after the window fails closed, the plan Section 7.1 rule for security-bearing values. The overlap is tolerance for the boundary, never an extension of the predecessor's authority: the offline ControlAdminStore switches to the successor as its signing key at the rotation itself, and the window exists so administrative records and receipt certifications signed by the predecessor across the boundary — an in-flight batch, a certification racing the cutover — stay verifiable, and so every reader's view converges within its own 60-second trust cache rather than at the rotation instant.";

/// The `privateKey` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_PRIVATE_KEY: &str = "both halves here are public — `previous_public_key` survives in this record precisely because verifiers need it to check this record's own signature and the window, and `public_key` is the half later records name in `authority_key_id`. No private material exists anywhere in this or any other record: the successor private half is generated by the tenant operator out of band, used to sign with, and reaches nothing else; the predecessor private half dies with the rotation (SEC-006). The gate's banned-name grammar plus the closed shape leave no member for material to ride in.";

/// The `replicaRule` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_REPLICA_RULE: &str = "An ingestion replica authenticating an uploader against a control record signed by an authority half its pinned root does not directly name resolves the signer through this chain, statelessly: the store's records are the only state (plan Section 3), and the 60-second trust cache bounds how long any earlier view is served (plan Section 5; EC-09) — the replica re-reads the chain like any other control record. Inside the overlap the replica accepts records signed by either half, each verified against its own establishing link; after the window a predecessor-signed record fails closed, and because acceptance is checked at the record's own `signed_at`, never at read time, records the predecessor legitimately signed before the window closed keep verifying forever. The offline ControlAdminStore writes this record signed by the predecessor and treats it as its own signing-key cutover: from the rotation instant it signs with the successor, inside the window a record it signed with either half verifies, and after the window a predecessor-signed write is rejected by every reader — the store gains nothing by signing with a retired half and the window costs no enforcement.";

/// The `rotationVerificationOverlapHours` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_ROTATION_VERIFICATION_OVERLAP_HOURS: usize = 24;

/// The `signature` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_SIGNATURE: &str = "control-record-v1 (schemas/v1/control-envelope.json): Ed25519 by the tenant authority named by `authority_key_id` over the RFC 8785 canonicalization of this object with the `authority_signature` member removed. The same construction, key namespace, and verifier core as every other control record; domain separation comes from `record_type`, so an authority rotation can never be replayed as another control record or the reverse. The signing key here is the predecessor — the still-current authority half at signing time — which is the chain rule itself: the record is the predecessor's signed witness to its own retirement, and the successor's half verifies only through it.";

/// The `trustRecordCacheTtlSeconds` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_TRUST_RECORD_CACHE_TTL_SECONDS: usize = 60;

/// The `unknownFields` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/control-authority-rotation.json`.
pub(crate) const CONTROL_AUTHORITY_ROTATION_META_WRITE_CLASS: &str = "immutable";

/// Every top-level member name `schemas/v1/control-authority-rotation.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CONTROL_AUTHORITY_ROTATION_FIELD_NAMES: [&str; 12] = [
    "authority_key_id",
    "authority_signature",
    "key_algorithm",
    "key_id",
    "previous_key_id",
    "previous_public_key",
    "public_key",
    "record_kind",
    "record_type",
    "schema",
    "signed_at",
    "tenant_id",
];

/// The canonical schema URN of `schemas/v1/control-client.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_CLIENT: &str = "urn:agent-archivist:schema:v1:control-client";

/// Pinned const of `record_kind` in `schemas/v1/control-client.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_CLIENT_RECORD_KIND: &str = "current-pointer";

/// Pinned const of `record_type` in `schemas/v1/control-client.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_CLIENT_RECORD_TYPE: &str = "linked-client";

/// The `canonicalization` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_COMPATIBILITY: &str = "member additions, redefinitions, and new required members are all v2 namespace events — the closed shape is the compatibility rule for control records (docs/notes/control-trust-schemas.md). The only in-place appends this schema tolerates are new tokens inside already-closed enums (record_type in the envelope; operations below), each shipped together with the readers that understand it";

/// The `epochRule` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_EPOCH_RULE: &str = "a replacement of this record is accepted only when its signed `authorization_epoch` strictly increases (plan Section 5). The link starts at epoch 1; every key rotation, scope change, and revocation bumps it. An ingest attempt presents the current epoch inside its signature, and a stale-epoch attempt fails closed even when its immutable envelope is valid (plan Phase 3 exit gate); the receipt records which epoch authorized the commit.";

/// The `floats` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_NAMESPACE_FIELD: &str = "schema";

/// The `objectKey` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_OBJECT_KEY: &str = "schemas/v1/control-envelope.json#/$defs/client-object-key";

/// The `privateKey` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_PRIVATE_KEY: &str = "the client's private half never appears in this or any other record, file, or argument — it is generated on the host (ID-001), used there to sign attempts, and reaches nothing else (SEC-006). This record carries the public half only; `key_id` is derivable from it by the pinned SHA-256 construction, so the record proves its own key identity";

/// The `rotationVerificationOverlapHours` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_ROTATION_VERIFICATION_OVERLAP_HOURS: usize = 24;

/// The `signature` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_SIGNATURE: &str = "control-record-v1 (schemas/v1/control-envelope.json): Ed25519 by the tenant authority named by `authority_key_id` over the RFC 8785 canonicalization of this object with the `authority_signature` member removed. The chain an offline verifier walks: pinned authority root over this record, record's public key over each ingest attempt (ID-009).";

/// The `trustRecordCacheTtlSeconds` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_TRUST_RECORD_CACHE_TTL_SECONDS: usize = 60;

/// The `unknownFields` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/control-client.json`.
pub(crate) const CONTROL_CLIENT_META_WRITE_CLASS: &str = "current-pointer";

/// Every top-level member name `schemas/v1/control-client.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CONTROL_CLIENT_FIELD_NAMES: [&str; 13] = [
    "authority_key_id",
    "authority_signature",
    "authorization_epoch",
    "client_id",
    "key_algorithm",
    "key_id",
    "public_key",
    "record_kind",
    "record_type",
    "schema",
    "scopes",
    "signed_at",
    "tenant_id",
];

/// Closed enum tokens of `scopes/operations` in `schemas/v1/control-client.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONTROL_CLIENT_SCOPES_OPERATIONS_TOKENS: &[&str] = &["ingest"];

/// Bearing of the `scopes/operations` enum in `schemas/v1/control-client.json`.
pub(crate) const ENUM_CONTROL_CLIENT_SCOPES_OPERATIONS_BEARING: &str = "security";

/// Whether the `scopes/operations` enum in `schemas/v1/control-client.json` is declared fail-closed.
pub(crate) const ENUM_CONTROL_CLIENT_SCOPES_OPERATIONS_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/control-delegation.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_DELEGATION: &str = "urn:agent-archivist:schema:v1:control-delegation";

/// Pinned const of `record_kind` in `schemas/v1/control-delegation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_DELEGATION_RECORD_KIND: &str = "current-pointer";

/// Pinned const of `record_type` in `schemas/v1/control-delegation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_DELEGATION_RECORD_TYPE: &str = "delegation";

/// The `canonicalization` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_COMPATIBILITY: &str = "member additions, redefinitions, and new required members are all v2 namespace events — the closed shape is the compatibility rule for control records (docs/notes/control-trust-schemas.md). The only in-place appends this schema tolerates are new tokens inside already-closed enums (record_type in the envelope; delegation_state and operations below), each shipped together with the readers that understand it";

/// The `epochRule` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_EPOCH_RULE: &str = "The grant's own monotonic sequence — the subject of this pointer is the (relay, origin) relation, not a client. The first grant of a pair is epoch 1, and every revision or withdrawal publishes the next epoch of the same object; a replacement is accepted only when its signed `authorization_epoch` strictly increases (plan Section 5). The relay's client epoch is a separate sequence presented by the attempt and checked against the relay's own linked-client pointer: revoking or rotating the relay does not touch this object, and a revoked relay fails closed through its own pointer and revocation record regardless of how active its grants are. Withdrawal is the one representation the current-pointer shape permits — the store has no delete, so withdrawing a grant publishes a strictly higher-epoch record at the same key with `delegation_state: withdrawn`, whose scopes are inert.";

/// The `floats` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_NAMESPACE_FIELD: &str = "schema";

/// The `objectKey` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_OBJECT_KEY: &str = "schemas/v1/control-envelope.json#/$defs/delegation-object-key";

/// The `privateKey` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_PRIVATE_KEY: &str = "no key material exists anywhere in this record — it grants a relation, not an identity. The relay signs attempts with the relay's key, verified through the relay's own linked-client record; the origin's identity is carried on occurrences and attestations, verified through the origin's record; this record adds origin authority, never a second key (SEC-006, ID-001). The gate's banned-name grammar plus the closed shape leave no member for material to ride in.";

/// The `signature` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_SIGNATURE: &str = "control-record-v1 (schemas/v1/control-envelope.json): Ed25519 by the tenant authority named by `authority_key_id` over the RFC 8785 canonicalization of this object with the `authority_signature` member removed. The same construction, key namespace, and verifier core as the linked-client and revocation records; domain separation comes from `record_type`, so a delegation can never be replayed as a client, rotation, or revocation record or the reverse.";

/// The `trustRecordCacheTtlSeconds` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_TRUST_RECORD_CACHE_TTL_SECONDS: usize = 60;

/// The `unknownFields` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/control-delegation.json`.
pub(crate) const CONTROL_DELEGATION_META_WRITE_CLASS: &str = "current-pointer";

/// Every top-level member name `schemas/v1/control-delegation.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CONTROL_DELEGATION_FIELD_NAMES: [&str; 12] = [
    "authority_key_id",
    "authority_signature",
    "authorization_epoch",
    "delegation_state",
    "origin_client_id",
    "record_kind",
    "record_type",
    "relay_client_id",
    "schema",
    "scopes",
    "signed_at",
    "tenant_id",
];

/// Closed enum tokens of `delegation_state` in `schemas/v1/control-delegation.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONTROL_DELEGATION_DELEGATION_STATE_TOKENS: &[&str] = &[
    "active",
    "withdrawn",
];

/// Bearing of the `delegation_state` enum in `schemas/v1/control-delegation.json`.
pub(crate) const ENUM_CONTROL_DELEGATION_DELEGATION_STATE_BEARING: &str = "security";

/// Whether the `delegation_state` enum in `schemas/v1/control-delegation.json` is declared fail-closed.
pub(crate) const ENUM_CONTROL_DELEGATION_DELEGATION_STATE_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `scopes/operations` in `schemas/v1/control-delegation.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONTROL_DELEGATION_SCOPES_OPERATIONS_TOKENS: &[&str] = &["ingest"];

/// Bearing of the `scopes/operations` enum in `schemas/v1/control-delegation.json`.
pub(crate) const ENUM_CONTROL_DELEGATION_SCOPES_OPERATIONS_BEARING: &str = "security";

/// Whether the `scopes/operations` enum in `schemas/v1/control-delegation.json` is declared fail-closed.
pub(crate) const ENUM_CONTROL_DELEGATION_SCOPES_OPERATIONS_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/control-envelope.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_ENVELOPE: &str = "urn:agent-archivist:schema:v1:control-envelope";

/// The `authorityChain` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_AUTHORITY_CHAIN: &str = "every control record is signed by the tenant authority: `authority_key_id` names the signing key and `authority_signature` carries the signature (construction `control-record-v1` below). The named key is either the tenant authority root the client pinned during linking (ID-009) or a successor established by an authority-rotation record — the record type that chains each successor key to its predecessor at the predecessor's own key ID (`tenants/<tenant>/v1/control/authority-rotations/<previous_key_id>.json`, schemas/v1/control-authority-rotation.json), signed by the key it retires. Verification always starts at the pinned root and walks forward: fetch the rotation record whose key segment names the key you trust, verify it against that half, adopt the successor its `key_id` names, repeat — and never trust a key because a record asserts it";

/// The `canonicalization` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_CLOSED_SHAPE: bool = true;

/// The `floats` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_NAMESPACE_FIELD: &str = "schema";

/// The `publicMaterialOnly` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_PUBLIC_MATERIAL_ONLY: &str = "no member of any control record carries private-key material: every key-bearing member is a public half under a common shape, and the closed shape leaves no undeclared member for anything else to ride in (SEC-006). tools/check-control-schemas.py rejects private/secret/seed member names outright so the property is machine-checked, not aspirational";

/// The `unknownFields` metadata of `schemas/v1/control-envelope.json`.
pub(crate) const CONTROL_ENVELOPE_META_UNKNOWN_FIELDS: &str = "reject";

/// Closed enum tokens of `record-kind` in `schemas/v1/control-envelope.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONTROL_ENVELOPE_RECORD_KIND_TOKENS: &[&str] = &[
    "immutable",
    "current-pointer",
];

/// Bearing of the `record-kind` enum in `schemas/v1/control-envelope.json`.
pub(crate) const ENUM_CONTROL_ENVELOPE_RECORD_KIND_BEARING: &str = "security";

/// Whether the `record-kind` enum in `schemas/v1/control-envelope.json` is declared fail-closed.
pub(crate) const ENUM_CONTROL_ENVELOPE_RECORD_KIND_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `record-type` in `schemas/v1/control-envelope.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONTROL_ENVELOPE_RECORD_TYPE_TOKENS: &[&str] = &[
    "linked-client",
    "revocation",
    "delegation",
    "rotation",
    "receipt-key",
    "authority-rotation",
    "retention",
];

/// Bearing of the `record-type` enum in `schemas/v1/control-envelope.json`.
pub(crate) const ENUM_CONTROL_ENVELOPE_RECORD_TYPE_BEARING: &str = "security";

/// Whether the `record-type` enum in `schemas/v1/control-envelope.json` is declared fail-closed.
pub(crate) const ENUM_CONTROL_ENVELOPE_RECORD_TYPE_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/control-receipt-key.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_RECEIPT_KEY: &str = "urn:agent-archivist:schema:v1:control-receipt-key";

/// Pinned const of `record_kind` in `schemas/v1/control-receipt-key.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_RECEIPT_KEY_RECORD_KIND: &str = "immutable";

/// Pinned const of `record_type` in `schemas/v1/control-receipt-key.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_RECEIPT_KEY_RECORD_TYPE: &str = "receipt-key";

/// The `canonicalization` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_CANONICALIZATION: &str = "rfc8785";

/// The `certificateSource` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_CERTIFICATE_SOURCE: &str = "The payload members — `key_id`, `key_algorithm`, `public_key`, `valid_from`, `valid_until` — are the receipt-key certificate definition in schemas/v1/ingest-receipt.json, consumed here: this control-prefix record is the authoritative copy of the certification whose by-value projection rides inside every receipt, and tools/check-control-schemas.py proves the member-for-member agreement, the object-key agreement, and the two named constants, so record and certificate cannot fork. `certificate_version` is deliberately absent: it is the wire certificate's own version axis (plan Section 7.1), not this family's — the control version axis is the namespace member, one axis, no numeric twin (docs/notes/control-trust-schemas.md decision 1).";

/// The `closedShape` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_COMPATIBILITY: &str = "member additions, redefinitions, and new required members are all v2 namespace events — the closed shape is the compatibility rule for control records (docs/notes/control-trust-schemas.md). The only in-place appends this schema tolerates are new tokens inside already-closed enums (record_type in the envelope; key_algorithm through the shared common definition), each shipped together with the readers that understand it";

/// The `floats` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_NAMESPACE_FIELD: &str = "schema";

/// The `objectKey` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_OBJECT_KEY: &str = "schemas/v1/control-envelope.json#/$defs/receipt-key-object-key";

/// The `privateKey` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_PRIVATE_KEY: &str = "the only key material here is the public half — `key_id` is its pinned SHA-256 derivation, computable from this record itself. The private half enters the server only through a secret reference (SEC-006) and appears in no record, file, or argument; the gate's banned-name grammar plus the closed shape leave no member for it to ride in.";

/// The `receiptKeyRotationDays` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_RECEIPT_KEY_ROTATION_DAYS: usize = 30;

/// The `receiptKeySigningOverlapDays` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_RECEIPT_KEY_SIGNING_OVERLAP_DAYS: usize = 7;

/// The `rotationRule` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_ROTATION_RULE: &str = "The signing window is the two envelope constants: a fresh key is certified every receiptKeyRotationDays (30, plan Section 7.8) and each key signs for receiptKeySigningOverlapDays (7) past its successor's first signing instant — `valid_until` − `valid_from` equals the two summed, 37 days, and a successor's `valid_from` sits exactly receiptKeyRotationDays after its predecessor's (VAL-002 cross-field checks a reader can re-make from the two records alone). The overlap keeps a valid signing key in hand across every rotation boundary; immutability keeps every retired certificate verifying, so rotation never invalidates a retained receipt (ID-009).";

/// The `signature` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_SIGNATURE: &str = "control-record-v1 (schemas/v1/control-envelope.json): Ed25519 by the tenant authority named by `authority_key_id` over the RFC 8785 canonicalization of this object with the `authority_signature` member removed. The same construction, key namespace, and verifier core as the linked-client, revocation, delegation, and rotation records; domain separation comes from `record_type`, so a receipt-key certification can never be replayed as another control record or the reverse. The administrative act that writes this record also produces the second signature the receipt chain needs — receipt-key-v1 (schemas/v1/ingest-identifiers.json) over the bare certificate, the same certification statement as the five payload members plus `certificate_version`, without the control wrapper members — because a receipt's embedded certificate is a data-plane object whose own signed bytes cannot grow the wrapper. The two signed byte ranges are structurally distinct by construction (the envelope's domain-separation rule: every control record's signed bytes contain the `schema` namespace member and no bare certificate's do), and both signatures come from the same pinned authority key, so one key-compromise story covers both.";

/// The `trustRecordCacheTtlSeconds` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_TRUST_RECORD_CACHE_TTL_SECONDS: usize = 60;

/// The `unknownFields` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/control-receipt-key.json`.
pub(crate) const CONTROL_RECEIPT_KEY_META_WRITE_CLASS: &str = "immutable";

/// Every top-level member name `schemas/v1/control-receipt-key.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CONTROL_RECEIPT_KEY_FIELD_NAMES: [&str; 12] = [
    "authority_key_id",
    "authority_signature",
    "key_algorithm",
    "key_id",
    "public_key",
    "record_kind",
    "record_type",
    "schema",
    "signed_at",
    "tenant_id",
    "valid_from",
    "valid_until",
];

/// The canonical schema URN of `schemas/v1/control-retention.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_RETENTION: &str = "urn:agent-archivist:schema:v1:control-retention";

/// Pinned const of `record_kind` in `schemas/v1/control-retention.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_RETENTION_RECORD_KIND: &str = "immutable";

/// Pinned const of `record_type` in `schemas/v1/control-retention.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_RETENTION_RECORD_TYPE: &str = "retention";

/// The `canonicalization` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_COMPATIBILITY: &str = "member additions, redefinitions, and new required members are all v2 namespace events — the closed shape is the compatibility rule for control records (docs/notes/control-trust-schemas.md). The only in-place appends this schema tolerates are new tokens inside already-closed enums (record_type in the envelope; retention_action and reason_class here), each shipped together with the readers that understand it — an old workflow fails closed on a new action token and neither tombstones nor releases anything it cannot interpret, which is the plan Section 7.1 rule for security-bearing values, not a compatibility break";

/// The `deletionGraceDays` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_DELETION_GRACE_DAYS: usize = 30;

/// The `epochRule` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_EPOCH_RULE: &str = "This record's `authorization_epoch` is the addressed occurrence's retention-history sequence — not a client authorization epoch and not a pointer guard: retention has no pointer, because the occurrence has no current object to guard, only a history to extend. It equals the object key's epoch segment in canonical decimal without leading zeros (VAL-002), and the envelope holds the member's bound and that grammar in lockstep — 18 digits at the ceiling. The first retention record for an occurrence is epoch 1 and every later record strictly increases; the store accepts a new record only at an epoch higher than every one present at the occurrence's retention prefix. A lost-response retry of identical bytes is the idempotent repair, as with every immutable record — one object per epoch, and an incompatible second write at the same epoch is rejected by the immutable-overwrite rule. Order is the only constraint the sequence carries: gaps are harmless, because state is the fold of the records in epoch order, never a distance between them.";

/// The `floats` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_NAMESPACE_FIELD: &str = "schema";

/// The `objectKey` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_OBJECT_KEY: &str = "schemas/v1/control-envelope.json#/$defs/retention-object-key";

/// The `offlineReader` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_OFFLINE_READER: &str = "The one shipped record type no ingestion replica reads, and the reason it pins no `trustRecordCacheTtlSeconds`: the 60-second cache TTL bounds how long an online replica may serve a stale trust record, and nothing online reads this record to serve stale. The plan's no-delete-route rule (plan Section 7.10) keeps the ingest path retention-blind — an uploader is authenticated by the linked-client, delegation, rotation, and revocation records exactly as before, and a hold or tombstone changes no authorization decision on that path. The record's readers are the offline deletion workflow and the auditors who re-verify it, and they re-read rather than cache: a hold or release takes effect when the store is next read, with no propagation bound to name, because the workflow's ordering guarantees (grace, two scans, HEAD revalidation) are the workflow's own beads of work, not members of this record.";

/// The `privateKey` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_PRIVATE_KEY: &str = "no private material exists anywhere in this record — `occurrence_id` is a SHA-256 digest of published occurrence fields, and every other member is an action, a bounded audit label, a timestamp, or a signature (SEC-006, ID-001). The gate's banned-name grammar plus the closed shape leave no member for material to ride in.";

/// The `retentionRule` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_RETENTION_RULE: &str = "The current retention state of an occurrence is the fold of its retention records in ascending epoch order, each mark set by its action and cleared only where stated: `tombstone` marks the occurrence scheduled for deletion, and the plan Section 7.10 grace runs from that record's `signed_at`; `legal-hold` marks a hold standing; `release` clears the hold and nothing else. Three properties the fold guarantees, and the deletion workflow depends on all three. Holds override deletion in either order: a tombstone never clears a hold, so a tombstone written under an active hold — whatever the epochs say — deletes nothing while the hold stands (SEC-007). A tombstone is permanent: no action un-tombstones, because the tombstone is the audit evidence the workflow ran on, and the plan's only route to shorter retention is a policy that still uses 'tombstones and reference-safe GC' (plan Section 7.10 revisit trigger). The default is no records: an occurrence with no retention history is retained indefinitely (plan Section 7.10: raw occurrences, attestations, and blobs default to indefinite retention). A referenced blob becomes collectible only when every occurrence referencing it is tombstoned, every such tombstone's grace has elapsed, and no hold on any of them stands — the shared-blob rule that makes per-occurrence records safe on shared storage (plan Section 7.10; SEC-008; EC-05).";

/// The `signature` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_SIGNATURE: &str = "control-record-v1 (schemas/v1/control-envelope.json): Ed25519 by the tenant authority named by `authority_key_id` over the RFC 8785 canonicalization of this object with the `authority_signature` member removed. The same construction, key namespace, and verifier core as every other control record; domain separation comes from `record_type`, so a retention record can never be replayed as another control record or the reverse. The signing key is the pinned root or the successor an authority-rotation chain establishes (ID-009) — a retention record is an administrative act of the tenant, and a signature from any other key is not a retention decision.";

/// The `unknownFields` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/control-retention.json`.
pub(crate) const CONTROL_RETENTION_META_WRITE_CLASS: &str = "immutable";

/// Every top-level member name `schemas/v1/control-retention.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CONTROL_RETENTION_FIELD_NAMES: [&str; 12] = [
    "audit_identity",
    "authority_key_id",
    "authority_signature",
    "authorization_epoch",
    "occurrence_id",
    "reason_class",
    "record_kind",
    "record_type",
    "retention_action",
    "schema",
    "signed_at",
    "tenant_id",
];

/// Closed enum tokens of `reason_class` in `schemas/v1/control-retention.json`.
/// Bearing `provenance`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONTROL_RETENTION_REASON_CLASS_TOKENS: &[&str] = &[
    "legal-hold",
    "tenant-policy",
    "operator-request",
    "privacy-request",
];

/// Bearing of the `reason_class` enum in `schemas/v1/control-retention.json`.
pub(crate) const ENUM_CONTROL_RETENTION_REASON_CLASS_BEARING: &str = "provenance";

/// Whether the `reason_class` enum in `schemas/v1/control-retention.json` is declared fail-closed.
pub(crate) const ENUM_CONTROL_RETENTION_REASON_CLASS_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `retention_action` in `schemas/v1/control-retention.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_CONTROL_RETENTION_RETENTION_ACTION_TOKENS: &[&str] = &[
    "tombstone",
    "legal-hold",
    "release",
];

/// Bearing of the `retention_action` enum in `schemas/v1/control-retention.json`.
pub(crate) const ENUM_CONTROL_RETENTION_RETENTION_ACTION_BEARING: &str = "security";

/// Whether the `retention_action` enum in `schemas/v1/control-retention.json` is declared fail-closed.
pub(crate) const ENUM_CONTROL_RETENTION_RETENTION_ACTION_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/control-revocation.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_REVOCATION: &str = "urn:agent-archivist:schema:v1:control-revocation";

/// Pinned const of `record_kind` in `schemas/v1/control-revocation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_REVOCATION_RECORD_KIND: &str = "immutable";

/// Pinned const of `record_type` in `schemas/v1/control-revocation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_REVOCATION_RECORD_TYPE: &str = "revocation";

/// The `canonicalization` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_COMPATIBILITY: &str = "member additions, redefinitions, and new required members are all v2 namespace events — the closed shape is the compatibility rule for control records (docs/notes/control-trust-schemas.md). The only in-place appends this schema tolerates are new tokens inside already-closed enums (record_type in the envelope), each shipped together with the readers that understand it";

/// The `epochRule` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_EPOCH_RULE: &str = "This record revokes the epoch its signed `authorization_epoch` names — the revoked epoch, equal to the object key's epoch segment (VAL-002). The write is accepted only when the revoked epoch does not exceed the linked-client pointer's current signed epoch: one cannot pre-revoke an epoch the client has not reached, because a forward-dated revocation would otherwise arm itself against a legitimate later rotation. Revocation is completed by publishing a strictly higher epoch of the linked-client record (plan Section 5), which is the move that fails stale-epoch attempts closed; together the two writes leave the client's authorization history a strictly ascending sequence — the pointer never decreases, and each revocation permanently fixes one of its rungs. Append-only follows: one immutable object per (client, epoch), a lost-response retry of identical bytes is an idempotent repair, and there is no operation that removes or supersedes a revocation — relinking after revocation (EC-12) is a new, higher epoch with a new key, never an edit of this record.";

/// The `floats` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_NAMESPACE_FIELD: &str = "schema";

/// The `objectKey` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_OBJECT_KEY: &str = "schemas/v1/control-envelope.json#/$defs/revocation-object-key";

/// The `privateKey` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_PRIVATE_KEY: &str = "no private material exists anywhere in this record — `revoked_key_id` is the SHA-256 of a public key and every other member is an identifier, a timestamp, or a signature (SEC-006, ID-001). The key that died stays wherever it died; this record proves it is dead.";

/// The `revocationPropagationBoundSeconds` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_REVOCATION_PROPAGATION_BOUND_SECONDS: usize = 60;

/// The `signature` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_SIGNATURE: &str = "control-record-v1 (schemas/v1/control-envelope.json): Ed25519 by the tenant authority named by `authority_key_id` over the RFC 8785 canonicalization of this object with the `authority_signature` member removed. The same construction, key namespace, and verifier core as the linked-client record; domain separation comes from `record_type`, so a revocation can never be replayed as a client record or the reverse.";

/// The `unknownFields` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/control-revocation.json`.
pub(crate) const CONTROL_REVOCATION_META_WRITE_CLASS: &str = "immutable";

/// Every top-level member name `schemas/v1/control-revocation.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CONTROL_REVOCATION_FIELD_NAMES: [&str; 10] = [
    "authority_key_id",
    "authority_signature",
    "authorization_epoch",
    "client_id",
    "record_kind",
    "record_type",
    "revoked_key_id",
    "schema",
    "signed_at",
    "tenant_id",
];

/// The canonical schema URN of `schemas/v1/control-rotation.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_CONTROL_ROTATION: &str = "urn:agent-archivist:schema:v1:control-rotation";

/// Pinned const of `record_kind` in `schemas/v1/control-rotation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_ROTATION_RECORD_KIND: &str = "immutable";

/// Pinned const of `record_type` in `schemas/v1/control-rotation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const CONTROL_ROTATION_RECORD_TYPE: &str = "rotation";

/// The `canonicalization` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_COMPATIBILITY: &str = "member additions, redefinitions, and new required members are all v2 namespace events — the closed shape is the compatibility rule for control records (docs/notes/control-trust-schemas.md). The only in-place appends this schema tolerates are new tokens inside already-closed enums (record_type in the envelope; key_algorithm through the shared common definition), each shipped together with the readers that understand it";

/// The `epochRule` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_EPOCH_RULE: &str = "This record's signed `authorization_epoch` is the epoch the rotation establishes — equal to the object key's epoch segment (VAL-002), so a reader holding the linked-client pointer at epoch E finds the overlap evidence for E's key at exactly `rotations/<client>/E.json`. `previous_epoch` equals `authorization_epoch` − 1 (VAL-002 cross-field check): every pointer move publishes the next epoch — the link is epoch 1 and each rotation, scope change, or revocation publishes exactly the next one — so a rotation never skips an epoch. The write is accepted only when the established epoch does not exceed the linked-client pointer's current signed epoch and the pointer at that epoch carries this record's `public_key`: one cannot pre-date a rotation for an epoch the client has not reached, because a forward-dated rotation would arm its overlap window early. The record and the pointer bump that activates it are one administrative act; immutability then makes the history append-only — one object per (client, established epoch), a lost-response retry of identical bytes is an idempotent repair, and no operation removes or rewrites a rotation.";

/// The `floats` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_FLOATS: bool = false;

/// The `namespace` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_NAMESPACE: &str = "archivist.control/v1";

/// The `namespaceField` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_NAMESPACE_FIELD: &str = "schema";

/// The `objectKey` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_OBJECT_KEY: &str = "schemas/v1/control-envelope.json#/$defs/rotation-object-key";

/// The `privateKey` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_PRIVATE_KEY: &str = "both halves here are public — `previous_public_key` survives in this record precisely because verification needs it, and `public_key` is the half the established epoch's linked-client record carries. No private material exists anywhere in this or any other record: the new private half is generated on the client host (ID-001), used there to sign attempts, and reaches nothing else; the old private half dies with the rotation (SEC-006). The gate's banned-name grammar plus the closed shape leave no member for material to ride in.";

/// The `rotationVerificationOverlapHours` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_ROTATION_VERIFICATION_OVERLAP_HOURS: usize = 24;

/// The `signature` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_SIGNATURE: &str = "control-record-v1 (schemas/v1/control-envelope.json): Ed25519 by the tenant authority named by `authority_key_id` over the RFC 8785 canonicalization of this object with the `authority_signature` member removed. The same construction, key namespace, and verifier core as the linked-client, revocation, and delegation records; domain separation comes from `record_type`, so a rotation can never be replayed as another control record or the reverse.";

/// The `trustRecordCacheTtlSeconds` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_TRUST_RECORD_CACHE_TTL_SECONDS: usize = 60;

/// The `unknownFields` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/control-rotation.json`.
pub(crate) const CONTROL_ROTATION_META_WRITE_CLASS: &str = "immutable";

/// Every top-level member name `schemas/v1/control-rotation.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const CONTROL_ROTATION_FIELD_NAMES: [&str; 15] = [
    "authority_key_id",
    "authority_signature",
    "authorization_epoch",
    "client_id",
    "key_algorithm",
    "key_id",
    "previous_epoch",
    "previous_key_id",
    "previous_public_key",
    "public_key",
    "record_kind",
    "record_type",
    "schema",
    "signed_at",
    "tenant_id",
];

/// The canonical schema URN of `schemas/v1/derived-episode.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_DERIVED_EPISODE: &str = "urn:agent-archivist:schema:v1:derived-episode";

/// Pinned const of `episode_version` in `schemas/v1/derived-episode.json`;
/// an unknown value fails closed on the wire.
pub(crate) const DERIVED_EPISODE_EPISODE_VERSION: i64 = 1;

/// The `canonicalization` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_CLOSED_SHAPE: bool = true;

/// The `derivationStability` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_DERIVATION_STABILITY: &str = "every member is a deterministic function of the input occurrence set, pipeline_id + pipeline_version (with the detector corpus that version freezes, digest-pinned below), and the tenant pseudonym key. No wall-clock, producer, run, assessment, approval, or policy input exists to make two derivations of the same inputs diverge — which is what makes the Phase 10 rebuild exit gate and assessment freshness by digest comparison possible at all";

/// The `floats` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_FLOATS: bool = false;

/// The `governanceBoundary` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_GOVERNANCE_BOUNDARY: &str = "classification is evidence about an episode; policy decides what that evidence authorizes; approval is a human act binding both. All three are later, separately versioned, separately signed records that reference this one by `episode_digest` — the plan's separation of classifier (rules-v1), authorization (consumption-policy-v1), and human approval (use-approval-v1). Nothing of them is embedded here, so a re-assessment supersedes in place, a policy change fails closed without touching derived bytes, and an approval can expire and be revoked without the episode ever knowing";

/// The `mediaType` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.derived-episode+json;version=1";

/// The `objectKey` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_OBJECT_KEY: &str = "schemas/v1/common.json#/$defs/derived-episode-object-key";

/// The `unknownFields` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_WRITE_CLASS: &str = "immutable, content-addressed by episode_digest: one object per digest, a rebuild writes identical bytes, and nothing can displace it. The derived prefix never touches a raw namespace (plan Section 7.1 derived-pipeline axis: rebuildable; never overwrites raw data)";

/// The `writeOrder` metadata of `schemas/v1/derived-episode.json`.
pub(crate) const DERIVED_EPISODE_META_WRITE_ORDER: &str = "after every input occurrence manifest is durable, before any risk assessment (plan Phase 10: episodes precede and feed classification)";

/// Reserved per-attempt, server, or foreign names of
/// `schemas/v1/derived-episode.json` (x-archivist.reservedFields), in
/// schema order: names the record rejects outright, so retries
/// cannot fork identity on them.
pub(crate) const DERIVED_EPISODE_RESERVED_FIELDS: [&str; 35] = [
    "approval",
    "approved_by",
    "assessment",
    "assessment_digest",
    "assessment_id",
    "blob_key",
    "built_at",
    "classification",
    "created_at",
    "generated_at",
    "labels",
    "location",
    "mapping",
    "object_key",
    "path",
    "plaintext",
    "policy",
    "policy_version",
    "produced_at",
    "producer",
    "pseudonym_map",
    "pseudonym_salt",
    "raw_object_key",
    "redaction_map",
    "removed_content",
    "reverse_map",
    "risk_assessment",
    "run_id",
    "salt",
    "severity",
    "source_path",
    "trust_decision",
    "url",
    "use_approval",
    "verdict",
];

/// Every top-level member name `schemas/v1/derived-episode.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const DERIVED_EPISODE_FIELD_NAMES: [&str; 11] = [
    "detector_corpus_digest",
    "episode_digest",
    "episode_version",
    "marker_counts",
    "occurrence_ids",
    "pipeline_id",
    "pipeline_version",
    "pseudonym_counts",
    "pseudonym_key_id",
    "records",
    "tenant_id",
];

/// Closed enum tokens of `episode-role` in `schemas/v1/derived-episode.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_DERIVED_EPISODE_EPISODE_ROLE_TOKENS: &[&str] = &[
    "assistant",
    "system",
    "tool",
    "user",
];

/// Bearing of the `episode-role` enum in `schemas/v1/derived-episode.json`.
pub(crate) const ENUM_DERIVED_EPISODE_EPISODE_ROLE_BEARING: &str = "security";

/// Whether the `episode-role` enum in `schemas/v1/derived-episode.json` is declared fail-closed.
pub(crate) const ENUM_DERIVED_EPISODE_EPISODE_ROLE_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `pipeline_id` in `schemas/v1/derived-episode.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_DERIVED_EPISODE_PIPELINE_ID_TOKENS: &[&str] = &["redaction"];

/// Bearing of the `pipeline_id` enum in `schemas/v1/derived-episode.json`.
pub(crate) const ENUM_DERIVED_EPISODE_PIPELINE_ID_BEARING: &str = "security";

/// Whether the `pipeline_id` enum in `schemas/v1/derived-episode.json` is declared fail-closed.
pub(crate) const ENUM_DERIVED_EPISODE_PIPELINE_ID_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/export-approval.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_EXPORT_APPROVAL: &str = "urn:agent-archivist:schema:v1:export-approval";

/// The canonical schema URN of `schemas/v1/inference-artifact.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_INFERENCE_ARTIFACT: &str = "urn:agent-archivist:schema:v1:inference-artifact";

/// Pinned const of `inference_artifact_version` in `schemas/v1/inference-artifact.json`;
/// an unknown value fails closed on the wire.
pub(crate) const INFERENCE_ARTIFACT_INFERENCE_ARTIFACT_VERSION: i64 = 1;

/// The `blobIdentity` metadata of `schemas/v1/inference-artifact.json`.
pub(crate) const INFERENCE_ARTIFACT_META_BLOB_IDENTITY: &str = "content-addressed: the payload digest is the plain SHA-256 of the captured bytes (the one label-less digest, per schemas/v1/ingest-identifiers.json). trace_id, inference_request_id, provider_attempt_id, and every other correlation or provenance field are record members only and are never inputs to any digest or storage key (plan Phase 9 correlation rule)";

/// The `canonicalization` metadata of `schemas/v1/inference-artifact.json`.
pub(crate) const INFERENCE_ARTIFACT_META_CANONICALIZATION: &str = "rfc8785";

/// The `captureBoundary` metadata of `schemas/v1/inference-artifact.json`.
pub(crate) const INFERENCE_ARTIFACT_META_CAPTURE_BOUNDARY: &str = "plan Phase 9: payload bytes are captured at the proxy/SDK hook boundary after HTTP transfer decoding — never TLS/TCP framing, never transfer-encoding framing; a failure below the decoded-content boundary is a transport-error record carrying an error class, never framing bytes";

/// The `floats` metadata of `schemas/v1/inference-artifact.json`.
pub(crate) const INFERENCE_ARTIFACT_META_FLOATS: bool = false;

/// The `mediaType` metadata of `schemas/v1/inference-artifact.json`.
pub(crate) const INFERENCE_ARTIFACT_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.inference-artifact+json;version=1";

/// The `metadataAllowlist` metadata of `schemas/v1/inference-artifact.json`.
pub(crate) const INFERENCE_ARTIFACT_META_METADATA_ALLOWLIST: &str = "closed: `metadata` rejects every name outside the allowlist outright. A new metadata entry is a new schema major (v2), never an additive v1 field — the closure is the boundary that keeps header and body material from drifting into archive metadata (plan Section 11: provider credentials must never become archive metadata)";

/// The `unknownFields` metadata of `schemas/v1/inference-artifact.json`.
pub(crate) const INFERENCE_ARTIFACT_META_UNKNOWN_FIELDS: &str = "retain-ignore";

/// Reserved per-attempt, server, or foreign names of
/// `schemas/v1/inference-artifact.json` (x-archivist.reservedFields), in
/// schema order: names the record rejects outright, so retries
/// cannot fork identity on them.
pub(crate) const INFERENCE_ARTIFACT_RESERVED_FIELDS: [&str; 43] = [
    "access_token",
    "alpn",
    "api_key",
    "api_token",
    "authorization",
    "authorization_epoch",
    "authorization_key_id",
    "authorization_timestamp",
    "bearer_token",
    "blob_key",
    "blob_url",
    "certificate",
    "certificate_chain",
    "cipher_suite",
    "client_certificate",
    "client_secret",
    "cookie",
    "credential",
    "endpoint",
    "ip_packet",
    "object_key",
    "password",
    "private_key",
    "proxy_authorization",
    "refresh_token",
    "request_id",
    "secret",
    "session_token",
    "set_cookie",
    "signature",
    "signature_algorithm",
    "storage_path",
    "tcp_segment",
    "tls_handshake",
    "tls_record",
    "tls_session_ticket",
    "tls_version",
    "transport_encoding",
    "upload_url",
    "uri",
    "url",
    "www_authenticate",
    "x_api_key",
];

/// Every top-level member name `schemas/v1/inference-artifact.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const INFERENCE_ARTIFACT_FIELD_NAMES: [&str; 18] = [
    "artifact_kind",
    "attempt_ordinal",
    "backoff_ms",
    "capture_time",
    "error_class",
    "event_ordinal",
    "inference_artifact_version",
    "inference_request_id",
    "metadata",
    "origin_client_id",
    "payload",
    "provider_attempt_id",
    "retry_of_attempt_ordinal",
    "retry_reason",
    "tenant_id",
    "timeout_ms",
    "trace_id",
    "usage_source",
];

/// Closed enum tokens of `artifact_kind` in `schemas/v1/inference-artifact.json`.
/// Bearing `identity`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_INFERENCE_ARTIFACT_ARTIFACT_KIND_TOKENS: &[&str] = &[
    "provider-request",
    "provider-response",
    "streaming-event",
    "retry",
    "usage",
    "transport-error",
];

/// Bearing of the `artifact_kind` enum in `schemas/v1/inference-artifact.json`.
pub(crate) const ENUM_INFERENCE_ARTIFACT_ARTIFACT_KIND_BEARING: &str = "identity";

/// Whether the `artifact_kind` enum in `schemas/v1/inference-artifact.json` is declared fail-closed.
pub(crate) const ENUM_INFERENCE_ARTIFACT_ARTIFACT_KIND_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `error_class` in `schemas/v1/inference-artifact.json`.
/// Bearing `provenance`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_INFERENCE_ARTIFACT_ERROR_CLASS_TOKENS: &[&str] = &[
    "connect",
    "dns",
    "tls-handshake",
    "read-timeout",
    "write-timeout",
    "connection-reset",
    "stream-interrupted",
    "transfer-decode",
    "other",
];

/// Bearing of the `error_class` enum in `schemas/v1/inference-artifact.json`.
pub(crate) const ENUM_INFERENCE_ARTIFACT_ERROR_CLASS_BEARING: &str = "provenance";

/// Whether the `error_class` enum in `schemas/v1/inference-artifact.json` is declared fail-closed.
pub(crate) const ENUM_INFERENCE_ARTIFACT_ERROR_CLASS_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `retry_reason` in `schemas/v1/inference-artifact.json`.
/// Bearing `provenance`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_INFERENCE_ARTIFACT_RETRY_REASON_TOKENS: &[&str] = &[
    "http-status",
    "rate-limit",
    "transport-error",
    "stream-incomplete",
    "timeout",
];

/// Bearing of the `retry_reason` enum in `schemas/v1/inference-artifact.json`.
pub(crate) const ENUM_INFERENCE_ARTIFACT_RETRY_REASON_BEARING: &str = "provenance";

/// Whether the `retry_reason` enum in `schemas/v1/inference-artifact.json` is declared fail-closed.
pub(crate) const ENUM_INFERENCE_ARTIFACT_RETRY_REASON_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `usage_source` in `schemas/v1/inference-artifact.json`.
/// Bearing `provenance`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_INFERENCE_ARTIFACT_USAGE_SOURCE_TOKENS: &[&str] = &[
    "response-body",
    "stream-event",
];

/// Bearing of the `usage_source` enum in `schemas/v1/inference-artifact.json`.
pub(crate) const ENUM_INFERENCE_ARTIFACT_USAGE_SOURCE_BEARING: &str = "provenance";

/// Whether the `usage_source` enum in `schemas/v1/inference-artifact.json` is declared fail-closed.
pub(crate) const ENUM_INFERENCE_ARTIFACT_USAGE_SOURCE_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/ingest-envelope.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_INGEST_ENVELOPE: &str = "urn:agent-archivist:schema:v1:ingest-envelope";

/// Pinned const of `envelope_version` in `schemas/v1/ingest-envelope.json`;
/// an unknown value fails closed on the wire.
pub(crate) const INGEST_ENVELOPE_ENVELOPE_VERSION: i64 = 1;

/// Pinned const of `protocol_version` in `schemas/v1/ingest-envelope.json`;
/// an unknown value fails closed on the wire.
pub(crate) const INGEST_ENVELOPE_PROTOCOL_VERSION: i64 = 1;

/// The `canonicalMaxBytes` metadata of `schemas/v1/ingest-envelope.json`.
pub(crate) const INGEST_ENVELOPE_META_CANONICAL_MAX_BYTES: usize = 65536;

/// The `canonicalization` metadata of `schemas/v1/ingest-envelope.json`.
pub(crate) const INGEST_ENVELOPE_META_CANONICALIZATION: &str = "rfc8785";

/// The `floats` metadata of `schemas/v1/ingest-envelope.json`.
pub(crate) const INGEST_ENVELOPE_META_FLOATS: bool = false;

/// The `mediaType` metadata of `schemas/v1/ingest-envelope.json`.
pub(crate) const INGEST_ENVELOPE_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.envelope+json;version=1";

/// The `mediaTypeVersionParameter` metadata of `schemas/v1/ingest-envelope.json`.
pub(crate) const INGEST_ENVELOPE_META_MEDIA_TYPE_VERSION_PARAMETER: &str = "tracks envelope_version: the media-type parameter and the field must agree, so a v2 envelope is framed as version=2 and an old server rejects at the framing layer before parsing the body — part of the fail-closed major rule (plan Section 7.1)";

/// The `signedBy` metadata of `schemas/v1/ingest-envelope.json`.
pub(crate) const INGEST_ENVELOPE_META_SIGNED_BY: &str = "ingest-attempt-v1 signature parameters over the whole request (schemas/v1/ingest-request.json); the envelope itself never carries per-attempt material";

/// The `unknownFields` metadata of `schemas/v1/ingest-envelope.json`.
pub(crate) const INGEST_ENVELOPE_META_UNKNOWN_FIELDS: &str = "retain-ignore";

/// Reserved per-attempt, server, or foreign names of
/// `schemas/v1/ingest-envelope.json` (x-archivist.reservedFields), in
/// schema order: names the record rejects outright, so retries
/// cannot fork identity on them.
pub(crate) const INGEST_ENVELOPE_RESERVED_FIELDS: [&str; 6] = [
    "authorization_epoch",
    "authorization_key_id",
    "authorization_timestamp",
    "commit_time",
    "correlation_id",
    "signature",
];

/// Every top-level member name `schemas/v1/ingest-envelope.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const INGEST_ENVELOPE_FIELD_NAMES: [&str; 33] = [
    "adapter_artifact_id",
    "adapter_id",
    "adapter_projection_version",
    "artifact_kind",
    "attestation_id",
    "blob_digest",
    "capture_time",
    "compressed_size",
    "envelope_creation_time",
    "envelope_version",
    "generation",
    "harness",
    "id_source",
    "incoming_checksum",
    "incoming_checksum_algorithm",
    "inference_request_id",
    "occurrence_id",
    "orchestrator_attempt_id",
    "origin_client_id",
    "parent_session_id",
    "protocol_version",
    "range_end",
    "range_kind",
    "range_start",
    "request_id",
    "source_time",
    "storage_profile",
    "tenant_id",
    "trace_id",
    "transport_encoding",
    "uncompressed_size",
    "uploader_client_id",
    "upstream_session_id",
];

/// The canonical schema URN of `schemas/v1/ingest-error.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_INGEST_ERROR: &str = "urn:agent-archivist:schema:v1:ingest-error";

/// Pinned const of `schema` in `schemas/v1/ingest-error.json`;
/// an unknown value fails closed on the wire.
pub(crate) const INGEST_ERROR_SCHEMA: &str = "archivist.error/v1";

/// The `closedShape` metadata of `schemas/v1/ingest-error.json`.
pub(crate) const INGEST_ERROR_META_CLOSED_SHAPE: bool = true;

/// The `compatibility` metadata of `schemas/v1/ingest-error.json`.
pub(crate) const INGEST_ERROR_META_COMPATIBILITY: &str = "appending registry codes and rewording templates are compatible (ERR-035); renaming or redefining codes, changing this field set, or a new namespace are v2 events (ERR-036, ERR-038)";

/// The `floats` metadata of `schemas/v1/ingest-error.json`.
pub(crate) const INGEST_ERROR_META_FLOATS: bool = false;

/// The `mediaType` metadata of `schemas/v1/ingest-error.json`.
pub(crate) const INGEST_ERROR_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.error+json";

/// The `namespace` metadata of `schemas/v1/ingest-error.json`.
pub(crate) const INGEST_ERROR_META_NAMESPACE: &str = "archivist.error/v1";

/// The `namespaceField` metadata of `schemas/v1/ingest-error.json`.
pub(crate) const INGEST_ERROR_META_NAMESPACE_FIELD: &str = "schema";

/// The `unknownFields` metadata of `schemas/v1/ingest-error.json`.
pub(crate) const INGEST_ERROR_META_UNKNOWN_FIELDS: &str = "reject";

/// Every top-level member name `schemas/v1/ingest-error.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const INGEST_ERROR_FIELD_NAMES: [&str; 6] = [
    "code",
    "correlation_id",
    "message",
    "request_id",
    "retryable",
    "schema",
];

/// The canonical schema URN of `schemas/v1/ingest-identifiers.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_INGEST_IDENTIFIERS: &str = "urn:agent-archivist:schema:v1:ingest-identifiers";

/// The `fieldEncoding` metadata of `schemas/v1/ingest-identifiers.json`.
pub(crate) const INGEST_IDENTIFIERS_META_FIELD_ENCODING: &str = "each field: 8-byte unsigned big-endian byte length followed by exactly that many field bytes";

/// The `floats` metadata of `schemas/v1/ingest-identifiers.json`.
pub(crate) const INGEST_IDENTIFIERS_META_FLOATS: bool = false;

/// The `hash` metadata of `schemas/v1/ingest-identifiers.json`.
pub(crate) const INGEST_IDENTIFIERS_META_HASH: &str = "SHA-256";

/// The `hashOutput` metadata of `schemas/v1/ingest-identifiers.json`.
pub(crate) const INGEST_IDENTIFIERS_META_HASH_OUTPUT: &str = "64 lowercase hexadecimal characters (the derived identifier value on the wire)";

/// The `labelEncoding` metadata of `schemas/v1/ingest-identifiers.json`.
pub(crate) const INGEST_IDENTIFIERS_META_LABEL_ENCODING: &str = "UTF-8 bytes of the domain label followed by one 0x00 byte";

/// The canonical schema URN of `schemas/v1/ingest-receipt.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_INGEST_RECEIPT: &str = "urn:agent-archivist:schema:v1:ingest-receipt";

/// Pinned const of `receipt_version` in `schemas/v1/ingest-receipt.json`;
/// an unknown value fails closed on the wire.
pub(crate) const INGEST_RECEIPT_RECEIPT_VERSION: i64 = 1;

/// The `acknowledgement` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_ACKNOWLEDGEMENT: &str = "the client acknowledges — advances its cursor and releases the spool entry — only after verifying the authority chain, the receipt signature, and every identity field against the frozen spool entry (plan Section 7.8; CAP-006): tenant, request, occurrence, attestation, blob digest, and each server-derived object key re-derived from them (VAL-002-style cross-field checks, not schema syntax)";

/// The `canonicalization` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_CANONICALIZATION: &str = "rfc8785";

/// The `floats` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_FLOATS: bool = false;

/// The `mediaType` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.receipt+json;version=1";

/// The `noReceiptCases` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_NO_RECEIPT_CASES: &str = "any blob-only or blob-plus-occurrence partial commit returns HTTP 503 with an archivist.error/v1 body and no receipt (plan Section 7.8; RCPT-005) — the next identical attempt repairs the same occurrence and attestation; quarantined poison input (plan Section 7.8 error matrix) reports through the error body only and never produces a receipt";

/// The `reservedFieldsNote` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_RESERVED_FIELDS_NOTE: &str = "none: this record is the sanctioned home of per-attempt authorization and server commit material, so unlike the envelope, occurrence manifest, and upload attestation it rejects no names";

/// The `retryConvergence` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_RETRY_CONVERGENCE: &str = "a retry of the same frozen request after a successful commit receives a fresh receipt whose identity fields are identical and whose per-object outcomes are `already_present` or `replaced_equivalent` — deterministic identities make the retry converge (STO-004), the outcomes keep the report honest (RCPT-003, RCPT-004)";

/// The `signature` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_SIGNATURE: &str = "receipt-v1 (schemas/v1/ingest-identifiers.json): Ed25519 over the RFC 8785 canonicalization of this object with the `signature` member removed. The embedded certificate, including its own authority signature, is inside the covered bytes, so certificate substitution fails the receipt signature before the authority chain is even consulted.";

/// The `unknownFields` metadata of `schemas/v1/ingest-receipt.json`.
pub(crate) const INGEST_RECEIPT_META_UNKNOWN_FIELDS: &str = "retain-ignore";

/// Reserved per-attempt, server, or foreign names of
/// `schemas/v1/ingest-receipt.json` (x-archivist.reservedFields), in
/// schema order: names the record rejects outright, so retries
/// cannot fork identity on them.
pub(crate) const INGEST_RECEIPT_RESERVED_FIELDS: [&str; 0] = [];

/// Every top-level member name `schemas/v1/ingest-receipt.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const INGEST_RECEIPT_FIELD_NAMES: [&str; 19] = [
    "attestation_id",
    "attestation_object_key",
    "attestation_outcome",
    "authorization_epoch",
    "authorization_key_id",
    "blob_digest",
    "blob_object_key",
    "blob_outcome",
    "certificate",
    "commit_time",
    "occurrence_id",
    "occurrence_object_key",
    "occurrence_outcome",
    "receipt_key_id",
    "receipt_version",
    "request_id",
    "signature",
    "signature_algorithm",
    "tenant_id",
];

/// The canonical schema URN of `schemas/v1/ingest-request.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_INGEST_REQUEST: &str = "urn:agent-archivist:schema:v1:ingest-request";

/// Pinned const of `http_method` in `schemas/v1/ingest-request.json`;
/// an unknown value fails closed on the wire.
pub(crate) const INGEST_REQUEST_HTTP_METHOD: &str = "POST";

/// Pinned const of `route` in `schemas/v1/ingest-request.json`;
/// an unknown value fails closed on the wire.
pub(crate) const INGEST_REQUEST_ROUTE: &str = "/v1/ingest";

/// The `authorizationWindowSeconds` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_AUTHORIZATION_WINDOW_SECONDS: usize = 300;

/// The `clockSkewAllowanceSeconds` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_CLOCK_SKEW_ALLOWANCE_SECONDS: usize = 300;

/// The `floats` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_FLOATS: bool = false;

/// The `method` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_METHOD: &str = "POST";

/// The `partOneMediaType` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_PART_ONE_MEDIA_TYPE: &str = "application/vnd.agent-archivist.envelope+json;version=1";

/// The `preauthorization` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_PREAUTHORIZATION: &str = "the server MAY pre-authorize uploader_key_id before the body arrives, but commits nothing until the complete signature and payload verify (plan Section 7.2); stale-epoch or window-expired proofs are rejected while an identical authorized retry stays logically idempotent (ID-006, ID-007)";

/// The `route` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_ROUTE: &str = "/v1/ingest";

/// The `signingConstruction` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_SIGNING_CONSTRUCTION: &str = "ingest-attempt-v1 domain label over zero-delimited, length-prefixed fields in the pinned covered order (schemas/v1/ingest-identifiers.json); golden vectors arrive with the language-neutral conformance corpus";

/// The `wholeRequestMediaType` metadata of `schemas/v1/ingest-request.json`.
pub(crate) const INGEST_REQUEST_META_WHOLE_REQUEST_MEDIA_TYPE: &str = "multipart/related";

/// Every top-level member name `schemas/v1/ingest-request.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const INGEST_REQUEST_FIELD_NAMES: [&str; 12] = [
    "authorization_epoch",
    "authorization_timestamp",
    "content_type",
    "envelope_digest",
    "http_method",
    "payload_canonical_digest",
    "payload_transport_digest",
    "request_content_digest",
    "route",
    "signature",
    "signature_algorithm",
    "uploader_key_id",
];

/// The canonical schema URN of `schemas/v1/occurrence-manifest.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_OCCURRENCE_MANIFEST: &str = "urn:agent-archivist:schema:v1:occurrence-manifest";

/// Pinned const of `occurrence_version` in `schemas/v1/occurrence-manifest.json`;
/// an unknown value fails closed on the wire.
pub(crate) const OCCURRENCE_MANIFEST_OCCURRENCE_VERSION: i64 = 1;

/// The `canonicalization` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_CANONICALIZATION: &str = "rfc8785";

/// The `deduplication` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_DEDUPLICATION: &str = "STO-002: one manifest per distinct occurrence_id, including when several occurrences reference one blob";

/// The `floats` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_FLOATS: bool = false;

/// The `identityStability` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_IDENTITY_STABILITY: &str = "STO-010: canonical fields MUST NOT vary by uploader or upload attempt — every field below is source-stable by construction, being an identity-hash input or a deterministic derivation of identity-hash inputs";

/// The `mediaType` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.occurrence+json;version=1";

/// The `objectKey` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_OBJECT_KEY: &str = "schemas/v1/common.json#/$defs/occurrence-object-key";

/// The `unknownFields` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_UNKNOWN_FIELDS: &str = "retain-ignore";

/// The `writeOrder` metadata of `schemas/v1/occurrence-manifest.json`.
pub(crate) const OCCURRENCE_MANIFEST_META_WRITE_ORDER: &str = "after the blob is durable, before any upload attestation (plan Section 7.5; RCPT-001 ordering)";

/// Reserved per-attempt, server, or foreign names of
/// `schemas/v1/occurrence-manifest.json` (x-archivist.reservedFields), in
/// schema order: names the record rejects outright, so retries
/// cannot fork identity on them.
pub(crate) const OCCURRENCE_MANIFEST_RESERVED_FIELDS: [&str; 16] = [
    "attestation_id",
    "authorization_epoch",
    "authorization_key_id",
    "authorization_timestamp",
    "capture_time",
    "commit_time",
    "compressed_size",
    "correlation_id",
    "delegation",
    "envelope_creation_time",
    "incoming_checksum",
    "incoming_checksum_algorithm",
    "request_id",
    "signature",
    "transport_encoding",
    "uploader_client_id",
];

/// Every top-level member name `schemas/v1/occurrence-manifest.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const OCCURRENCE_MANIFEST_FIELD_NAMES: [&str; 20] = [
    "adapter_artifact_id",
    "adapter_id",
    "adapter_projection_version",
    "artifact_hash",
    "artifact_kind",
    "blob_digest",
    "generation",
    "harness",
    "id_source",
    "occurrence_id",
    "occurrence_version",
    "origin_client_id",
    "range_end",
    "range_kind",
    "range_start",
    "session_hash",
    "source_time",
    "storage_profile",
    "tenant_id",
    "upstream_session_id",
];

/// The canonical schema URN of `schemas/v1/upload-attestation.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_UPLOAD_ATTESTATION: &str = "urn:agent-archivist:schema:v1:upload-attestation";

/// Pinned const of `attestation_version` in `schemas/v1/upload-attestation.json`;
/// an unknown value fails closed on the wire.
pub(crate) const UPLOAD_ATTESTATION_ATTESTATION_VERSION: i64 = 1;

/// The `canonicalization` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_CANONICALIZATION: &str = "rfc8785";

/// The `consistency` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_CONSISTENCY: &str = "delegation=direct requires uploader_client_id == origin_client_id; delegation=relay requires them to differ and the uploader to hold verified origin/uploader delegation (plan Section 5, server flow step; ID-005). This cross-field relation and agreement with the bound occurrence manifest are server-side validation (VAL-002), not schema syntax.";

/// The `floats` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_FLOATS: bool = false;

/// The `identityStability` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_IDENTITY_STABILITY: &str = "STO-013: retries of one frozen request converge to one attestation; a distinct authorized uploader or request remains separately auditable — never an overwrite of the occurrence or of another attestation";

/// The `mediaType` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.attestation+json;version=1";

/// The `objectKey` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_OBJECT_KEY: &str = "schemas/v1/common.json#/$defs/attestation-object-key";

/// The `unknownFields` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_UNKNOWN_FIELDS: &str = "retain-ignore";

/// The `writeOrder` metadata of `schemas/v1/upload-attestation.json`.
pub(crate) const UPLOAD_ATTESTATION_META_WRITE_ORDER: &str = "after the bound occurrence manifest is durable (plan Section 7.5; RCPT-001: a request succeeds only once blob, occurrence, and attestation are all durable)";

/// Reserved per-attempt, server, or foreign names of
/// `schemas/v1/upload-attestation.json` (x-archivist.reservedFields), in
/// schema order: names the record rejects outright, so retries
/// cannot fork identity on them.
pub(crate) const UPLOAD_ATTESTATION_RESERVED_FIELDS: [&str; 6] = [
    "authorization_epoch",
    "authorization_key_id",
    "authorization_timestamp",
    "commit_time",
    "correlation_id",
    "signature",
];

/// Every top-level member name `schemas/v1/upload-attestation.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const UPLOAD_ATTESTATION_FIELD_NAMES: [&str; 10] = [
    "attestation_id",
    "attestation_version",
    "capture_time",
    "delegation",
    "envelope_creation_time",
    "occurrence_id",
    "origin_client_id",
    "request_id",
    "tenant_id",
    "uploader_client_id",
];

/// Closed enum tokens of `delegation-relation` in `schemas/v1/upload-attestation.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_UPLOAD_ATTESTATION_DELEGATION_RELATION_TOKENS: &[&str] = &[
    "direct",
    "relay",
];

/// Bearing of the `delegation-relation` enum in `schemas/v1/upload-attestation.json`.
pub(crate) const ENUM_UPLOAD_ATTESTATION_DELEGATION_RELATION_BEARING: &str = "security";

/// Whether the `delegation-relation` enum in `schemas/v1/upload-attestation.json` is declared fail-closed.
pub(crate) const ENUM_UPLOAD_ATTESTATION_DELEGATION_RELATION_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/usage-summary.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_USAGE_SUMMARY: &str = "urn:agent-archivist:schema:v1:usage-summary";

/// Pinned const of `usage_summary_version` in `schemas/v1/usage-summary.json`;
/// an unknown value fails closed on the wire.
pub(crate) const USAGE_SUMMARY_USAGE_SUMMARY_VERSION: i64 = 1;

/// The `canonicalization` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_CANONICALIZATION: &str = "rfc8785";

/// The `closedShape` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_CLOSED_SHAPE: bool = true;

/// The `contentBoundary` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_CONTENT_BOUNDARY: &str = "the record is numeric and referential only. The member grammars make the content-freeness claim mechanical rather than aspirational: model_id, service_tier, adapter_id, and the enum members are bounded tokens that cannot carry a sentence; the token counts are integers; and the reserved list rejects by name every carrier of transcript text, prompt, tool argument, or monetary amount. The negative matrix in tools/usagegen.py --verify injects each reserved name into a valid record and proves the schema rejects it";

/// The `denominatorBoundary` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_DENOMINATOR_BOUNDARY: &str = "the record carries two usage denominators as two separate members, never one. `harness_usage` (required) is the harness-reported denominator: semantic and complete for every supported adapter, read from the raw bytes by the pinned adapter projection. `provider_usage` (reserved: defined here, optional in v1) is the Phase 9 provider-observed denominator: exact, and covering only the routed or hooked traffic the exact-inference boundary captured — its counters are the `usage` artifact kind's own bounded intersection (schemas/v1/inference-artifact.json), reconciled to the occurrence by the Phase 9 join that has not shipped; the member's shape is pinned now so no interim encoding can blur the boundary, and no v1 row is required to carry it until that producer exists. Each denominator holds its own coverage state inside its own object — `measured` or `unknown` — so neither can be collapsed into the other and no single member can express both; the grand-total and artifact-counter names are reserved below, so nothing at the root can sum the two into one number. The member's absence is itself a state, distinct from its `unknown`: absent means the occurrence is outside exact-capture coverage entirely (traffic that was neither routed nor hooked), while `unknown` means covered traffic whose exact count still does not exist. A row may carry both, either, or neither (plan Phase 10, token accounting)";

/// The `derivationStability` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_DERIVATION_STABILITY: &str = "every member is a deterministic function of the cited occurrence's raw bytes, pipeline_id + pipeline_version, and the adapter projection version that read the usage region. No wall-clock, producer, run, assessment, approval, policy, or price input exists to make two derivations of the same inputs diverge — which is what makes the Phase 10 byte-identical-rebuild exit gate possible, and why every wall-clock, producer, and run-identity name is in the reserved list below";

/// The `floats` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_FLOATS: bool = false;

/// The `mediaType` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_MEDIA_TYPE: &str = "application/vnd.agent-archivist.usage-summary+json;version=1";

/// The `objectKey` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_OBJECT_KEY: &str = "schemas/v1/common.json#/$defs/usage-summary-object-key";

/// The `unknownFields` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_UNKNOWN_FIELDS: &str = "reject";

/// The `writeClass` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_WRITE_CLASS: &str = "immutable, content-addressed by usage_summary_digest: one object per digest, a rebuild writes identical bytes, and nothing can displace it. The derived prefix never touches a raw namespace (plan Section 7.1 derived-pipeline axis: rebuildable; never overwrites raw data). Retention is inherited from the cited occurrence: the disabled-by-default mark-and-sweep (plan Section 7.10) removes the usage row in the same pass that removes the occurrence — the row exists only while the raw prefix it was rebuilt from does";

/// The `writeOrder` metadata of `schemas/v1/usage-summary.json`.
pub(crate) const USAGE_SUMMARY_META_WRITE_ORDER: &str = "after the cited occurrence and its upload attestation are durable in the raw prefix; before any query-time cost computation, which happens outside the archive and never writes back";

/// Reserved per-attempt, server, or foreign names of
/// `schemas/v1/usage-summary.json` (x-archivist.reservedFields), in
/// schema order: names the record rejects outright, so retries
/// cannot fork identity on them.
pub(crate) const USAGE_SUMMARY_RESERVED_FIELDS: [&str; 89] = [
    "aggregate_tokens",
    "amount",
    "approval",
    "approved_by",
    "assessment",
    "assessment_digest",
    "assessment_id",
    "billing",
    "blob_key",
    "body",
    "built_at",
    "cents",
    "charge",
    "classification",
    "combined_tokens",
    "completion",
    "context",
    "cost",
    "cost_usd",
    "costs",
    "created_at",
    "currency",
    "dollar",
    "dollars",
    "expenditure",
    "fee",
    "generated_at",
    "ingested_at",
    "labels",
    "location",
    "mapping",
    "message",
    "messages",
    "object_key",
    "path",
    "plaintext",
    "policy",
    "policy_version",
    "price",
    "price_table",
    "prices",
    "pricing",
    "produced_at",
    "producer",
    "prompt",
    "prompts",
    "pseudonym_map",
    "pseudonym_salt",
    "rate",
    "rate_table",
    "rates",
    "raw_object_key",
    "rebuilt_id",
    "recorded_at",
    "records",
    "redacted_content",
    "redaction_map",
    "removed_content",
    "response",
    "reverse_map",
    "risk_assessment",
    "run_id",
    "salt",
    "severity",
    "source_content",
    "source_path",
    "spend",
    "spent",
    "summed_tokens",
    "text",
    "tool_argument",
    "tool_call",
    "tool_input",
    "tool_output",
    "tool_result",
    "total_cost",
    "total_token_count",
    "total_tokens",
    "transcript",
    "trust_decision",
    "unit_price",
    "url",
    "usd",
    "use_approval",
    "usage_cost",
    "usage_input_tokens",
    "usage_output_tokens",
    "usage_total_tokens",
    "verdict",
];

/// Every top-level member name `schemas/v1/usage-summary.json` defines,
/// alphabetical: the known-name set against which unknown members
/// are recognized.
pub(crate) const USAGE_SUMMARY_FIELD_NAMES: [&str; 12] = [
    "adapter_id",
    "adapter_projection_version",
    "harness_usage",
    "model_id",
    "occurrence_id",
    "pipeline_id",
    "pipeline_version",
    "provider_usage",
    "service_tier",
    "tenant_id",
    "usage_summary_digest",
    "usage_summary_version",
];

/// Closed enum tokens of `harness-usage-unknown/reason` in `schemas/v1/usage-summary.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_USAGE_SUMMARY_HARNESS_USAGE_UNKNOWN_REASON_TOKENS: &[&str] = &[
    "absent",
    "malformed",
    "unsupported",
];

/// Bearing of the `harness-usage-unknown/reason` enum in `schemas/v1/usage-summary.json`.
pub(crate) const ENUM_USAGE_SUMMARY_HARNESS_USAGE_UNKNOWN_REASON_BEARING: &str = "security";

/// Whether the `harness-usage-unknown/reason` enum in `schemas/v1/usage-summary.json` is declared fail-closed.
pub(crate) const ENUM_USAGE_SUMMARY_HARNESS_USAGE_UNKNOWN_REASON_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `pipeline_id` in `schemas/v1/usage-summary.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_USAGE_SUMMARY_PIPELINE_ID_TOKENS: &[&str] = &["usage"];

/// Bearing of the `pipeline_id` enum in `schemas/v1/usage-summary.json`.
pub(crate) const ENUM_USAGE_SUMMARY_PIPELINE_ID_BEARING: &str = "security";

/// Whether the `pipeline_id` enum in `schemas/v1/usage-summary.json` is declared fail-closed.
pub(crate) const ENUM_USAGE_SUMMARY_PIPELINE_ID_FAIL_CLOSED: bool = true;

/// Closed enum tokens of `provider-usage-unknown/reason` in `schemas/v1/usage-summary.json`.
/// Bearing `security`; fail-closed: true.
/// Schema order is wire order; unknown values fail closed on the
/// wire (plan Section 7.1).
pub(crate) const ENUM_USAGE_SUMMARY_PROVIDER_USAGE_UNKNOWN_REASON_TOKENS: &[&str] = &[
    "unreconciled",
    "malformed",
];

/// Bearing of the `provider-usage-unknown/reason` enum in `schemas/v1/usage-summary.json`.
pub(crate) const ENUM_USAGE_SUMMARY_PROVIDER_USAGE_UNKNOWN_REASON_BEARING: &str = "security";

/// Whether the `provider-usage-unknown/reason` enum in `schemas/v1/usage-summary.json` is declared fail-closed.
pub(crate) const ENUM_USAGE_SUMMARY_PROVIDER_USAGE_UNKNOWN_REASON_FAIL_CLOSED: bool = true;

/// The canonical schema URN of `schemas/v1/use-approval.json`, read from
/// the schema's own `$id`.
pub(crate) const SCHEMA_URN_USE_APPROVAL: &str = "urn:agent-archivist:schema:v1:use-approval";
