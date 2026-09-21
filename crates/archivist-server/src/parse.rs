// SPDX-License-Identifier: Apache-2.0

//! Bounded request parsing for the ingestion pipeline, layered beneath the
//! envelope and signature validation it feeds.
//!
//! # Status
//!
//! The **multipart/related framing layer** is implemented:
//! [`framing`] validates the request Content-Type against the pinned
//! `multipart/related; boundary=<token>` grammar before any body byte is
//! read, then tokenizes the body into part boundaries, part headers, and
//! payload runs while buffering no more than a fixed small window — the
//! bounded-memory streaming the plan requires of every parser (plan Section
//! 7.6; VAL-008). The pipeline slices consume it when they land, replacing
//! the fail-closed ingest stub.

pub mod framing;
