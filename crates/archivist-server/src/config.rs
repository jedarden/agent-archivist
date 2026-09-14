// SPDX-License-Identifier: Apache-2.0

//! The validated server configuration: one typed value per registered
//! `server.*` key (`tools/config-keys.toml`, "Ingestion server" section),
//! assembled through a fail-closed builder.
//!
//! Every field here is a registry key owned by this crate; the registry is
//! the deployment surface and this module is the typed shape an assembled
//! configuration must validate into. The split of labor mirrors
//! `archivist-storage-s3`'s configuration surface: a tier loader (the
//! composition root's job) resolves strings per key; [`ServerConfigBuilder`]
//! carries them; [`ServerConfigBuilder::build`] is the single gate that
//! applies the registry defaults, range-checks every value against its
//! suffix's bounds (CFG-015), and rejects cross-field contradictions. There
//! is no half-valid configuration and no silent clamp: a value outside its
//! bounds is a construction failure, never a correction (CFG-013).
//!
//! The bounds and defaults quoted below are the registry's, pinned here as
//! constants and held to the registry by the unit tests that construct every
//! boundary. The listen address is the one required key (CFG-020): it has no
//! default because a replica's socket is a deployment decision, and building
//! without one fails before anything binds.
//!
//! Content freedom holds by construction: errors carry a closed kind and a
//! static detail naming the setting class, and the type cannot hold the
//! offending text (CFG-013, CFG-027) — the listen address is parsed into a
//! [`SocketAddr`] at the gate, so no raw setting string survives validation.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

/// Registry bound for every `_bytes` key: 1 .. 2^48 (CFG-015).
pub const BYTE_MAX: u64 = 1 << 48;

/// Registry bound for every `_seconds` key: 1 .. 31,536,000 (CFG-015) —
/// one second of granularity up to a single year.
pub const SECONDS_MAX: u64 = 31_536_000;

/// Registry bound for every `_count` key: 0 .. 2^31 − 1 (CFG-015).
pub const COUNT_MAX: u32 = i32::MAX as u32;

/// Registry bound for every `_ratio` key: 1 .. 10,000 (CFG-015).
pub const RATIO_MAX: u32 = 10_000;

/// Registry default of `server.request_deadline_seconds` (plan Phase 4:
/// the 15-minute request deadline).
pub const DEFAULT_REQUEST_DEADLINE_SECONDS: u64 = 900;

/// Registry default of `server.envelope_max_bytes` (plan Phase 4: 64 KiB
/// canonical envelope).
pub const DEFAULT_ENVELOPE_MAX_BYTES: u64 = 65_536;

/// Registry default of `server.record_max_bytes` (plan Phase 4: 256 MiB
/// uncompressed record).
pub const DEFAULT_RECORD_MAX_BYTES: u64 = 268_435_456;

/// Registry default of `server.max_expansion_ratio` (plan Phase 4: 100:1
/// maximum decompression expansion).
pub const DEFAULT_MAX_EXPANSION_RATIO: u32 = 100;

/// Registry default of `server.multipart_part_bytes` (plan Phase 4: 8 MiB
/// multipart parts).
pub const DEFAULT_MULTIPART_PART_BYTES: u64 = 8_388_608;

/// Registry default of `server.max_inflight_upload_count` (plan Phase 4:
/// 16 in-flight uploads per process).
pub const DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT: u32 = 16;

/// Registry default of `server.max_inflight_per_client_count` (plan
/// Phase 4: at most 4 of the process total for one client).
pub const DEFAULT_MAX_INFLIGHT_PER_CLIENT_COUNT: u32 = 4;

/// Registry default of `server.rate_per_minute_count` (plan Phase 4: 60
/// new requests per minute per client).
pub const DEFAULT_RATE_PER_MINUTE_COUNT: u32 = 60;

/// Registry default of `server.rate_burst_count` (plan Phase 4: burst 8).
pub const DEFAULT_RATE_BURST_COUNT: u32 = 8;

/// Registry default of `server.shutdown_drain_seconds` (plan Phase 4:
/// drain for 30 seconds before aborting unfinished multipart uploads).
pub const DEFAULT_SHUTDOWN_DRAIN_SECONDS: u64 = 30;

/// Why a configuration failed validation: a closed class of failure
/// carrying the decision the operator must make next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServerConfigErrorKind {
    /// The one required setting never arrived in any tier.
    MissingSetting,
    /// A setting arrived but is outside its registry bounds or closed
    /// grammar.
    MalformedSetting,
    /// Two settings are each within bounds but contradict each other, so
    /// at least one of the two could never take effect.
    ContradictorySetting,
}

impl ServerConfigErrorKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::MissingSetting,
            Self::MalformedSetting,
            Self::ContradictorySetting,
        ]
    }

    /// The content-free default detail shipped with this kind. Callers
    /// that have nothing more specific to say use these verbatim; the
    /// literals are pinned by a unit test to stay inside the project's
    /// safe-message grammar.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::MissingSetting => "required setting is absent from every tier",
            Self::MalformedSetting => "setting is outside its closed grammar",
            Self::ContradictorySetting => "two settings contradict each other",
        }
    }
}

impl fmt::Display for ServerConfigErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::MissingSetting => "missing-setting",
            Self::MalformedSetting => "malformed-setting",
            Self::ContradictorySetting => "contradictory-setting",
        };
        f.write_str(text)
    }
}

/// Which setting an error is about. The per-setting detail literals live
/// here so every operator-facing sentence is a static, pinned string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Setting {
    ListenAddress,
    RequestDeadline,
    EnvelopeMax,
    RecordMax,
    ExpansionRatio,
    MultipartPart,
    InflightTotal,
    InflightPerClient,
    RatePerMinute,
    RateBurst,
    ShutdownDrain,
}

impl Setting {
    /// The detail for a required-but-absent setting.
    const fn missing_detail(self) -> &'static str {
        match self {
            Self::ListenAddress => "listen address is required",
            _ => "setting is required",
        }
    }

    /// The detail for a present-but-malformed setting.
    const fn malformed_detail(self) -> &'static str {
        match self {
            Self::ListenAddress => "listen address is outside the socket-address grammar",
            Self::RequestDeadline => "request deadline is outside the seconds bounds",
            Self::EnvelopeMax => "envelope maximum is outside the byte bounds",
            Self::RecordMax => "record maximum is outside the byte bounds",
            Self::ExpansionRatio => "expansion ratio is outside the ratio bounds",
            Self::MultipartPart => "multipart part size is outside the byte bounds",
            Self::InflightTotal => "in-flight total is outside the count bounds",
            Self::InflightPerClient => "per-client in-flight cap is outside the count bounds",
            Self::RatePerMinute => "rate refill is outside the count bounds",
            Self::RateBurst => "rate burst is outside the count bounds",
            Self::ShutdownDrain => "shutdown drain is outside the seconds bounds",
        }
    }

    /// The detail for a contradiction between two settings.
    const fn contradictory_detail(self, other: Self) -> &'static str {
        match (self, other) {
            (Self::InflightPerClient, Self::InflightTotal)
            | (Self::InflightTotal, Self::InflightPerClient) => {
                "the per-client in-flight cap exceeds the process total"
            }
            (Self::RateBurst, Self::RatePerMinute) | (Self::RatePerMinute, Self::RateBurst) => {
                "a zero burst depth admits no request at any refill rate"
            }
            _ => "two settings contradict each other",
        }
    }
}

/// Why a configuration failed validation: a closed kind plus one
/// content-safe detail naming the setting class, never the offending
/// value.
///
/// The detail is a static literal by construction — the type cannot carry
/// runtime text such as a mistyped address — so a configuration error can
/// never echo operator input (CFG-013, CFG-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerConfigError {
    kind: ServerConfigErrorKind,
    detail: &'static str,
}

impl ServerConfigError {
    /// Build an error carrying the kind's default detail.
    #[must_use]
    pub const fn of_kind(kind: ServerConfigErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
        }
    }

    /// Build an error from a kind and a static, content-safe detail.
    #[must_use]
    pub const fn new(kind: ServerConfigErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> ServerConfigErrorKind {
        self.kind
    }

    /// The content-free detail text.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for ServerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server config {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for ServerConfigError {}

fn missing(setting: Setting) -> ServerConfigError {
    ServerConfigError::new(
        ServerConfigErrorKind::MissingSetting,
        setting.missing_detail(),
    )
}

fn malformed(setting: Setting) -> ServerConfigError {
    ServerConfigError::new(
        ServerConfigErrorKind::MalformedSetting,
        setting.malformed_detail(),
    )
}

fn contradictory(first: Setting, second: Setting) -> ServerConfigError {
    ServerConfigError::new(
        ServerConfigErrorKind::ContradictorySetting,
        first.contradictory_detail(second),
    )
}

/// The validated configuration of one ingestion replica.
///
/// Construct only through [`ServerConfig::builder`]; every field is
/// immutable after the gate. Accessors return the validated values, and
/// the duration accessors hand back [`Duration`] so callers cannot
/// re-derive seconds wrongly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    listen_address: SocketAddr,
    request_deadline: Duration,
    envelope_max_bytes: u64,
    record_max_bytes: u64,
    max_expansion_ratio: u32,
    multipart_part_bytes: u64,
    max_inflight_upload_count: u32,
    max_inflight_per_client_count: u32,
    rate_per_minute_count: u32,
    rate_burst_count: u32,
    shutdown_drain: Duration,
}

impl ServerConfig {
    /// Begin assembling a configuration from registry tier values.
    #[must_use]
    pub fn builder() -> ServerConfigBuilder {
        ServerConfigBuilder::default()
    }

    /// The socket address the replica listens on
    /// (`server.listen_address`).
    #[must_use]
    pub const fn listen_address(&self) -> SocketAddr {
        self.listen_address
    }

    /// The per-request deadline (`server.request_deadline_seconds`);
    /// past it a request is rejected in the throttle class (plan
    /// Section 7.6).
    #[must_use]
    pub const fn request_deadline(&self) -> Duration {
        self.request_deadline
    }

    /// The canonical-envelope size cap (`server.envelope_max_bytes`).
    #[must_use]
    pub const fn envelope_max_bytes(&self) -> u64 {
        self.envelope_max_bytes
    }

    /// The uncompressed-record size cap (`server.record_max_bytes`).
    #[must_use]
    pub const fn record_max_bytes(&self) -> u64 {
        self.record_max_bytes
    }

    /// The maximum decompression expansion ratio, as integer N of N:1
    /// (`server.max_expansion_ratio`).
    #[must_use]
    pub const fn max_expansion_ratio(&self) -> u32 {
        self.max_expansion_ratio
    }

    /// The multipart part size for streamed commits
    /// (`server.multipart_part_bytes`).
    #[must_use]
    pub const fn multipart_part_bytes(&self) -> u64 {
        self.multipart_part_bytes
    }

    /// The process-wide in-flight upload cap
    /// (`server.max_inflight_upload_count`).
    #[must_use]
    pub const fn max_inflight_upload_count(&self) -> u32 {
        self.max_inflight_upload_count
    }

    /// The per-client share of the in-flight cap
    /// (`server.max_inflight_per_client_count`).
    #[must_use]
    pub const fn max_inflight_per_client_count(&self) -> u32 {
        self.max_inflight_per_client_count
    }

    /// The per-client token-bucket refill, new requests per minute
    /// (`server.rate_per_minute_count`); a resource guard, not a quota.
    #[must_use]
    pub const fn rate_per_minute_count(&self) -> u32 {
        self.rate_per_minute_count
    }

    /// The per-client token-bucket burst depth
    /// (`server.rate_burst_count`).
    #[must_use]
    pub const fn rate_burst_count(&self) -> u32 {
        self.rate_burst_count
    }

    /// The graceful-shutdown drain window
    /// (`server.shutdown_drain_seconds`).
    #[must_use]
    pub const fn shutdown_drain(&self) -> Duration {
        self.shutdown_drain
    }
}

/// The unvalidated configuration under assembly: every registry-backed
/// setting enters as its tier string or integer, exactly as a loader
/// would carry it, and [`ServerConfigBuilder::build`] is the single
/// fail-closed gate.
///
/// Absent optional settings resolve to their registry defaults inside
/// `build` — never before, so a caller cannot observe a default as if it
/// had been configured (CFG-019: defaults live in the registry).
#[derive(Clone, Debug, Default)]
pub struct ServerConfigBuilder {
    listen_address: Option<String>,
    request_deadline_seconds: Option<u64>,
    envelope_max_bytes: Option<u64>,
    record_max_bytes: Option<u64>,
    max_expansion_ratio: Option<u32>,
    multipart_part_bytes: Option<u64>,
    max_inflight_upload_count: Option<u32>,
    max_inflight_per_client_count: Option<u32>,
    rate_per_minute_count: Option<u32>,
    rate_burst_count: Option<u32>,
    shutdown_drain_seconds: Option<u64>,
}

impl ServerConfigBuilder {
    /// Set the socket address to listen on (`server.listen_address`).
    /// Required: `build` refuses to produce a configuration without one.
    #[must_use]
    pub fn listen_address(mut self, value: impl Into<String>) -> Self {
        self.listen_address = Some(value.into());
        self
    }

    /// Set the per-request deadline in seconds
    /// (`server.request_deadline_seconds`). Defaults to the registry's
    /// 900.
    #[must_use]
    pub fn request_deadline_seconds(mut self, value: u64) -> Self {
        self.request_deadline_seconds = Some(value);
        self
    }

    /// Set the canonical-envelope size cap in bytes
    /// (`server.envelope_max_bytes`). Defaults to the registry's 64 KiB.
    #[must_use]
    pub fn envelope_max_bytes(mut self, value: u64) -> Self {
        self.envelope_max_bytes = Some(value);
        self
    }

    /// Set the uncompressed-record size cap in bytes
    /// (`server.record_max_bytes`). Defaults to the registry's 256 MiB.
    #[must_use]
    pub fn record_max_bytes(mut self, value: u64) -> Self {
        self.record_max_bytes = Some(value);
        self
    }

    /// Set the maximum decompression expansion ratio as integer N of N:1
    /// (`server.max_expansion_ratio`). Defaults to the registry's 100.
    #[must_use]
    pub fn max_expansion_ratio(mut self, value: u32) -> Self {
        self.max_expansion_ratio = Some(value);
        self
    }

    /// Set the multipart part size in bytes
    /// (`server.multipart_part_bytes`). Defaults to the registry's 8 MiB.
    #[must_use]
    pub fn multipart_part_bytes(mut self, value: u64) -> Self {
        self.multipart_part_bytes = Some(value);
        self
    }

    /// Set the process-wide in-flight upload cap
    /// (`server.max_inflight_upload_count`). Defaults to the registry's
    /// 16.
    #[must_use]
    pub fn max_inflight_upload_count(mut self, value: u32) -> Self {
        self.max_inflight_upload_count = Some(value);
        self
    }

    /// Set the per-client in-flight share
    /// (`server.max_inflight_per_client_count`). Defaults to the
    /// registry's 4.
    #[must_use]
    pub fn max_inflight_per_client_count(mut self, value: u32) -> Self {
        self.max_inflight_per_client_count = Some(value);
        self
    }

    /// Set the per-client rate refill, new requests per minute
    /// (`server.rate_per_minute_count`). Defaults to the registry's 60.
    #[must_use]
    pub fn rate_per_minute_count(mut self, value: u32) -> Self {
        self.rate_per_minute_count = Some(value);
        self
    }

    /// Set the per-client rate burst depth
    /// (`server.rate_burst_count`). Defaults to the registry's 8.
    #[must_use]
    pub fn rate_burst_count(mut self, value: u32) -> Self {
        self.rate_burst_count = Some(value);
        self
    }

    /// Set the graceful-shutdown drain window in seconds
    /// (`server.shutdown_drain_seconds`). Defaults to the registry's 30.
    #[must_use]
    pub fn shutdown_drain_seconds(mut self, value: u64) -> Self {
        self.shutdown_drain_seconds = Some(value);
        self
    }

    /// Validate everything and build the configuration.
    ///
    /// # Errors
    /// [`ServerConfigErrorKind::MissingSetting`] when the required listen
    /// address never arrived, [`ServerConfigErrorKind::MalformedSetting`]
    /// when any value is outside its registry bounds or grammar, and
    /// [`ServerConfigErrorKind::ContradictorySetting`] when two in-bounds
    /// values cannot both take effect. The offending values are not
    /// echoed.
    pub fn build(self) -> Result<ServerConfig, ServerConfigError> {
        let listen_text = self
            .listen_address
            .as_deref()
            .ok_or(missing(Setting::ListenAddress))?;
        let listen_address: SocketAddr = listen_text
            .parse()
            .map_err(|_| malformed(Setting::ListenAddress))?;

        let request_deadline_seconds = self
            .request_deadline_seconds
            .unwrap_or(DEFAULT_REQUEST_DEADLINE_SECONDS);
        check_seconds(request_deadline_seconds, Setting::RequestDeadline)?;
        let envelope_max_bytes = self
            .envelope_max_bytes
            .unwrap_or(DEFAULT_ENVELOPE_MAX_BYTES);
        check_bytes(envelope_max_bytes, Setting::EnvelopeMax)?;
        let record_max_bytes = self.record_max_bytes.unwrap_or(DEFAULT_RECORD_MAX_BYTES);
        check_bytes(record_max_bytes, Setting::RecordMax)?;
        let max_expansion_ratio = self
            .max_expansion_ratio
            .unwrap_or(DEFAULT_MAX_EXPANSION_RATIO);
        check_ratio(max_expansion_ratio, Setting::ExpansionRatio)?;
        let multipart_part_bytes = self
            .multipart_part_bytes
            .unwrap_or(DEFAULT_MULTIPART_PART_BYTES);
        check_bytes(multipart_part_bytes, Setting::MultipartPart)?;
        let max_inflight_upload_count = self
            .max_inflight_upload_count
            .unwrap_or(DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT);
        check_count(max_inflight_upload_count, Setting::InflightTotal)?;
        let max_inflight_per_client_count = self
            .max_inflight_per_client_count
            .unwrap_or(DEFAULT_MAX_INFLIGHT_PER_CLIENT_COUNT);
        check_count(max_inflight_per_client_count, Setting::InflightPerClient)?;
        let rate_per_minute_count = self
            .rate_per_minute_count
            .unwrap_or(DEFAULT_RATE_PER_MINUTE_COUNT);
        check_count(rate_per_minute_count, Setting::RatePerMinute)?;
        let rate_burst_count = self.rate_burst_count.unwrap_or(DEFAULT_RATE_BURST_COUNT);
        check_count(rate_burst_count, Setting::RateBurst)?;
        let shutdown_drain_seconds = self
            .shutdown_drain_seconds
            .unwrap_or(DEFAULT_SHUTDOWN_DRAIN_SECONDS);
        check_seconds(shutdown_drain_seconds, Setting::ShutdownDrain)?;

        // Cross-field contradictions: each setting is in bounds, but the
        // pair cannot both take effect. The per-client cap must be
        // enforceable inside the process total, and a token bucket with
        // zero burst depth admits nothing regardless of its refill.
        if max_inflight_per_client_count > max_inflight_upload_count {
            return Err(contradictory(
                Setting::InflightPerClient,
                Setting::InflightTotal,
            ));
        }
        if rate_burst_count == 0 && rate_per_minute_count > 0 {
            return Err(contradictory(Setting::RateBurst, Setting::RatePerMinute));
        }

        Ok(ServerConfig {
            listen_address,
            request_deadline: Duration::from_secs(request_deadline_seconds),
            envelope_max_bytes,
            record_max_bytes,
            max_expansion_ratio,
            multipart_part_bytes,
            max_inflight_upload_count,
            max_inflight_per_client_count,
            rate_per_minute_count,
            rate_burst_count,
            shutdown_drain: Duration::from_secs(shutdown_drain_seconds),
        })
    }
}

fn check_seconds(value: u64, setting: Setting) -> Result<(), ServerConfigError> {
    if value == 0 || value > SECONDS_MAX {
        return Err(malformed(setting));
    }
    Ok(())
}

fn check_bytes(value: u64, setting: Setting) -> Result<(), ServerConfigError> {
    if value == 0 || value > BYTE_MAX {
        return Err(malformed(setting));
    }
    Ok(())
}

fn check_count(value: u32, setting: Setting) -> Result<(), ServerConfigError> {
    if value > COUNT_MAX {
        return Err(malformed(setting));
    }
    Ok(())
}

fn check_ratio(value: u32, setting: Setting) -> Result<(), ServerConfigError> {
    if value == 0 || value > RATIO_MAX {
        return Err(malformed(setting));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BYTE_MAX, COUNT_MAX, DEFAULT_ENVELOPE_MAX_BYTES, DEFAULT_MAX_EXPANSION_RATIO,
        DEFAULT_MAX_INFLIGHT_PER_CLIENT_COUNT, DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT,
        DEFAULT_MULTIPART_PART_BYTES, DEFAULT_RATE_BURST_COUNT, DEFAULT_RATE_PER_MINUTE_COUNT,
        DEFAULT_RECORD_MAX_BYTES, DEFAULT_REQUEST_DEADLINE_SECONDS, DEFAULT_SHUTDOWN_DRAIN_SECONDS,
        RATIO_MAX, SECONDS_MAX, ServerConfig, ServerConfigErrorKind,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    const LISTEN: &str = "127.0.0.1:8087";

    fn valid() -> ServerConfig {
        ServerConfig::builder()
            .listen_address(LISTEN)
            .build()
            .unwrap()
    }

    /// The registry defaults are quoted here verbatim; this test is the
    /// pin that keeps the constants and `tools/config-keys.toml` in
    /// agreement (CFG-021: a default change is a registry change).
    #[test]
    fn defaults_quote_the_registry() {
        assert_eq!(DEFAULT_REQUEST_DEADLINE_SECONDS, 900);
        assert_eq!(DEFAULT_ENVELOPE_MAX_BYTES, 65_536);
        assert_eq!(DEFAULT_RECORD_MAX_BYTES, 268_435_456);
        assert_eq!(DEFAULT_MAX_EXPANSION_RATIO, 100);
        assert_eq!(DEFAULT_MULTIPART_PART_BYTES, 8_388_608);
        assert_eq!(DEFAULT_MAX_INFLIGHT_UPLOAD_COUNT, 16);
        assert_eq!(DEFAULT_MAX_INFLIGHT_PER_CLIENT_COUNT, 4);
        assert_eq!(DEFAULT_RATE_PER_MINUTE_COUNT, 60);
        assert_eq!(DEFAULT_RATE_BURST_COUNT, 8);
        assert_eq!(DEFAULT_SHUTDOWN_DRAIN_SECONDS, 30);
    }

    /// The registry bounds are quoted here verbatim (CFG-015).
    #[test]
    fn bounds_quote_the_registry() {
        assert_eq!(BYTE_MAX, 1u64 << 48);
        assert_eq!(SECONDS_MAX, 31_536_000);
        assert_eq!(COUNT_MAX, 2_147_483_647);
        assert_eq!(RATIO_MAX, 10_000);
    }

    #[test]
    fn minimal_configuration_carries_the_defaults() {
        let config = valid();
        assert_eq!(
            config.listen_address(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8087))
        );
        assert_eq!(config.request_deadline(), Duration::from_mins(15));
        assert_eq!(config.envelope_max_bytes(), 65_536);
        assert_eq!(config.record_max_bytes(), 268_435_456);
        assert_eq!(config.max_expansion_ratio(), 100);
        assert_eq!(config.multipart_part_bytes(), 8_388_608);
        assert_eq!(config.max_inflight_upload_count(), 16);
        assert_eq!(config.max_inflight_per_client_count(), 4);
        assert_eq!(config.rate_per_minute_count(), 60);
        assert_eq!(config.rate_burst_count(), 8);
        assert_eq!(config.shutdown_drain(), Duration::from_secs(30));
    }

    #[test]
    fn a_complete_configuration_survives_round_trip() {
        let config = ServerConfig::builder()
            .listen_address("[2001:db8::1]:9443")
            .request_deadline_seconds(600)
            .envelope_max_bytes(131_072)
            .record_max_bytes(134_217_728)
            .max_expansion_ratio(50)
            .multipart_part_bytes(16_777_216)
            .max_inflight_upload_count(8)
            .max_inflight_per_client_count(2)
            .rate_per_minute_count(120)
            .rate_burst_count(16)
            .shutdown_drain_seconds(10)
            .build()
            .unwrap();
        assert_eq!(
            config.listen_address(),
            "[2001:db8::1]:9443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.request_deadline(), Duration::from_mins(10));
        assert_eq!(config.envelope_max_bytes(), 131_072);
        assert_eq!(config.record_max_bytes(), 134_217_728);
        assert_eq!(config.max_expansion_ratio(), 50);
        assert_eq!(config.multipart_part_bytes(), 16_777_216);
        assert_eq!(config.max_inflight_upload_count(), 8);
        assert_eq!(config.max_inflight_per_client_count(), 2);
        assert_eq!(config.rate_per_minute_count(), 120);
        assert_eq!(config.rate_burst_count(), 16);
        assert_eq!(config.shutdown_drain(), Duration::from_secs(10));
    }

    #[test]
    fn the_required_listen_address_is_required() {
        let error = ServerConfig::builder().build().unwrap_err();
        assert_eq!(error.kind(), ServerConfigErrorKind::MissingSetting);
        assert_eq!(error.detail(), "listen address is required");
        assert_eq!(
            error.to_string(),
            "server config missing-setting: listen address is required"
        );
    }

    #[test]
    fn malformed_listen_addresses_fail_closed() {
        for text in [
            "",
            "127.0.0.1",
            "localhost:8087",
            "127.0.0.1:portal",
            "127.0.0.1:99999",
            "256.0.0.1:8087",
            "127.0.0.1:8087 ",
            " 127.0.0.1:8087",
        ] {
            let error = ServerConfig::builder()
                .listen_address(text)
                .build()
                .unwrap_err();
            assert_eq!(
                error.kind(),
                ServerConfigErrorKind::MalformedSetting,
                "{text:?}"
            );
            assert_eq!(
                error.detail(),
                "listen address is outside the socket-address grammar"
            );
        }
    }

    #[test]
    fn every_seconds_bound_is_enforced() {
        for (value, ok) in [
            (0, false),
            (1, true),
            (900, true),
            (SECONDS_MAX, true),
            (SECONDS_MAX + 1, false),
        ] {
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .request_deadline_seconds(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "request_deadline_seconds={value}");
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .shutdown_drain_seconds(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "shutdown_drain_seconds={value}");
        }
    }

    #[test]
    fn every_byte_bound_is_enforced() {
        for (value, ok) in [
            (0, false),
            (1, true),
            (65_536, true),
            (BYTE_MAX, true),
            (BYTE_MAX + 1, false),
        ] {
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .envelope_max_bytes(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "envelope_max_bytes={value}");
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .record_max_bytes(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "record_max_bytes={value}");
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .multipart_part_bytes(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "multipart_part_bytes={value}");
        }
    }

    #[test]
    fn every_count_bound_is_enforced() {
        // The two in-flight settings and the two rate settings are set
        // together, so the count bound — not the cross-field contradiction
        // its dedicated tests below cover — decides each outcome.
        for (value, ok) in [
            (0, true),
            (1, true),
            (16, true),
            (COUNT_MAX, true),
            (COUNT_MAX + 1, false),
        ] {
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .max_inflight_upload_count(value)
                .max_inflight_per_client_count(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "max_inflight_upload_count={value}");
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .max_inflight_per_client_count(value)
                .max_inflight_upload_count(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "max_inflight_per_client_count={value}");
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .rate_per_minute_count(value)
                .rate_burst_count(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "rate_per_minute_count={value}");
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .rate_burst_count(value)
                .rate_per_minute_count(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "rate_burst_count={value}");
        }
    }

    #[test]
    fn every_ratio_bound_is_enforced() {
        for (value, ok) in [
            (0, false),
            (1, true),
            (100, true),
            (RATIO_MAX, true),
            (RATIO_MAX + 1, false),
        ] {
            let outcome = ServerConfig::builder()
                .listen_address(LISTEN)
                .max_expansion_ratio(value)
                .build();
            assert_eq!(outcome.is_ok(), ok, "max_expansion_ratio={value}");
        }
    }

    #[test]
    fn the_per_client_cap_must_fit_inside_the_process_total() {
        let error = ServerConfig::builder()
            .listen_address(LISTEN)
            .max_inflight_upload_count(4)
            .max_inflight_per_client_count(5)
            .build()
            .unwrap_err();
        assert_eq!(error.kind(), ServerConfigErrorKind::ContradictorySetting);
        assert_eq!(
            error.detail(),
            "the per-client in-flight cap exceeds the process total"
        );
        // Equal caps are the degenerate-but-consistent single-client case.
        assert!(
            ServerConfig::builder()
                .listen_address(LISTEN)
                .max_inflight_upload_count(4)
                .max_inflight_per_client_count(4)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn a_zero_burst_contradicts_a_nonzero_refill() {
        let error = ServerConfig::builder()
            .listen_address(LISTEN)
            .rate_burst_count(0)
            .build()
            .unwrap_err();
        assert_eq!(error.kind(), ServerConfigErrorKind::ContradictorySetting);
        assert_eq!(
            error.detail(),
            "a zero burst depth admits no request at any refill rate"
        );
        // A fully disabled guard (no refill, no burst) is consistent.
        assert!(
            ServerConfig::builder()
                .listen_address(LISTEN)
                .rate_per_minute_count(0)
                .rate_burst_count(0)
                .build()
                .is_ok()
        );
    }

    #[test]
    fn error_kinds_and_details_stay_inside_the_safe_grammar() {
        for kind in ServerConfigErrorKind::all() {
            let detail = kind.default_detail();
            assert!(!detail.is_empty());
            assert!(
                detail.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "{detail:?}"
            );
            assert!(!detail.contains('{') && !detail.contains('}'), "{detail:?}");
        }
    }

    #[test]
    fn a_rejected_setting_is_never_echoed() {
        let hostile = "127.0.0.1:8087; DROP TABLE tenants";
        let error = ServerConfig::builder()
            .listen_address(hostile)
            .build()
            .unwrap_err();
        assert_eq!(error.kind(), ServerConfigErrorKind::MalformedSetting);
        let rendered = error.to_string();
        assert!(!rendered.contains(hostile));
    }
}
