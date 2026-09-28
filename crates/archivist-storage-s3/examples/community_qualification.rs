// SPDX-License-Identifier: Apache-2.0

//! The community qualification driver: the operator-side command that
//! executes the community qualification kit's complete run — probe,
//! write-path, fault-injection — against a live backend the operator
//! supplies, and emits the report line and transcript the contribution
//! attaches (`docs/notes/community-qualification-kit.md`).
//!
//! ```text
//! ARCHIVIST_QUALIFY_PROFILE=garage \
//! ARCHIVIST_QUALIFY_ENDPOINT=https://s3.example.invalid \
//! ARCHIVIST_QUALIFY_REGION=us-east-1 \
//! ARCHIVIST_QUALIFY_RAW_BUCKET=qualify-raw \
//! ARCHIVIST_QUALIFY_CONTROL_BUCKET=qualify-control \
//! ARCHIVIST_QUALIFY_ENCRYPTION=s3_sse \
//! ARCHIVIST_QUALIFY_RAW_WRITE_CREDENTIALS=env:RAW_WRITE_TOKEN \
//! ARCHIVIST_QUALIFY_CONTROL_READ_CREDENTIALS=env:CONTROL_READ_TOKEN \
//! ARCHIVIST_QUALIFY_OFFLINE_RESTORE_CREDENTIALS=env:OFFLINE_RESTORE_TOKEN \
//! ARCHIVIST_QUALIFY_READ_CAPABLE=true \
//! ARCHIVIST_QUALIFY_SUITE_REVISION=$(git rev-parse HEAD) \
//! cargo run -p archivist-storage-s3 --example community_qualification
//! ```
//!
//! Credentials enter as `env:`/`file:` references only (CFG-029): the
//! driver reads the reference strings, never the values, and the values
//! resolve inside the binding's credential store. The three roles are
//! pairwise distinct per the configuration's own identity check, and the
//! offline-restore role is required — the run's physical half rides it.
//!
//! The transcript renders only after the redaction pass finds no
//! forbidden field: no URL, no address shape, no tailnet hostname, and
//! none of the run's own configured endpoint, bucket, or reference
//! values (SP-006). A refusal prints the violation classes — never the
//! offending text — and exits 1; nothing printable is emitted on that
//! path. The transcript is the operator's to attach to the
//! contribution; it is never committed, and this example is project
//! automation the way the kit means it: it never runs a community
//! profile on its own — the operator's own env and buckets are the two
//! halves project automation cannot hold (SP-001).
//!
//! Exit codes: `0` the run executed and its transcript rendered (the
//! verdict — qualified or unqualified with its reason — is the
//! transcript's own trailing line, and an honest negative is a
//! successful run); `1` the redaction pass refused the transcript;
//! `64` configuration misuse (a missing setting or a value outside its
//! grammar — the refusal names the setting, never the value).

use std::process::ExitCode;

use archivist_protocol::vocabulary::{TenantId, Timestamp};
use archivist_storage_s3::config::{EncryptionPolicy, PathStyle, S3StorageConfig};
use archivist_storage_s3::lifecycle_audit::S3LifecycleAuditStore;
use archivist_storage_s3::probe::S3ProbeSource;
use archivist_storage_s3::qualify::{self, FIXTURE_TENANT, RunPlan, RunTranscript};
use archivist_storage_s3::raw_write::S3RawWriteStore;
use archivist_storage_s3::request::S3RequestBackend;

fn main() -> ExitCode {
    let configured = match settings() {
        Ok(settings) => settings,
        Err(refusal) => {
            eprintln!("archivist community-qualification: {refusal}");
            return ExitCode::from(64);
        }
    };
    let transcript = match execute(&configured) {
        Ok(transcript) => transcript,
        Err(refusal) => {
            eprintln!("archivist community-qualification: {refusal}");
            return ExitCode::from(64);
        }
    };
    // The redaction scan list: every configured value the transcript
    // must never carry. The render fails closed on any hit.
    let scan = configured.redaction_scan();
    match transcript.render(&scan) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            // Classes and offsets only — echoing the text would be the
            // leak the pass exists to prevent.
            for violation in &refusal.violations {
                eprintln!(
                    "transcript refused: {} at byte offset {}",
                    violation.what, violation.at
                );
            }
            ExitCode::FAILURE
        }
    }
}

/// The run's operator-supplied settings: the resolved environment, kept
/// as owned strings so the redaction scan can name every configured
/// value without printing any of them.
struct Settings {
    profile_key: String,
    suite_revision: String,
    endpoint: String,
    region: String,
    raw_bucket: String,
    control_bucket: String,
    encryption: String,
    path_style: Option<String>,
    raw_write_credentials: String,
    control_read_credentials: String,
    offline_restore_credentials: String,
    read_capable: String,
}

impl Settings {
    /// Every configured value the redaction pass scans for: the
    /// endpoint, both buckets, and the three credential reference
    /// strings. A transcript that carries any of them cannot render.
    fn redaction_scan(&self) -> Vec<String> {
        vec![
            self.endpoint.clone(),
            self.raw_bucket.clone(),
            self.control_bucket.clone(),
            self.raw_write_credentials.clone(),
            self.control_read_credentials.clone(),
            self.offline_restore_credentials.clone(),
        ]
    }

    /// The validated storage configuration. Every refusal names the
    /// setting, never the value.
    fn storage_config(&self) -> Result<S3StorageConfig, String> {
        let encryption = EncryptionPolicy::parse(&self.encryption)
            .map_err(|_| "ARCHIVIST_QUALIFY_ENCRYPTION is outside its token set".to_owned())?;
        let mut builder = S3StorageConfig::builder()
            .endpoint_url(self.endpoint.clone())
            .region(self.region.clone())
            .raw_bucket(self.raw_bucket.clone())
            .control_bucket(self.control_bucket.clone())
            .encryption(encryption)
            .raw_write_credentials(self.raw_write_credentials.clone())
            .control_read_credentials(self.control_read_credentials.clone())
            .offline_restore_credentials(self.offline_restore_credentials.clone());
        if let Some(token) = self.path_style.as_deref() {
            let path_style = PathStyle::parse(token)
                .map_err(|_| "ARCHIVIST_QUALIFY_PATH_STYLE is outside its token set".to_owned())?;
            builder = builder.path_style(path_style);
        }
        builder
            .build()
            .map_err(|error| format!("storage configuration refused: {error}"))
    }
}

/// Read the run's settings from the process environment. A missing
/// setting is named by its variable; nothing else is echoed.
fn settings() -> Result<Settings, String> {
    settings_from(|name| std::env::var(name).ok())
}

/// Parse settings from a value lookup. Keeping the lookup separate from the
/// process environment lets the executable's refusal boundary be tested
/// without mutating a process-global environment shared by other tests.
fn settings_from(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Settings, String> {
    let path_style = lookup("ARCHIVIST_QUALIFY_PATH_STYLE");
    let mut required = |name: &str| {
        lookup(name).ok_or_else(|| format!("{name} is not set — the run cannot compose"))
    };
    let read_capable = required("ARCHIVIST_QUALIFY_READ_CAPABLE")?;
    if read_capable != "true" && read_capable != "false" {
        return Err(
            "ARCHIVIST_QUALIFY_READ_CAPABLE must be true or false — the write grant's shape"
                .to_owned(),
        );
    }
    Ok(Settings {
        profile_key: required("ARCHIVIST_QUALIFY_PROFILE")?,
        suite_revision: required("ARCHIVIST_QUALIFY_SUITE_REVISION")?,
        endpoint: required("ARCHIVIST_QUALIFY_ENDPOINT")?,
        region: required("ARCHIVIST_QUALIFY_REGION")?,
        raw_bucket: required("ARCHIVIST_QUALIFY_RAW_BUCKET")?,
        control_bucket: required("ARCHIVIST_QUALIFY_CONTROL_BUCKET")?,
        encryption: required("ARCHIVIST_QUALIFY_ENCRYPTION")?,
        path_style,
        raw_write_credentials: required("ARCHIVIST_QUALIFY_RAW_WRITE_CREDENTIALS")?,
        control_read_credentials: required("ARCHIVIST_QUALIFY_CONTROL_READ_CREDENTIALS")?,
        offline_restore_credentials: required("ARCHIVIST_QUALIFY_OFFLINE_RESTORE_CREDENTIALS")?,
        read_capable,
    })
}

/// Compose the kit's three bindings over the resolved configuration and
/// execute the run on a current-thread runtime — the same runtime shape
/// the serve composition pins. The probe instrument and the raw-write
/// store share the write-shaped role's binding (two instances of one
/// authority type); the audit store rides the offline-restore identity.
fn execute(settings: &Settings) -> Result<RunTranscript, String> {
    let config = settings.storage_config()?;
    let tenant = TenantId::parse(FIXTURE_TENANT)
        .map_err(|_| "the kit's fixture tenant parses".to_owned())?;
    let profile_key = settings.profile_key.clone();
    let suite_revision = settings.suite_revision.clone();
    let read_capable = settings.read_capable == "true";

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|_| "the run could not start its runtime".to_owned())?;
    runtime.block_on(async move {
        let probe_binding =
            S3RequestBackend::probe_write(&config, &tenant).map_err(binding_refusal)?;
        let raw_binding = S3RequestBackend::raw_write(&config, &tenant).map_err(binding_refusal)?;
        let audit_binding =
            S3RequestBackend::version_audit(&config, &tenant).map_err(binding_refusal)?;
        let probe = S3ProbeSource::new(probe_binding, tenant.clone());
        let store = std::sync::Arc::new(S3RawWriteStore::new(
            config.clone(),
            tenant.clone(),
            raw_binding,
        ));
        let audit = S3LifecycleAuditStore::new(config, tenant.clone(), audit_binding)
            .map_err(|_| "the offline-restore identity is absent".to_owned())?;
        let plan = RunPlan {
            profile_key: &profile_key,
            suite_revision: &suite_revision,
            read_capable,
            observed_at: Timestamp::parse(&run_instant())
                .map_err(|_| "the run's instant parses".to_owned())?,
        };
        let report = qualify::run(&plan, &tenant, &probe, &store, &audit).await;
        Ok(RunTranscript::from_report(&report, &suite_revision))
    })
}

/// A binding composition refusal, stated without any configured value.
fn binding_refusal(_error: archivist_storage_s3::request::S3RequestError) -> String {
    "the request binding could not compose from the configuration".to_owned()
}

/// The instant this run stamps its observations with: UTC, RFC 3339, the
/// protocol timestamp grammar — computed from the epoch with integer
/// civil arithmetic so the driver carries no date-time dependency.
fn run_instant() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let day_seconds = seconds % 86_400;
    // Howard Hinnant's civil_from_days: days since 1970-03-01 shifted
    // into year/month/day.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3_600,
        (day_seconds % 3_600) / 60,
        day_seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT: &str = "https://operator.example.invalid";
    const RAW_BUCKET: &str = "raw";
    const CONTROL_BUCKET: &str = "ctl";
    const RAW_CREDENTIAL: &str = "env:RAW_CREDENTIAL";
    const CONTROL_CREDENTIAL: &str = "file:/run/control";
    const RESTORE_CREDENTIAL: &str = "env:RESTORE_CREDENTIAL";

    fn values(name: &str) -> Option<String> {
        match name {
            "ARCHIVIST_QUALIFY_PROFILE" => Some("community-fixture".to_owned()),
            "ARCHIVIST_QUALIFY_SUITE_REVISION" => Some("test-revision".to_owned()),
            "ARCHIVIST_QUALIFY_ENDPOINT" => Some(ENDPOINT.to_owned()),
            "ARCHIVIST_QUALIFY_REGION" => Some("test-region".to_owned()),
            "ARCHIVIST_QUALIFY_RAW_BUCKET" => Some(RAW_BUCKET.to_owned()),
            "ARCHIVIST_QUALIFY_CONTROL_BUCKET" => Some(CONTROL_BUCKET.to_owned()),
            "ARCHIVIST_QUALIFY_ENCRYPTION" => Some("s3_sse".to_owned()),
            "ARCHIVIST_QUALIFY_RAW_WRITE_CREDENTIALS" => Some(RAW_CREDENTIAL.to_owned()),
            "ARCHIVIST_QUALIFY_CONTROL_READ_CREDENTIALS" => Some(CONTROL_CREDENTIAL.to_owned()),
            "ARCHIVIST_QUALIFY_OFFLINE_RESTORE_CREDENTIALS" => Some(RESTORE_CREDENTIAL.to_owned()),
            "ARCHIVIST_QUALIFY_READ_CAPABLE" => Some("true".to_owned()),
            _ => None,
        }
    }

    #[test]
    fn settings_refusals_name_only_the_setting_class() {
        let missing = match settings_from(|name| {
            (name == "ARCHIVIST_QUALIFY_READ_CAPABLE").then(|| "true".to_owned())
        }) {
            Ok(_) => panic!("the incomplete environment must be refused"),
            Err(error) => error,
        };
        assert!(missing.contains("ARCHIVIST_QUALIFY_PROFILE"));
        assert!(!missing.contains(ENDPOINT));

        let invalid = match settings_from(|name| {
            if name == "ARCHIVIST_QUALIFY_READ_CAPABLE" {
                Some("maybe".to_owned())
            } else {
                Some("https://secret.example.invalid/credential".to_owned())
            }
        }) {
            Ok(_) => panic!("a non-boolean read capability must be refused"),
            Err(error) => error,
        };
        assert!(invalid.contains("ARCHIVIST_QUALIFY_READ_CAPABLE"));
        assert!(!invalid.contains("secret.example.invalid"));
    }

    #[test]
    fn valid_settings_keep_operator_values_out_of_configuration_errors_and_scan_them() {
        let settings = settings_from(values).expect("fixture environment");
        let configuration = settings.storage_config().expect("fixture settings compose");
        assert_eq!(configuration.raw_bucket(), RAW_BUCKET);

        let scan = settings.redaction_scan();
        assert!(scan.iter().any(|value| value == RAW_BUCKET));
        assert!(scan.iter().any(|value| value == CONTROL_BUCKET));
        assert!(scan.iter().any(|value| value == RAW_CREDENTIAL));
        assert!(scan.iter().any(|value| value == CONTROL_CREDENTIAL));
        assert!(scan.iter().any(|value| value == RESTORE_CREDENTIAL));
    }

    #[test]
    fn run_instant_is_a_protocol_timestamp() {
        let instant = run_instant();
        assert_eq!(instant.len(), 20);
        assert!(instant.ends_with('Z'));
        assert_eq!(instant.as_bytes()[10], b'T');
        assert_eq!(instant.as_bytes()[13], b':');
        assert_eq!(instant.as_bytes()[16], b':');
        Timestamp::parse(&instant).expect("driver instant uses the protocol grammar");
    }
}
