// SPDX-License-Identifier: Apache-2.0

//! The liveness probe: one bounded HTTP GET on the served process-only
//! liveness route, performed by the same binary that serves it.
//!
//! The release image's `HEALTHCHECK` (docs/notes/release-container.md
//! RC-020) invokes this module through the binary's registered `probe`
//! command: the runtime base ships neither `curl` nor `wget` and the
//! runtime stage installs no packages (RC-017), so the image's own binary
//! is the probe mechanism — a second compiled probe target would be an
//! RC-014 contract change, and fetched probe tooling is exactly what the
//! baseline forbids. The probe is deliberately not a general HTTP client:
//! it performs exactly one request to exactly the route [`crate::routes`]
//! mounts for process-only liveness, with every stage of the exchange
//! bounded, and reports a three-valued verdict — the route answered
//! `200 OK` within the bound, or it did not, or the probe target itself
//! was malformed (a composition fault, not a replica condition).
//!
//! The act is synchronous and blocking on purpose: the probe command is a
//! one-shot process the container runtime schedules, outside the replica's
//! async runtime, and a bounded blocking exchange needs no runtime of its
//! own.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// The served route the probe reads: the process-only liveness route
/// [`crate::routes`] mounts, answered from the process alone — never from
/// storage or configuration, so a probe success means "the process is
/// accepting and answering" and nothing else.
pub const LIVENESS_ROUTE: &str = "/health/live";

/// The bound on the whole probe exchange: connect, write, and read must
/// all complete within it, so a replica that never answers cannot hang the
/// probe past its own scheduling. The image's `HEALTHCHECK --timeout`
/// reserves a larger window around the command as a whole.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a probe did not confirm liveness. Content-free, like every server
/// diagnostic: the verdict distinguishes only a malformed probe target
/// from the two replica conditions, and the exit code that carries it is
/// the diagnostic, not a message about tenants, addresses, or routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeFault {
    /// The configured listen address is not a socket address, so no probe
    /// was attempted — the composition that produced it is wrong, and no
    /// retry can repair that.
    MalformedAddress,
    /// The replica did not answer within the bound: the connection was
    /// refused, timed out, or broke mid-exchange.
    Unreachable,
    /// The replica answered within the bound, but not with the liveness
    /// route's `200 OK` status line.
    Unhealthy,
}

/// Perform one bounded liveness probe against the replica listening on
/// `listen_address`.
///
/// The probe opens one connection, writes one `GET /health/live` request
/// with `Connection: close`, reads the response to EOF, and accepts only
/// an `HTTP/1.1 200` status line — the verdict the route's own handler
/// pins. Every stage is bounded by [`PROBE_TIMEOUT`].
///
/// # Errors
/// [`ProbeFault::MalformedAddress`] when the address is not a socket
/// address; [`ProbeFault::Unreachable`] when the exchange could not
/// complete within the bound; [`ProbeFault::Unhealthy`] when the replica
/// answered with anything but the liveness route's `200`.
pub fn probe_live(listen_address: &str) -> Result<(), ProbeFault> {
    probe_within(listen_address, PROBE_TIMEOUT)
}

/// [`probe_live`] over an explicit bound — the internal shape the pinned
/// constant wraps and the tests shrink so a bound-exceeded case proves
/// itself in milliseconds.
fn probe_within(listen_address: &str, bound: Duration) -> Result<(), ProbeFault> {
    let address: SocketAddr = listen_address
        .parse()
        .map_err(|_| ProbeFault::MalformedAddress)?;
    let mut stream =
        TcpStream::connect_timeout(&address, bound).map_err(|_| ProbeFault::Unreachable)?;
    stream
        .set_write_timeout(Some(bound))
        .map_err(|_| ProbeFault::Unreachable)?;
    stream
        .set_read_timeout(Some(bound))
        .map_err(|_| ProbeFault::Unreachable)?;
    let request =
        format!("GET {LIVENESS_ROUTE} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| ProbeFault::Unreachable)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|_| ProbeFault::Unreachable)?;
    let live = std::str::from_utf8(&response)
        .ok()
        .and_then(|text| text.lines().next())
        .is_some_and(|status| status.starts_with("HTTP/1.1 200 "));
    if live {
        Ok(())
    } else {
        Err(ProbeFault::Unhealthy)
    }
}

#[cfg(test)]
mod tests {
    use super::{ProbeFault, probe_within};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    /// The shrunken bound the tests use, so every failure mode proves
    /// itself well inside the suite's patience.
    const BOUND: Duration = Duration::from_millis(250);

    /// Bind an ephemeral listener whose first connection is answered with
    /// `response` and then closed; returns the address. The stream drops
    /// at the serving thread's end, so a probe's read-to-EOF terminates.
    fn canned(response: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral listener binds");
        let address = listener
            .local_addr()
            .expect("the listener names an address");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 512];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        address
    }

    /// Bind an ephemeral listener whose first connection is accepted and
    /// then held silent past any reasonable probe bound.
    fn silent() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral listener binds");
        let address = listener
            .local_addr()
            .expect("the listener names an address");
        std::thread::spawn(move || {
            if let Ok((_stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(5));
            }
        });
        address
    }

    #[test]
    fn the_liveness_routes_200_answer_confirms_the_replica() {
        let address = canned(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
             content-length: 13\r\nconnection: close\r\n\r\n{\"live\":true}",
        );
        assert_eq!(probe_within(&address.to_string(), BOUND), Ok(()));
    }

    #[test]
    fn a_non_200_answer_is_unhealthy() {
        let address = canned(
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\
             connection: close\r\n\r\n",
        );
        assert_eq!(
            probe_within(&address.to_string(), BOUND),
            Err(ProbeFault::Unhealthy)
        );
    }

    #[test]
    fn an_answer_that_is_not_http_is_unhealthy() {
        let address = canned("not an http response at all\r\n\r\n");
        assert_eq!(
            probe_within(&address.to_string(), BOUND),
            Err(ProbeFault::Unhealthy)
        );
    }

    #[test]
    fn a_silent_replica_is_unreachable_within_the_bound() {
        let address = silent();
        let started = std::time::Instant::now();
        let verdict = probe_within(&address.to_string(), BOUND);
        assert_eq!(verdict, Err(ProbeFault::Unreachable));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the bound, not the silent replica, ends the probe"
        );
    }

    #[test]
    fn a_refused_connection_is_unreachable() {
        // Bind, take the address, and drop the listener: nothing answers
        // there now, and localhost refuses the connect outright.
        let address = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral listener binds");
            listener
                .local_addr()
                .expect("the listener names an address")
        };
        assert_eq!(
            probe_within(&address.to_string(), BOUND),
            Err(ProbeFault::Unreachable)
        );
    }

    #[test]
    fn a_malformed_target_is_a_composition_fault() {
        assert_eq!(
            probe_within("not-a-socket-address", BOUND),
            Err(ProbeFault::MalformedAddress)
        );
    }
}
