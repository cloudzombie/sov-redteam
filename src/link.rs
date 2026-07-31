//! **Node link** — connect to a real node, and when that fails, say exactly WHY
//! and what to type instead.
//!
//! Every live probe in this crate starts by reaching a node over JSON-RPC, and the
//! single most common way that fails has nothing to do with the chain:
//!
//!   * `:9645` was typed. That is the **P2P** port — it speaks the encrypted
//!     Noise-XX wire protocol, not JSON-RPC, so it accepts the TCP connection and
//!     then never answers. RPC is `:8645`.
//!   * The address came from a node UI that printed a **VPN / point-to-point
//!     interface** address (Tailscale, utun, a `10.x` peer address). The node is
//!     listening on `*:8645` and is perfectly healthy, but nothing can reach it on
//!     that particular address — not even the same machine.
//!   * The node binds loopback only, so `127.0.0.1:8645` works and the LAN address
//!     does not.
//!
//! A bare "node unreachable" is useless against any of those. So this module does
//! what an operator would do by hand: normalize the endpoint, probe it, and — if it
//! is silent — sweep a ranked list of CANDIDATES (the same host on the RPC port,
//! loopback, and every local IPv4 address this machine actually holds), then report
//! which one answered. The probes and the GUI both use it, so they diagnose
//! identically.

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use sov_rpc::{RpcClient, RpcClientError};

/// The SOV JSON-RPC port. What every tool in this repo wants.
pub const RPC_PORT: u16 = 8645;
/// The SOV P2P port. Speaks Noise-XX, NOT JSON-RPC — a very common mis-entry.
pub const P2P_PORT: u16 = 9645;

/// How a link attempt ended. Ordered from worst to best so the UI can colour it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkStatus {
    /// Nothing has been tried yet.
    Idle,
    /// A probe is in flight.
    Checking,
    /// The host name does not resolve.
    Unresolved,
    /// TCP refused — nothing is listening there.
    Refused,
    /// TCP connected (or hung) but no JSON-RPC answer arrived in time. The classic
    /// signature of pointing at the P2P port, or of a firewalled path.
    Silent,
    /// Something answered, but not a SOV node's JSON-RPC.
    NotSov,
    /// A SOV node answered. Live.
    Live,
}

impl LinkStatus {
    /// A short label for a status chip.
    pub fn label(self) -> &'static str {
        match self {
            LinkStatus::Idle => "NOT CHECKED",
            LinkStatus::Checking => "CHECKING",
            LinkStatus::Unresolved => "NO SUCH HOST",
            LinkStatus::Refused => "REFUSED",
            LinkStatus::Silent => "NO ANSWER",
            LinkStatus::NotSov => "NOT A SOV NODE",
            LinkStatus::Live => "LIVE",
        }
    }
    /// Whether a probe can proceed against this endpoint.
    pub fn is_live(self) -> bool {
        self == LinkStatus::Live
    }
}

/// One candidate endpoint's result during discovery.
#[derive(Clone, Debug)]
pub struct Attempt {
    pub endpoint: String,
    pub status: LinkStatus,
    /// Why this candidate was worth trying ("as typed", "RPC port", "loopback", …).
    pub why: &'static str,
    pub detail: String,
}

/// The state of the link to a node: where it is, whether it answered, what it said,
/// and — when it did not — every candidate that was tried and the fix to apply.
#[derive(Clone, Debug)]
pub struct NodeLink {
    /// The endpoint that ANSWERED, or the one that was tried and failed.
    pub endpoint: String,
    pub status: LinkStatus,
    pub chain_id: Option<String>,
    pub height: Option<u64>,
    pub mempool: Option<usize>,
    /// Round-trip time of the successful health call.
    pub latency: Option<Duration>,
    /// A plain-language diagnosis, and the fix when there is one.
    pub detail: String,
    /// Every candidate discovery tried, in order.
    pub attempts: Vec<Attempt>,
    /// True when the endpoint that worked is NOT the one the operator typed — the
    /// UI should adopt it and say so.
    pub redirected: bool,
}

impl NodeLink {
    fn down(endpoint: String, status: LinkStatus, detail: String) -> Self {
        Self {
            endpoint,
            status,
            chain_id: None,
            height: None,
            mempool: None,
            latency: None,
            detail,
            attempts: Vec::new(),
            redirected: false,
        }
    }
    /// True if the linked node names a mainnet chain id.
    pub fn is_mainnet(&self) -> bool {
        self.chain_id
            .as_deref()
            .map(|c| c.contains("mainnet"))
            .unwrap_or(false)
    }
}

/// Normalize a user-typed endpoint: strip a scheme and any path, trim whitespace,
/// and default the port to the RPC port when none is given. Bracketed IPv6 is left
/// alone. This is the same normalization the live probes use.
pub fn normalize_endpoint(target: &str) -> String {
    let t = target.trim();
    let t = t
        .strip_prefix("http://")
        .or_else(|| t.strip_prefix("https://"))
        .unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t).trim();
    if t.starts_with('[') || t.contains(':') {
        t.to_string()
    } else {
        format!("{t}:{RPC_PORT}")
    }
}

/// Split `host:port`, defaulting the port to the RPC port.
fn split(endpoint: &str) -> (String, u16) {
    match endpoint.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(RPC_PORT)),
        None => (endpoint.to_string(), RPC_PORT),
    }
}

/// Probe ONE endpoint: resolve it, open TCP with a short timeout so a black-holed
/// address fails fast, then ask the node for its chain id / height / mempool.
///
/// Every layer is separated on purpose — "unresolved", "refused", "connected but
/// silent" and "answered something that is not SOV" are four different operator
/// problems with four different fixes, and collapsing them into "unreachable" is
/// what made this hard to debug in the first place.
pub fn check_endpoint(target: &str, timeout: Duration) -> NodeLink {
    let endpoint = normalize_endpoint(target);
    let (host, port) = split(&endpoint);

    // 1. Resolve.
    let addrs: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => {
            return NodeLink::down(
                endpoint,
                LinkStatus::Unresolved,
                format!("`{host}` does not resolve ({e}) — check the host name or use an IP"),
            )
        }
    };
    if addrs.is_empty() {
        return NodeLink::down(
            endpoint,
            LinkStatus::Unresolved,
            format!("`{host}` resolved to no addresses"),
        );
    }

    // 2. TCP. Two different patiences on purpose: a black-holed VPN address must
    //    fail FAST (it will never answer, and a sweep of candidates behind it would
    //    crawl), while a node that is busy serving a miner must be given time at the
    //    RPC layer below. So the connect gets a short cap and the RPC call gets the
    //    full budget.
    let connect_timeout = timeout.min(Duration::from_millis(1_500));
    let connected = addrs
        .iter()
        .any(|a| TcpStream::connect_timeout(a, connect_timeout).is_ok());
    if !connected {
        let hint = if port == P2P_PORT {
            format!(
                " — and {P2P_PORT} is the P2P port anyway; JSON-RPC is {RPC_PORT}, \
                 try `{host}:{RPC_PORT}`"
            )
        } else if is_probably_vpn(&host) {
            " — that looks like a VPN / point-to-point interface address; try the node's \
             LAN address or 127.0.0.1"
                .to_string()
        } else {
            String::new()
        };
        return NodeLink::down(
            endpoint.clone(),
            LinkStatus::Refused,
            format!("nothing accepted a TCP connection at {endpoint}{hint}"),
        );
    }

    // 3. Speak JSON-RPC.
    let client = RpcClient::new(endpoint.clone()).with_timeout(timeout);
    let started = Instant::now();
    let height = match client.height() {
        Ok(h) => h,
        Err(e) => {
            let msg = e.to_string();
            // Classify by the ERROR KIND, not by string sniffing.
            //
            // The distinction that matters: did something answer us as a service
            // (a JSON-RPC error, a malformed body — "not a SOV node"), or did the
            // TRANSPORT fail (timeout, connection reset, broken pipe — "silent")?
            // A node under load resets and drops connections constantly, and
            // calling that "not a SOV node" sends the operator hunting for the
            // wrong problem. Transport trouble is always SILENT, i.e. retryable.
            let (status, detail) = match &e {
                RpcClientError::Rpc { .. } | RpcClientError::Malformed(_) => (
                    LinkStatus::NotSov,
                    format!("{endpoint} answered, but not as a SOV node ({msg})"),
                ),
                RpcClientError::Json(_) | RpcClientError::Io(_) => {
                    if port == P2P_PORT {
                        (
                            LinkStatus::Silent,
                            format!(
                                "{endpoint} accepted the connection but never answered JSON-RPC \
                                 — {P2P_PORT} is the P2P (Noise-XX) port. RPC is {RPC_PORT}: try \
                                 `{host}:{RPC_PORT}`"
                            ),
                        )
                    } else {
                        (
                            LinkStatus::Silent,
                            format!(
                                "{endpoint} connected but the call did not complete ({msg}) — \
                                 a node busy serving a miner does this under load"
                            ),
                        )
                    }
                }
            };
            return NodeLink::down(endpoint, status, detail);
        }
    };
    let latency = started.elapsed();
    let chain_id = client.chain_id().ok();
    let mempool = client.mempool_size().ok();
    NodeLink {
        endpoint: endpoint.clone(),
        status: LinkStatus::Live,
        chain_id: chain_id.clone(),
        height: Some(height),
        mempool,
        latency: Some(latency),
        detail: format!(
            "{endpoint} · {} · height {height} · {} ms",
            chain_id.as_deref().unwrap_or("unknown chain"),
            latency.as_millis()
        ),
        attempts: Vec::new(),
        redirected: false,
    }
}

/// Probe an endpoint, retrying briefly before calling it down.
///
/// This exists because of a very real deployment: SOV Station running an embedded
/// node with its RPC exposed, WHILE the XUS Miner hammers that same RPC for
/// templates and submissions. Under that load a single call can time out or be
/// refused (accept backlog) on a node that is perfectly healthy. One failed call
/// must therefore never be reported as "node unreachable" — the harness retries
/// with a short backoff and only reports the failure if it is consistent.
///
/// `tries` is total attempts, not extra ones. Retries stop early on `Unresolved`
/// (a name does not start resolving because you asked twice).
pub fn check_endpoint_resilient(target: &str, timeout: Duration, tries: u32) -> NodeLink {
    let mut last = check_endpoint(target, timeout);
    for attempt in 1..tries.max(1) {
        if last.status.is_live() || last.status == LinkStatus::Unresolved {
            return last;
        }
        // Exponential-ish backoff. Under real load the node's accept backlog
        // drains in tens to hundreds of milliseconds; retrying instantly just
        // adds to the pile-up we are waiting out.
        std::thread::sleep(Duration::from_millis(150 * (1 << (attempt - 1)) as u64));
        last = check_endpoint(target, timeout);
    }
    last
}

/// The default patience for the RPC call. Measured, not guessed: a SOV Station node
/// serving three steady template pollers (the XUS Miner's shape of load) answers
/// `sov_getHeight` in 280–2550 ms, so anything under ~3s reports a healthy node as
/// dead. The TCP connect inside `check_endpoint` stays capped at 1.5s, so a
/// black-holed address still fails fast.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(5_000);
/// Total attempts a single endpoint gets before it is called down.
pub const DEFAULT_TRIES: u32 = 3;

/// Heuristic: an address on a point-to-point / VPN-style interface (Tailscale and
/// friends hand out `10.x` peer addresses that the host cannot connect to itself).
/// Only used to phrase a HINT — never to skip an attempt.
fn is_probably_vpn(host: &str) -> bool {
    matches!(host.parse::<IpAddr>(), Ok(IpAddr::V4(v4)) if v4.octets()[0] == 10)
}

/// Every IPv4 address this machine currently holds, so discovery can offer the
/// node's real LAN address when a UI advertised an unreachable one. Read from
/// `ifconfig` — no extra dependency for something this small, and it fails soft
/// (an empty list just means fewer candidates).
fn local_ipv4s() -> Vec<String> {
    let Ok(out) = std::process::Command::new("ifconfig").output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("inet ") else {
            continue;
        };
        let Some(ip) = rest.split_whitespace().next() else {
            continue;
        };
        // Skip the whole 127.0.0.0/8 loopback range (127.0.0.1 is already a
        // candidate, and aliases like 127.210.x are not LAN addresses), plus
        // point-to-point peers — a line with `-->` is exactly the VPN case that
        // cannot be connected to.
        let is_loopback = matches!(ip.parse::<IpAddr>(), Ok(IpAddr::V4(v4)) if v4.is_loopback());
        if is_loopback || line.contains("-->") {
            continue;
        }
        if ip.parse::<IpAddr>().is_ok() && !found.contains(&ip.to_string()) {
            found.push(ip.to_string());
        }
    }
    found
}

/// The ranked candidate endpoints to try for a typed target: the target itself,
/// then the same host on the RPC port, then loopback, then this machine's real
/// IPv4 addresses. Deduplicated, order preserved.
pub fn candidates(target: &str) -> Vec<(String, &'static str)> {
    let endpoint = normalize_endpoint(target);
    let (host, port) = split(&endpoint);
    let mut out: Vec<(String, &'static str)> = vec![(endpoint.clone(), "as typed")];
    let mut push = |e: String, why: &'static str| {
        if !out.iter().any(|(x, _)| *x == e) {
            out.push((e, why));
        }
    };
    if port != RPC_PORT {
        push(
            format!("{host}:{RPC_PORT}"),
            "same host on the JSON-RPC port",
        );
    }
    push(format!("127.0.0.1:{RPC_PORT}"), "this machine (loopback)");
    for ip in local_ipv4s() {
        push(format!("{ip}:{RPC_PORT}"), "this machine (LAN address)");
    }
    out
}

/// Probe the typed endpoint and, if it is not live, sweep the ranked candidates and
/// adopt the first that answers. Returns a link whose `attempts` records every try —
/// so the UI can show the operator precisely what was attempted and what worked,
/// rather than a dead end.
pub fn discover(target: &str, timeout: Duration) -> NodeLink {
    let typed = normalize_endpoint(target);
    let mut attempts = Vec::new();

    // TWO PASSES, and the order matters for how this FEELS to use.
    //
    // Pass 1 is a fast scan: one try per candidate on a short budget. The common
    // failures — the P2P port, a VPN address nothing is bound to — are silent
    // black holes, and spending full patience on each before reaching the endpoint
    // that works turns a 3-second recovery into a 16-second stall.
    //
    // Pass 2 only runs if NOTHING answered, and is fully patient: that is the case
    // where the node may be alive but slow (a miner hammering the same RPC), and
    // being impatient there is exactly the bug that reports a healthy node as dead.
    let fast = timeout.min(Duration::from_millis(1_500));
    for (pass, (per_timeout, tries)) in [(fast, 1), (timeout, DEFAULT_TRIES)].iter().enumerate() {
        for (endpoint, why) in candidates(target) {
            let link = check_endpoint_resilient(&endpoint, *per_timeout, *tries);
            attempts.push(Attempt {
                endpoint: endpoint.clone(),
                status: link.status,
                why,
                detail: link.detail.clone(),
            });
            if link.status.is_live() {
                let redirected = endpoint != typed;
                let mut link = link;
                link.attempts = attempts;
                link.redirected = redirected;
                if redirected {
                    link.detail = format!(
                        "{} — `{typed}` did not answer; switched to `{endpoint}` ({why})",
                        link.detail
                    );
                }
                return link;
            }
        }
        let _ = pass;
    }
    // Nothing answered on either pass: report the typed endpoint's own diagnosis,
    // with the full sweep attached so the operator sees exactly what was tried.
    let mut link = check_endpoint(&typed, timeout);
    link.detail = format!(
        "{} — tried {} candidate endpoint(s), none answered",
        link.detail,
        attempts.len()
    );
    link.attempts = attempts;
    link
}

/// Discovery that WAITS OUT a stalled node.
///
/// Measured on a real SOV Station running an embedded mining node: its RPC can go
/// completely silent for tens of seconds while a mining/import burst holds the chain
/// lock, then answer normally again. A one-shot sweep hits that window and reports a
/// perfectly healthy node as dead — so this retries the whole sweep for up to
/// `patience`, calling `on_wait` between rounds so a caller can show progress.
///
/// Returns as soon as anything answers.
pub fn discover_patient(
    target: &str,
    timeout: Duration,
    patience: Duration,
    mut on_wait: impl FnMut(&NodeLink, Duration),
) -> NodeLink {
    let deadline = Instant::now() + patience;
    let mut last = discover(target, timeout);
    while !last.status.is_live() && Instant::now() < deadline {
        // Only a TRANSPORT-level silence is worth waiting on. A name that does not
        // resolve will not start resolving, and a service that answered as
        // not-SOV is not going to become a SOV node.
        if last.status == LinkStatus::Unresolved || last.status == LinkStatus::NotSov {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        on_wait(&last, remaining);
        std::thread::sleep(Duration::from_secs(3));
        last = discover(target, timeout);
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_scheme_path_and_default_port() {
        assert_eq!(normalize_endpoint("  http://1.2.3.4/rpc "), "1.2.3.4:8645");
        assert_eq!(normalize_endpoint("1.2.3.4"), "1.2.3.4:8645");
        assert_eq!(normalize_endpoint("1.2.3.4:9645"), "1.2.3.4:9645");
    }

    /// The P2P port must never be silently accepted as an RPC endpoint: it is the
    /// single most common mis-entry, and the candidate list has to offer 8645.
    #[test]
    fn p2p_port_gets_the_rpc_port_as_a_candidate() {
        let c = candidates("10.0.0.5:9645");
        assert_eq!(c[0].0, "10.0.0.5:9645");
        assert!(
            c.iter().any(|(e, _)| e == "10.0.0.5:8645"),
            "the RPC port must be offered: {c:?}"
        );
    }

    /// Loopback is always a candidate — a node on THIS machine is the common case
    /// for an operator whose UI advertised an unreachable VPN address.
    #[test]
    fn loopback_is_always_a_candidate() {
        assert!(candidates("203.0.113.9:8645")
            .iter()
            .any(|(e, _)| e == "127.0.0.1:8645"));
    }

    /// A closed port must be diagnosed as REFUSED (or SILENT), never as LIVE, and
    /// must never hang: this drives real sockets, so it also pins the timeout path.
    #[test]
    fn a_dead_endpoint_is_diagnosed_not_hung() {
        let link = check_endpoint("127.0.0.1:1", Duration::from_millis(400));
        assert!(!link.status.is_live(), "{:?}", link);
        assert!(matches!(
            link.status,
            LinkStatus::Refused | LinkStatus::Silent | LinkStatus::NotSov
        ));
    }
}
