//! `sov-redteam` CLI — runs the adversarial battery (implemented in the `sov_redteam`
//! library, so the standalone GUI can run the exact same attacks) and prints a terminal
//! report. Exits non-zero if any attack is VULNERABLE, so CI or a release gate can
//! consume it.
//!
//! Two modes:
//!   sov-redteam                          in-process: attack a private replica of consensus
//!   sov-redteam --target <host[:port]>   live-fire: probe a REAL running node's RPC front door
//!
//! The live-fire probe is side-effect-free — every tx it sends is rejected at admission,
//! so nothing lands in the target's mempool.

use sov_redteam::{
    backdoor_any_vulnerable, funded_any_vulnerable, gauntlet_any_vulnerable, keypair_from_secret,
    live_any_vulnerable, probe_backdoor, probe_frontdoor, probe_funded, probe_gauntlet, run_all,
    GauntletReport, Verdict,
};

fn main() {
    // `--target <addr>` switches to a live probe; add `--p2p` (back door), `--funded`
    // (funded adversary, key from SOV_REDTEAM_KEY), or `--gauntlet` (attack the live pot).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = parse_target(&args);
    let p2p = args.iter().any(|a| a == "--p2p" || a == "--backdoor");
    let funded = args.iter().any(|a| a == "--funded");
    let gauntlet = args.iter().any(|a| a == "--gauntlet");

    let link_only = args.iter().any(|a| a == "--link" || a == "--check");

    match target {
        // `--link` is the diagnostic on its own: point it at anything and it says
        // what is (or is not) there, and what to type instead.
        Some(addr) if link_only => {
            if !link_mode(&addr) {
                std::process::exit(2);
            }
        }
        Some(addr) if gauntlet => with_link(&addr, gauntlet_mode),
        Some(addr) if funded => with_link(&addr, funded_mode),
        Some(addr) if p2p => with_link(&addr, backdoor_mode),
        Some(addr) => with_link(&addr, live_mode),
        None => in_process_mode(),
    }
}

/// Preflight EVERY live mode through node discovery.
///
/// A live probe that opens with "node unreachable" and stops is useless: the cause
/// is almost always the P2P port (`9645`) typed where JSON-RPC (`8645`) belongs, or
/// an address a node UI advertised from a VPN interface that nothing can dial. So
/// resolve the endpoint FIRST, adopt whichever candidate actually answers, print the
/// evidence, and only then hand the working endpoint to the probe.
fn with_link(addr: &str, probe: fn(&str)) {
    let timeout = sov_redteam::link::DEFAULT_TIMEOUT;
    // Wait out a stalled node rather than dead-ending on it: a SOV Station node
    // that is mining (or serving the XUS Miner) can go silent for tens of seconds
    // while a burst holds the chain lock, then answer normally again.
    let link = sov_redteam::link::discover_patient(
        addr,
        timeout,
        std::time::Duration::from_secs(45),
        |link, remaining| {
            println!(
                "  \x1b[33m…\x1b[0m {} — node busy or silent; retrying for {}s",
                link.status.label(),
                remaining.as_secs()
            );
        },
    );
    if !link.status.is_live() {
        report_link(&link);
        std::process::exit(2);
    }
    if link.redirected {
        println!(
            "\n  \x1b[33m⟳\x1b[0m endpoint corrected: {} → \x1b[32m{}\x1b[0m",
            sov_redteam::normalize_endpoint(addr),
            link.endpoint
        );
    }
    println!(
        "  \x1b[32m●\x1b[0m LIVE {} · {} · height {} · {} ms",
        link.endpoint,
        link.chain_id.as_deref().unwrap_or("unknown chain"),
        link.height.unwrap_or(0),
        link.latency.map(|l| l.as_millis()).unwrap_or(0)
    );
    probe(&link.endpoint);
}

/// `--link`: diagnose a node endpoint and print the candidate sweep. Returns true
/// if a node answered.
fn link_mode(addr: &str) -> bool {
    println!("\n  sov-redteam — node link check");
    let link = sov_redteam::link::discover_patient(
        addr,
        sov_redteam::link::DEFAULT_TIMEOUT,
        std::time::Duration::from_secs(20),
        |l, r| println!("  … {} — retrying for {}s", l.status.label(), r.as_secs()),
    );
    report_link(&link);
    link.status.is_live()
}

/// Print a link result: the verdict, the diagnosis, and every candidate tried.
fn report_link(link: &sov_redteam::NodeLink) {
    let live = link.status.is_live();
    let (mark, color) = if live {
        ("●", "\x1b[32m")
    } else {
        ("✗", "\x1b[31m")
    };
    println!(
        "\n  {color}{mark} [{}]\x1b[0m {}",
        link.status.label(),
        link.detail
    );
    if !link.attempts.is_empty() {
        println!("\n  candidates tried:");
        for a in &link.attempts {
            let c = if a.status.is_live() {
                "\x1b[32m"
            } else {
                "\x1b[90m"
            };
            println!(
                "   {c}{:<24} {:<15}\x1b[0m {}",
                a.endpoint,
                a.status.label(),
                a.why
            );
        }
    }
    if !live {
        println!(
            "\n  JSON-RPC is port {} — port {} is P2P (Noise-XX) and never answers RPC.\n  \
             If SOV Station shows a 10.x VPN address, use its LAN address or 127.0.0.1:{}.\n",
            sov_redteam::RPC_PORT,
            sov_redteam::P2P_PORT,
            sov_redteam::RPC_PORT
        );
    } else {
        println!();
    }
}

fn gauntlet_mode(addr: &str) {
    println!("\n  sov-redteam — THE GAUNTLET (attack the live pot)");
    println!("  trying to drain the steal-the-pot account with no key — every way possible…\n");
    let report = probe_gauntlet(addr);
    if let Some(err) = &report.error {
        println!("  \x1b[31m{err}\x1b[0m\n");
        std::process::exit(2);
    }
    let banner = if report.is_mainnet {
        "\x1b[33mLIVE MAINNET\x1b[0m"
    } else {
        report.chain_id.as_deref().unwrap_or("unknown")
    };
    println!(
        "  pot {}…  ·  balance {} XUS  ·  {}\n",
        short(&report.pot),
        GauntletReport::xus(report.balance_before),
        banner
    );
    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    for o in &report.outcomes {
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<40} {}", o.name, o.detail);
    }
    // The measured metric panel — the same numbers the Station Red Team tab shows,
    // sourced from the report's Display/summary path (`summary_lines`).
    println!("\n  ── metrics ──");
    for line in report.summary_lines() {
        println!("  {line}");
    }
    println!(
        "  {} attacks · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        report.outcomes.len()
    );
    if gauntlet_any_vulnerable(&report) {
        println!("  \x1b[31mTHE POT IS IN DANGER — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    } else {
        println!("  the pot held — no key, no coins.\n");
    }
}

fn funded_mode(addr: &str) {
    println!("\n  sov-redteam — FUNDED-ADVERSARY probe");
    let secret = match std::env::var("SOV_REDTEAM_KEY") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            println!("  \x1b[31mset SOV_REDTEAM_KEY to the funded account's mnemonic or 32-byte hex seed\x1b[0m\n");
            std::process::exit(2);
        }
    };
    let kp = match keypair_from_secret(&secret) {
        Ok(kp) => kp,
        Err(e) => {
            println!("  \x1b[31m{e}\x1b[0m\n");
            std::process::exit(2);
        }
    };
    println!("  attacking AS a real funded account — probing it like a thief (double-spend, replay, rewind, drain)…\n");
    let report = probe_funded(addr, &kp, 100_000);
    if let Some(err) = &report.error {
        println!("  \x1b[31m{err}\x1b[0m\n");
        std::process::exit(2);
    }
    let banner = if report.is_mainnet {
        "\x1b[33mLIVE MAINNET\x1b[0m"
    } else {
        report.chain_id.as_deref().unwrap_or("unknown")
    };
    println!(
        "  account {}  ·  balance {}  ·  nonce {}  ·  {}",
        short(&report.account),
        report.balance,
        report.nonce,
        banner
    );
    println!();

    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    for o in &report.outcomes {
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<44} {}", o.name, o.detail);
    }
    println!(
        "\n  {} steps · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        report.outcomes.len()
    );
    if funded_any_vulnerable(&report) {
        println!("  \x1b[31mA DOUBLE-SPEND OR REPLAY WAS ADMITTED — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    } else {
        println!("  the chain refused to spend the same coin twice.\n");
    }
}

fn short(s: &str) -> String {
    s.chars().take(16).collect()
}

/// Pull the value of `--target <addr>` / `--target=<addr>` out of the args, if present.
fn parse_target(args: &[String]) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(v) = a.strip_prefix("--target=") {
            return Some(v.to_string());
        }
        if a == "--target" {
            return it.next().cloned();
        }
    }
    None
}

fn in_process_mode() {
    println!("\n  sov-redteam — adversarial harness for the SOV chain");
    println!("  building a real in-process chain and attacking consensus…\n");

    let outcomes = run_all();

    let mut last_cat = "";
    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    for o in &outcomes {
        if o.category != last_cat {
            println!("  ── {} ──", o.category.to_uppercase());
            last_cat = o.category;
        }
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<42} {}", o.name, o.detail);
    }

    println!(
        "\n  {} attacks · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        outcomes.len()
    );
    if vulnerable == 0 {
        println!("  every defense held.\n");
    } else {
        println!("  \x1b[31mVULNERABILITIES FOUND — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    }
}

fn live_mode(addr: &str) {
    println!("\n  sov-redteam — LIVE front-door probe");
    println!("  submitting adversarial transactions to a real node (rejected at admission — nothing lands)…\n");

    let report = probe_frontdoor(addr);

    if !report.reachable {
        println!(
            "  \x1b[31mcould not reach {} — is the node running and RPC exposed?\x1b[0m\n",
            report.target
        );
        std::process::exit(2);
    }

    let chain = report.chain_id.as_deref().unwrap_or("unknown");
    let height = report
        .height
        .map(|h| h.to_string())
        .unwrap_or_else(|| "?".into());
    let banner = if report.is_mainnet {
        "\x1b[33mLIVE MAINNET\x1b[0m"
    } else {
        chain
    };
    println!(
        "  target {}  ·  chain {}  ·  height {}\n",
        report.target, banner, height
    );

    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    let mut last_cat = "";
    for o in &report.outcomes {
        if o.category != last_cat {
            println!("  ── {} ──", o.category.to_uppercase());
            last_cat = o.category;
        }
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<48} {}", o.name, o.detail);
    }

    // No-residue proof: the mempool must be unchanged if every attack was rejected
    // before admission.
    if let (Some(b), Some(a)) = (report.mempool_before, report.mempool_after) {
        let verdict = if report.no_residue() {
            "\x1b[32mno residue — nothing landed\x1b[0m"
        } else {
            "\x1b[31mRESIDUE — a tx was admitted!\x1b[0m"
        };
        println!("\n  mempool {b} → {a}  ·  {verdict}");
    }

    println!(
        "  {} probes · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        report.outcomes.len()
    );
    if live_any_vulnerable(&report) {
        println!("  \x1b[31mAN ADVERSARIAL TX WAS ADMITTED — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    } else {
        println!("  the front door held — every adversarial tx was rejected before admission.\n");
    }
}

fn backdoor_mode(addr: &str) {
    println!("\n  sov-redteam — LIVE BACK-DOOR probe (P2P peer)");
    println!(
        "  joining the network as a hostile peer and gossiping forged blocks/txs over the wire…\n"
    );

    let report = probe_backdoor(addr);

    if let Some(err) = &report.error {
        println!("  \x1b[31mcould not run: {err}\x1b[0m\n");
        std::process::exit(2);
    }

    let chain = report.chain_id.as_deref().unwrap_or("unknown");
    let banner = if report.is_mainnet {
        "\x1b[33mLIVE MAINNET\x1b[0m"
    } else {
        chain
    };
    let auth = if report.authenticated {
        "\x1b[32mauthenticated\x1b[0m"
    } else {
        "\x1b[31mNOT authenticated\x1b[0m"
    };
    println!(
        "  p2p {}  ·  chain {}  ·  hostile peer {}",
        report.p2p_target, banner, auth
    );
    if let Some((h, hash)) = &report.head_before {
        println!("  head before: height {h}  {}", &hash[..16.min(hash.len())]);
    }
    println!();

    let (mut defended, mut vulnerable, mut info) = (0u32, 0u32, 0u32);
    let mut last_cat = "";
    for o in &report.outcomes {
        if o.category != last_cat {
            println!("  ── {} ──", o.category.to_uppercase());
            last_cat = o.category;
        }
        let (tag, mark) = mark_of(o.verdict, &mut defended, &mut vulnerable, &mut info);
        println!("   {mark} [{tag:<10}] {:<44} {}", o.name, o.detail);
    }

    // Tip-held proof + ejection.
    if let (Some((hb, _)), Some((ha, _))) = (&report.head_before, &report.head_after) {
        let moved = ha != hb;
        println!(
            "\n  head after: height {ha}  ·  {}",
            if moved {
                "advanced by the node's OWN honest mining (no forged hash adopted)"
            } else {
                "unmoved"
            }
        );
    }
    if report.ejected {
        println!("  \x1b[32mthe node BANNED our peer — the attacker was ejected\x1b[0m");
    }
    println!(
        "  {} probes · \x1b[32m{defended} defended\x1b[0m · \x1b[31m{vulnerable} vulnerable\x1b[0m · {info} info",
        report.outcomes.len()
    );
    if backdoor_any_vulnerable(&report) {
        println!("  \x1b[31mA FORGED BLOCK/TX WAS ACCEPTED — see ✗ above.\x1b[0m\n");
        std::process::exit(1);
    } else {
        println!("  the back door held — no forged block was adopted, no forged tx admitted.\n");
    }
}

fn mark_of(
    v: Verdict,
    defended: &mut u32,
    vulnerable: &mut u32,
    info: &mut u32,
) -> (&'static str, &'static str) {
    match v {
        Verdict::Defended => {
            *defended += 1;
            ("DEFENDED", "\x1b[32m✓\x1b[0m")
        }
        Verdict::Vulnerable => {
            *vulnerable += 1;
            ("VULNERABLE", "\x1b[31m✗\x1b[0m")
        }
        Verdict::Info => {
            *info += 1;
            ("INFO", "\x1b[33m•\x1b[0m")
        }
    }
}
