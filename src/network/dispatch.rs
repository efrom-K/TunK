//! Packet dispatch loop — routes Wintun TUN traffic to proxy connections.
//!
//! For each new TCP flow destined to the FakeIP range (198.18.0.0/16), a proxy
//! connection is opened via `ProxyConnector::connect` and a relay task is spawned
//! that bridges the TUN session and the proxy TCP stream bidirectionally.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::config::ProxyProfile;
use crate::proxy::connector::{ProxyConnector, ProxyStream, TargetAddr};
use crate::state::AppState;

// ─── TCP flag bitmasks ────────────────────────────────────────────────────────

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// ─── Flow table ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
}

/// A data segment forwarded from the dispatch loop to a relay task.
struct FlowMsg {
    /// TCP sequence number of the first byte of `payload`.
    seq: u32,
    payload: Vec<u8>,
}

struct FlowEntry {
    tx: mpsc::Sender<FlowMsg>,
    last_active: Arc<AtomicU64>,
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Returns the current time as Unix timestamp in seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Reads packets from `session` and dispatches each TCP flow destined for the
/// FakeIP range (198.18.0.0/16) to a proxy relay task.
///
/// Returns when `session.shutdown()` is called (receive_blocking returns Err).
pub async fn run_dispatch(session: Arc<wintun::Session>, state: Arc<AppState>) -> Result<()> {
    let flows: Arc<DashMap<FlowKey, FlowEntry>> = Arc::new(DashMap::new());

    // Spawn idle-flow cleanup task: remove flows not active for > 300 s.
    let flows_cleanup = flows.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = now_secs();
            flows_cleanup.retain(|_, entry| {
                now.saturating_sub(entry.last_active.load(Ordering::Relaxed)) < 300
            });
        }
    });

    loop {
        let session_c = session.clone();
        let result = tokio::task::spawn_blocking(move || session_c.receive_blocking())
            .await
            .map_err(|e| anyhow!("spawn_blocking join error: {}", e))?;

        let packet = match result {
            Ok(p) => p,
            Err(_) => break, // session.shutdown() was called
        };

        let bytes = packet.bytes().to_vec();
        drop(packet); // return slot to Wintun ring buffer immediately

        if let Err(e) = handle_packet(&bytes, &flows, &session, &state).await {
            let _ = state.log("WARN", &format!("dispatch: {}", e));
        }
    }

    Ok(())
}

// ─── Per-packet handler ───────────────────────────────────────────────────────

async fn handle_packet(
    bytes: &[u8],
    flows: &Arc<DashMap<FlowKey, FlowEntry>>,
    session: &Arc<wintun::Session>,
    state: &Arc<AppState>,
) -> Result<()> {
    let (proto, src_ip, dst_ip, ihl) = parse_ipv4(bytes).ok_or_else(|| anyhow!("not IPv4"))?;
    if proto != 6 {
        return Ok(()); // only TCP is handled
    }

    // Only intercept the FakeIP range 198.18.0.0/16
    let dst_octets = Ipv4Addr::from(dst_ip).octets();
    if dst_octets[0] != 198 || dst_octets[1] != 18 {
        return Ok(());
    }

    let tcp = parse_tcp(bytes, ihl).ok_or_else(|| anyhow!("bad TCP header"))?;
    let key = FlowKey { src_ip, src_port: tcp.src_port, dst_ip, dst_port: tcp.dst_port };

    if tcp.flags & TCP_RST != 0 {
        flows.remove(&key);
        return Ok(());
    }

    // FIN: dropping the sender closes the channel, which unblocks the relay task.
    if tcp.flags & TCP_FIN != 0 {
        flows.remove(&key);
        return Ok(());
    }

    // SYN (without ACK) — new connection.
    if tcp.flags & TCP_SYN != 0 && tcp.flags & TCP_ACK == 0 {
        return open_flow(key, tcp.seq, tcp.dst_port, dst_ip, src_ip, tcp.src_port, flows, session, state).await;
    }

    // Data or pure ACK — forward non-empty payload to the relay task.
    let payload = &bytes[tcp.payload_start..];
    if !payload.is_empty() {
        if let Some(entry) = flows.get(&key) {
            let _ = entry.tx.try_send(FlowMsg { seq: tcp.seq, payload: payload.to_vec() });
        }
    }

    Ok(())
}

// ─── New-flow handler ─────────────────────────────────────────────────────────

async fn open_flow(
    key: FlowKey,
    client_syn_seq: u32,
    dst_port: u16,
    dst_ip: u32,
    src_ip: u32,
    src_port: u16,
    flows: &Arc<DashMap<FlowKey, FlowEntry>>,
    session: &Arc<wintun::Session>,
    state: &Arc<AppState>,
) -> Result<()> {
    // Resolve FakeIP → domain name
    let domain = {
        let ip_str = Ipv4Addr::from(dst_ip).to_string();
        state
            .fake_ip_to_domain
            .get(&ip_str)
            .map(|v| v.clone())
            .ok_or_else(|| anyhow!("FakeIP {} not in table", ip_str))?
    };

    // Get selected proxy profile
    let profile = {
        let pid = state.get_profile_id().ok_or_else(|| anyhow!("no profile selected"))?;
        state
            .find_profile(&pid)
            .map_err(|e| anyhow!("profile lookup failed: {}", e))?
            .ok_or_else(|| anyhow!("profile not found"))?
    };

    // Send SYN-ACK to the OS
    let our_isn: u32 = rand::thread_rng().gen();
    let client_next = client_syn_seq.wrapping_add(1);
    let synack = build_tcp(
        dst_ip, dst_port, src_ip, src_port,
        our_isn, client_next,
        TCP_SYN | TCP_ACK, 65535, &[],
    );
    write_tun(session, &synack)?;

    // Create channel and record flow entry with last_active timestamp.
    let (tx, rx) = mpsc::channel::<FlowMsg>(128);
    let key_c = key.clone();
    let last_active = Arc::new(AtomicU64::new(now_secs()));
    let last_active_c = last_active.clone();
    flows.insert(key, FlowEntry { tx, last_active });

    // Spawn the relay task
    let session_c = session.clone();
    let state_c = state.clone();
    let flows_c = flows.clone();
    let target = TargetAddr::Domain(domain);

    tokio::spawn(async move {
        let state_log = state_c.clone();
        if let Err(e) = relay_flow(
            profile, target, dst_port,
            src_ip, src_port, dst_ip,
            our_isn.wrapping_add(1),
            client_next,
            rx, session_c, state_c,
            last_active_c,
        ).await {
            let _ = state_log.log("WARN", &format!("relay: {}", e));
        }
        flows_c.remove(&key_c);
    });

    Ok(())
}

// ─── Bidirectional relay ──────────────────────────────────────────────────────

async fn relay_flow(
    profile: ProxyProfile,
    target: TargetAddr,
    dst_port: u16,
    client_ip: u32,
    client_port: u16,
    server_ip: u32, // the FakeIP address (used as src in outgoing packets)
    mut our_seq: u32,
    mut client_next: u32,
    mut rx: mpsc::Receiver<FlowMsg>,
    session: Arc<wintun::Session>,
    state: Arc<AppState>,
    last_active: Arc<AtomicU64>,
) -> Result<()> {
    let proxy_stream: ProxyStream = match ProxyConnector::connect(&profile, &target, dst_port).await {
        Ok(s) => s,
        Err(e) => {
            // Signal connection failure with a RST
            let rst = build_tcp(
                server_ip, dst_port, client_ip, client_port,
                our_seq, client_next, TCP_RST | TCP_ACK, 0, &[],
            );
            let _ = write_tun(&session, &rst);
            return Err(e);
        }
    };

    let (mut pr, mut pw) = tokio::io::split(proxy_stream);
    let mut buf = [0u8; 8192];

    loop {
        tokio::select! {
            // TUN → proxy direction
            msg = rx.recv() => {
                match msg {
                    None => break, // flow removed (FIN/RST) or channel closed
                    Some(FlowMsg { seq, payload }) => {
                        pw.write_all(&payload).await?;
                        // ACK the client's data
                        client_next = seq.wrapping_add(payload.len() as u32);
                        let ack = build_tcp(
                            server_ip, dst_port, client_ip, client_port,
                            our_seq, client_next, TCP_ACK, 65535, &[],
                        );
                        write_tun(&session, &ack)?;
                        last_active.store(now_secs(), Ordering::Relaxed);
                        if let Ok(mut stats) = state.stats.write() {
                            stats.upload_speed_bps =
                                stats.upload_speed_bps.saturating_add(payload.len() as u64);
                        }
                    }
                }
            }
            // proxy → TUN direction
            n = pr.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // Segment into ≤1400-byte chunks to stay within MTU
                        for chunk in buf[..n].chunks(1400) {
                            let pkt = build_tcp(
                                server_ip, dst_port, client_ip, client_port,
                                our_seq, client_next, TCP_PSH | TCP_ACK, 65535, chunk,
                            );
                            write_tun(&session, &pkt)?;
                            our_seq = our_seq.wrapping_add(chunk.len() as u32);
                        }
                        last_active.store(now_secs(), Ordering::Relaxed);
                        if let Ok(mut stats) = state.stats.write() {
                            stats.download_speed_bps =
                                stats.download_speed_bps.saturating_add(n as u64);
                        }
                    }
                }
            }
        }
    }

    // Graceful teardown: send FIN+ACK
    let fin = build_tcp(
        server_ip, dst_port, client_ip, client_port,
        our_seq, client_next, TCP_FIN | TCP_ACK, 0, &[],
    );
    let _ = write_tun(&session, &fin);

    Ok(())
}

// ─── Wintun write helper ──────────────────────────────────────────────────────

fn write_tun(session: &Arc<wintun::Session>, pkt: &[u8]) -> Result<()> {
    let mut send = session
        .allocate_send_packet(pkt.len() as u16)
        .map_err(|_| anyhow!("wintun ring buffer full"))?;
    send.bytes_mut().copy_from_slice(pkt);
    session.send_packet(send);
    Ok(())
}

// ─── Packet construction ──────────────────────────────────────────────────────

/// Builds a minimal IPv4 + TCP packet (no IP options, no TCP options).
fn build_tcp(
    src_ip: u32, src_port: u16,
    dst_ip: u32, dst_port: u16,
    seq: u32, ack_seq: u32,
    flags: u8, window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 40 + payload.len(); // 20 IP + 20 TCP + payload
    let mut pkt = vec![0u8; total];

    // IPv4 header
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 6;  // protocol: TCP
    pkt[12..16].copy_from_slice(&src_ip.to_be_bytes());
    pkt[16..20].copy_from_slice(&dst_ip.to_be_bytes());
    let ip_cksum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // TCP header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack_seq.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5 (20 bytes, no options)
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&window.to_be_bytes());
    if !payload.is_empty() {
        pkt[40..].copy_from_slice(payload);
    }
    let tcp_cksum = tcp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_cksum.to_be_bytes());

    pkt
}

/// RFC 1071 one's-complement checksum over `data`.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP checksum over the IPv4 pseudo-header + TCP segment.
fn tcp_checksum(src_ip: u32, dst_ip: u32, tcp_seg: &[u8]) -> u16 {
    let len = tcp_seg.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + tcp_seg.len());
    pseudo.extend_from_slice(&src_ip.to_be_bytes());
    pseudo.extend_from_slice(&dst_ip.to_be_bytes());
    pseudo.push(0);
    pseudo.push(6); // TCP
    pseudo.extend_from_slice(&len.to_be_bytes());
    pseudo.extend_from_slice(tcp_seg);
    checksum(&pseudo)
}

// ─── Header parsing ───────────────────────────────────────────────────────────

/// Returns (protocol, src_ip, dst_ip, ihl) for an IPv4 packet, or None.
fn parse_ipv4(pkt: &[u8]) -> Option<(u8, u32, u32, usize)> {
    if pkt.len() < 20 { return None; }
    if pkt[0] >> 4 != 4 { return None; }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() < ihl { return None; }
    let proto = pkt[9];
    let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
    Some((proto, src, dst, ihl))
}

struct TcpFields {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags: u8,
    payload_start: usize, // absolute offset into the original packet
}

/// Parses the TCP header starting at byte `ip_end` of `pkt`.
fn parse_tcp(pkt: &[u8], ip_end: usize) -> Option<TcpFields> {
    let tcp = pkt.get(ip_end..)?;
    if tcp.len() < 20 { return None; }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset { return None; }
    let flags = tcp[13];
    Some(TcpFields { src_port, dst_port, seq, flags, payload_start: ip_end + data_offset })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_synack() {
        let src_ip = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        let dst_ip = u32::from(Ipv4Addr::new(10, 0, 0, 1));

        let pkt = build_tcp(src_ip, 443, dst_ip, 54321, 1000, 2001, TCP_SYN | TCP_ACK, 65535, &[]);

        let (proto, p_src, p_dst, ihl) = parse_ipv4(&pkt).unwrap();
        assert_eq!(proto, 6);
        assert_eq!(p_src, src_ip);
        assert_eq!(p_dst, dst_ip);

        let tcp = parse_tcp(&pkt, ihl).unwrap();
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 54321);
        assert_eq!(tcp.seq, 1000);
        assert_eq!(tcp.flags, TCP_SYN | TCP_ACK);
        assert_eq!(tcp.payload_start, 40);
    }

    #[test]
    fn test_build_tcp_with_payload() {
        let src_ip = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        let dst_ip = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let payload = b"hello world";

        let pkt = build_tcp(src_ip, 443, dst_ip, 12345, 500, 100, TCP_PSH | TCP_ACK, 8192, payload);

        let (_, _, _, ihl) = parse_ipv4(&pkt).unwrap();
        let tcp = parse_tcp(&pkt, ihl).unwrap();
        assert_eq!(&pkt[tcp.payload_start..], payload);
    }

    #[test]
    fn test_ip_checksum_verifies_to_zero() {
        // A packet with a correct IP checksum, when checksummed again (including
        // the checksum field), should produce 0x0000.
        let src_ip = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        let dst_ip = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = build_tcp(src_ip, 443, dst_ip, 80, 0, 0, TCP_SYN, 65535, &[]);
        assert_eq!(checksum(&pkt[..20]), 0);
    }

    #[test]
    fn test_known_checksum_value() {
        // 0x4500 + 0x003c = 0x453c; !0x453c = 0xbac3
        let data = [0x45u8, 0x00, 0x00, 0x3c];
        assert_eq!(checksum(&data), 0xbac3);
    }

    #[test]
    fn test_parse_ipv4_rejects_ipv6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // IPv6
        assert!(parse_ipv4(&pkt).is_none());
    }

    #[test]
    fn test_parse_ipv4_rejects_short() {
        assert!(parse_ipv4(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_tcp_rejects_short_header() {
        let pkt = vec![0u8; 30]; // 20 IP + 10 bytes (TCP needs ≥20)
        assert!(parse_tcp(&pkt, 20).is_none());
    }

    #[test]
    fn test_fakeip_range_check() {
        // Only 198.18.x.x should be intercepted
        let fakeip = Ipv4Addr::new(198, 18, 5, 100);
        let octets = fakeip.octets();
        assert!(octets[0] == 198 && octets[1] == 18);

        let other = Ipv4Addr::new(8, 8, 8, 8);
        let octets = other.octets();
        assert!(!(octets[0] == 198 && octets[1] == 18));
    }

    #[test]
    fn test_tcp_flag_constants() {
        assert_eq!(TCP_SYN | TCP_ACK, 0x12);
        assert_eq!(TCP_PSH | TCP_ACK, 0x18);
        assert_eq!(TCP_FIN | TCP_ACK, 0x11);
        assert_eq!(TCP_RST | TCP_ACK, 0x14);
    }
}
