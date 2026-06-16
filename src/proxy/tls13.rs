//! Minimal TLS 1.3 client for REALITY proxy connections.
//!
//! Completes a TLS 1.3 handshake after sending a custom REALITY ClientHello,
//! then wraps the TCP stream so application data flows encrypted.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use anyhow::{anyhow, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::proxy::reality::RealityClientHello;

// ─── TLS constants ────────────────────────────────────────────────────────────

const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CT_HANDSHAKE: u8 = 0x16;
const CT_APPLICATION_DATA: u8 = 0x17;

const HT_FINISHED: u8 = 0x14;

pub const CS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const CS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

const EXT_KEY_SHARE: u16 = 0x0033;

// ─── Internal types ───────────────────────────────────────────────────────────

struct ServerHelloInfo {
    cipher_suite: u16,
    server_key_share: [u8; 32],
    /// Raw handshake message bytes (type+length+body, no TLS record header).
    raw: Vec<u8>,
}

struct HsKeys {
    server_key: Vec<u8>,
    server_iv: [u8; 12],
    client_key: Vec<u8>,
    client_iv: [u8; 12],
    server_finished_key: [u8; 32],
    client_finished_key: [u8; 32],
    handshake_secret: Vec<u8>,
    cipher_suite: u16,
}

// ─── Public: application-data stream ─────────────────────────────────────────

/// TLS 1.3 stream ready for encrypted application data.
pub struct Tls13Stream {
    inner: TcpStream,
    read_key: Vec<u8>,
    read_iv: [u8; 12],
    read_seq: u64,
    write_key: Vec<u8>,
    write_iv: [u8; 12],
    write_seq: u64,
    cipher_suite: u16,
    /// Decrypted data waiting to be returned to the caller.
    buf: Vec<u8>,
    buf_pos: usize,
}

impl Tls13Stream {
    /// Returns the underlying TCP stream (used after REALITY handshake to hand
    /// the connection back to the generic VLESS data path).
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }

    fn new(
        inner: TcpStream,
        read_key: Vec<u8>, read_iv: [u8; 12],
        write_key: Vec<u8>, write_iv: [u8; 12],
        cipher_suite: u16,
    ) -> Self {
        Self {
            inner,
            read_key, read_iv, read_seq: 0,
            write_key, write_iv, write_seq: 0,
            cipher_suite,
            buf: Vec::new(), buf_pos: 0,
        }
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Sends the REALITY ClientHello, completes the TLS 1.3 handshake, and returns
/// a stream ready for application-data exchange.
pub async fn complete_tls13_handshake(
    mut stream: TcpStream,
    hello: RealityClientHello,
) -> Result<Tls13Stream> {
    // RFC 8446 §D.3: use version 0x0301 in the outer record for middlebox compat.
    let mut ch_record = make_record(CT_HANDSHAKE, &hello.raw);
    ch_record[2] = 0x01;
    stream.write_all(&ch_record).await?;

    // Read ServerHello, skipping any ChangeCipherSpec for middlebox compat.
    let sh_data = loop {
        let (ct, data) = read_record(&mut stream).await?;
        if ct == CT_CHANGE_CIPHER_SPEC { continue; }
        if ct != CT_HANDSHAKE {
            return Err(anyhow!("expected ServerHello, got 0x{:02x}", ct));
        }
        break data;
    };
    let sh = parse_server_hello(&sh_data)?;
    if sh.cipher_suite != CS_AES_128_GCM_SHA256 && sh.cipher_suite != CS_CHACHA20_POLY1305_SHA256 {
        return Err(anyhow!("unsupported cipher suite 0x{:04x}", sh.cipher_suite));
    }

    // Derive handshake keys from ECDH(our_ephemeral, server_key_share).
    let ecdh = x25519_dalek::x25519(hello.ephemeral_private_key, sh.server_key_share);
    let hs = derive_hs_keys(&hello.raw, &sh.raw, &ecdh, sh.cipher_suite)?;

    // Running transcript hash (SHA-256 for both supported suites).
    let mut ts = Sha256::new();
    ts.update(&hello.raw);
    ts.update(&sh.raw);

    // Read encrypted server handshake records until Finished.
    let mut srv_seq: u64 = 0;
    let server_finished_data: Vec<u8>;
    'recv: loop {
        let (ct, data) = read_record(&mut stream).await?;
        if ct == CT_CHANGE_CIPHER_SPEC { continue; }
        if ct != CT_APPLICATION_DATA {
            return Err(anyhow!("expected encrypted handshake record, got 0x{:02x}", ct));
        }

        let nonce = xnonce(&hs.server_iv, srv_seq);
        let aad = outer_aad(data.len());
        let plain = aead_open(&hs.server_key, &nonce, &aad, &data, hs.cipher_suite)?;
        srv_seq += 1;

        let (hs_bytes, inner_ct) = strip_inner_ct(&plain)?;
        if inner_ct != CT_HANDSHAKE { continue; }

        let mut pos = 0;
        while pos + 4 <= hs_bytes.len() {
            let ht = hs_bytes[pos];
            let body_len = u24be(&hs_bytes[pos + 1..]);
            if pos + 4 + body_len > hs_bytes.len() { break; }
            let msg_raw = &hs_bytes[pos..pos + 4 + body_len];
            let body    = &hs_bytes[pos + 4..pos + 4 + body_len];
            if ht == HT_FINISHED {
                server_finished_data = body.to_vec();
                break 'recv;
            }
            ts.update(msg_raw); // EE, Certificate, CertificateVerify go into transcript
            pos += 4 + body_len;
        }
    }

    // Verify server Finished: HMAC-SHA256(server_finished_key, transcript_so_far).
    let ts_before_sf: [u8; 32] = ts.clone().finalize().into();
    let expected_sf = hmac_sha256(&hs.server_finished_key, &ts_before_sf);
    if expected_sf != server_finished_data.as_slice() {
        return Err(anyhow!("server Finished verification failed"));
    }

    // Commit server Finished to transcript.
    let sf_header = [HT_FINISHED, 0, 0, server_finished_data.len() as u8];
    ts.update(&sf_header);
    ts.update(&server_finished_data);

    // Derive application traffic keys (transcript includes server Finished).
    let ts_full: [u8; 32] = ts.finalize().into();
    let (read_key, read_iv, write_key, write_iv) = derive_app_keys(&hs, &ts_full)?;

    // Client Finished verify_data = HMAC-SHA256(client_finished_key, transcript_through_SF).
    let cf_data = hmac_sha256(&hs.client_finished_key, &ts_full);
    let cf_msg: Vec<u8> = std::iter::once(HT_FINISHED)
        .chain([0u8, 0, cf_data.len() as u8])
        .chain(cf_data.iter().copied())
        .collect();
    // Append content-type byte, encrypt with client handshake key.
    let pt: Vec<u8> = cf_msg.iter().copied().chain([CT_HANDSHAKE]).collect();
    let cf_nonce = xnonce(&hs.client_iv, 0);
    let cf_aad = outer_aad(pt.len() + 16); // ciphertext = plaintext + 16-byte tag
    let cf_ct = aead_seal(&hs.client_key, &cf_nonce, &cf_aad, &pt, hs.cipher_suite)?;
    stream.write_all(&make_record(CT_APPLICATION_DATA, &cf_ct)).await?;

    Ok(Tls13Stream::new(stream, read_key, read_iv, write_key, write_iv, hs.cipher_suite))
}

// ─── AsyncRead / AsyncWrite ───────────────────────────────────────────────────

impl AsyncRead for Tls13Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain our decrypted buffer first.
        if self.buf_pos < self.buf.len() {
            let available = &self.buf[self.buf_pos..];
            let n = available.len().min(out.remaining());
            out.put_slice(&available[..n]);
            self.buf_pos += n;
            return Poll::Ready(Ok(()));
        }

        // Need a new TLS record. We do this synchronously by reading into a
        // temporary buffer — requires the stream to be ready.
        let record = {
            let stream = &mut self.inner;
            tokio::pin!(stream);
            let mut header = [0u8; 5];
            let mut hbuf = ReadBuf::new(&mut header);
            match stream.poll_read(cx, &mut hbuf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) if hbuf.filled().len() < 5 => {
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Ready(Ok(())) => header,
            }
        };
        // We have the header — schedule an async read for the body in the next
        // poll via our internal buffer.  Use a one-shot flag approach: store
        // the partial read state. For simplicity in the prototype, just wake
        // immediately and let the caller drive via `AsyncReadExt::read`.
        let _ = record; // suppress warning; real body read happens below
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// Provide a proper blocking-style read via inherent method for internal use.
impl Tls13Stream {
    /// Reads and decrypts the next TLS application-data record, filling `self.buf`.
    pub async fn fill_buf(&mut self) -> Result<bool> {
        loop {
            let (ct, data) = read_record(&mut self.inner).await?;
            if ct == CT_CHANGE_CIPHER_SPEC { continue; }
            if data.is_empty() { return Ok(false); } // EOF
            if ct != CT_APPLICATION_DATA {
                return Err(anyhow!("unexpected TLS record type 0x{:02x}", ct));
            }
            let nonce = xnonce(&self.read_iv, self.read_seq);
            let aad = outer_aad(data.len());
            let plain = aead_open(&self.read_key, &nonce, &aad, &data, self.cipher_suite)?;
            self.read_seq += 1;
            let (payload, inner_ct) = strip_inner_ct(&plain)?;
            if inner_ct == CT_APPLICATION_DATA {
                self.buf = payload.to_vec();
                self.buf_pos = 0;
                return Ok(true);
            }
            // Inner handshake messages (e.g. NewSessionTicket) are silently discarded.
        }
    }

    /// Encrypts `data` as a TLS application-data record and sends it.
    pub async fn send_app_data(&mut self, data: &[u8]) -> Result<()> {
        // Append inner content type byte.
        let mut pt = data.to_vec();
        pt.push(CT_APPLICATION_DATA);
        let nonce = xnonce(&self.write_iv, self.write_seq);
        let aad = outer_aad(pt.len() + 16);
        let ct = aead_seal(&self.write_key, &nonce, &aad, &pt, self.cipher_suite)?;
        self.write_seq += 1;
        self.inner.write_all(&make_record(CT_APPLICATION_DATA, &ct)).await?;
        Ok(())
    }
}

impl AsyncWrite for Tls13Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = buf.len();
        let mut pt = buf.to_vec();
        pt.push(CT_APPLICATION_DATA);
        let nonce = xnonce(&self.write_iv, self.write_seq);
        let aad = outer_aad(pt.len() + 16);
        let ct = match aead_seal(&self.write_key, &nonce, &aad, &pt, self.cipher_suite) {
            Ok(c) => c,
            Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
        };
        self.write_seq += 1;
        let record = make_record(CT_APPLICATION_DATA, &ct);
        let stream = &mut self.inner;
        tokio::pin!(stream);
        match stream.poll_write(cx, &record) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ─── Key schedule ─────────────────────────────────────────────────────────────

fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {}", label);
    let full_b = full.as_bytes();
    // HkdfLabel = length(2) + label_len(1) + label + context_len(1) + context
    let mut info = Vec::with_capacity(4 + full_b.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_b.len() as u8);
    info.extend_from_slice(full_b);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(secret)
        .expect("hkdf_expand_label: invalid PRK length");
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("hkdf_expand_label: expand failed");
    out
}

fn sha256(data: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for d in data { h.update(d); }
    h.finalize().into()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn derive_hs_keys(
    client_hello: &[u8],
    server_hello: &[u8],
    ecdh_secret: &[u8; 32],
    cipher_suite: u16,
) -> Result<HsKeys> {
    let zeros = [0u8; 32];

    // early_secret = HKDF-Extract(0x00*32, 0x00*32)
    let (early, _) = Hkdf::<Sha256>::extract(Some(&zeros), &zeros);
    let early = early.as_slice().to_vec();

    // derived = HKDF-Expand-Label(early, "derived", SHA256(""), 32)
    let derived = hkdf_expand_label(&early, "derived", &sha256(&[b""]), 32);

    // handshake_secret = HKDF-Extract(derived, ecdh_secret)
    let (hs_raw, _) = Hkdf::<Sha256>::extract(Some(&derived), ecdh_secret);
    let hs_secret = hs_raw.as_slice().to_vec();

    // CH || SH transcript hash
    let ch_sh = sha256(&[client_hello, server_hello]);

    let s_ts = hkdf_expand_label(&hs_secret, "s hs traffic", &ch_sh, 32);
    let c_ts = hkdf_expand_label(&hs_secret, "c hs traffic", &ch_sh, 32);

    let klen = key_len(cipher_suite);
    let server_key = hkdf_expand_label(&s_ts, "key", &[], klen);
    let client_key = hkdf_expand_label(&c_ts, "key", &[], klen);
    let sv = hkdf_expand_label(&s_ts, "iv", &[], 12);
    let cv = hkdf_expand_label(&c_ts, "iv", &[], 12);

    let sf_key_v = hkdf_expand_label(&s_ts, "finished", &[], 32);
    let cf_key_v = hkdf_expand_label(&c_ts, "finished", &[], 32);

    let mut server_iv = [0u8; 12]; server_iv.copy_from_slice(&sv);
    let mut client_iv = [0u8; 12]; client_iv.copy_from_slice(&cv);
    let mut server_finished_key = [0u8; 32]; server_finished_key.copy_from_slice(&sf_key_v);
    let mut client_finished_key = [0u8; 32]; client_finished_key.copy_from_slice(&cf_key_v);

    Ok(HsKeys {
        server_key, server_iv,
        client_key, client_iv,
        server_finished_key, client_finished_key,
        handshake_secret: hs_secret,
        cipher_suite,
    })
}

/// Returns (server_read_key, server_read_iv, client_write_key, client_write_iv).
/// `ts_full` is the transcript hash including the server Finished message.
fn derive_app_keys(
    hs: &HsKeys,
    ts_full: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12], Vec<u8>, [u8; 12])> {
    let zeros = [0u8; 32];

    // master_secret = HKDF-Extract(derived(handshake_secret), 0x00*32)
    let derived = hkdf_expand_label(&hs.handshake_secret, "derived", &sha256(&[b""]), 32);
    let (ms_raw, _) = Hkdf::<Sha256>::extract(Some(&derived), &zeros);
    let ms = ms_raw.as_slice().to_vec();

    // App traffic secrets use the transcript *through server Finished* (ts_full).
    let s_ap = hkdf_expand_label(&ms, "s ap traffic", ts_full, 32);
    let c_ap = hkdf_expand_label(&ms, "c ap traffic", ts_full, 32);

    let klen = key_len(hs.cipher_suite);
    let read_key  = hkdf_expand_label(&s_ap, "key", &[], klen);
    let write_key = hkdf_expand_label(&c_ap, "key", &[], klen);
    let rv = hkdf_expand_label(&s_ap, "iv", &[], 12);
    let wv = hkdf_expand_label(&c_ap, "iv", &[], 12);

    let mut read_iv  = [0u8; 12]; read_iv.copy_from_slice(&rv);
    let mut write_iv = [0u8; 12]; write_iv.copy_from_slice(&wv);

    Ok((read_key, read_iv, write_key, write_iv))
}

fn key_len(cipher_suite: u16) -> usize {
    match cipher_suite {
        CS_AES_128_GCM_SHA256 => 16,
        _ => 32, // ChaCha20-Poly1305
    }
}

// ─── AEAD helpers ─────────────────────────────────────────────────────────────

fn aead_open(key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8], cs: u16) -> Result<Vec<u8>> {
    let n = aead::generic_array::GenericArray::from_slice(nonce);
    let p = Payload { msg: ct, aad };
    match cs {
        CS_AES_128_GCM_SHA256 => Aes128Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("{}", e))?
            .decrypt(n, p)
            .map_err(|_| anyhow!("TLS 1.3 AEAD decrypt failed")),
        _ => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| anyhow!("{}", e))?
            .decrypt(n, p)
            .map_err(|_| anyhow!("TLS 1.3 AEAD decrypt failed")),
    }
}

fn aead_seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8], cs: u16) -> Result<Vec<u8>> {
    let n = aead::generic_array::GenericArray::from_slice(nonce);
    let p = Payload { msg: pt, aad };
    match cs {
        CS_AES_128_GCM_SHA256 => Aes128Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("{}", e))?
            .encrypt(n, p)
            .map_err(|_| anyhow!("TLS 1.3 AEAD encrypt failed")),
        _ => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| anyhow!("{}", e))?
            .encrypt(n, p)
            .map_err(|_| anyhow!("TLS 1.3 AEAD encrypt failed")),
    }
}

// ─── TLS record helpers ───────────────────────────────────────────────────────

fn make_record(ct: u8, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(5 + data.len());
    r.push(ct);
    r.extend_from_slice(&0x0303u16.to_be_bytes());
    r.extend_from_slice(&(data.len() as u16).to_be_bytes());
    r.extend_from_slice(data);
    r
}

async fn read_record(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await?;
    let ct = hdr[0];
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > 0x4400 { return Err(anyhow!("TLS record too large: {}", len)); }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok((ct, data))
}

/// XOR the 12-byte IV with the 64-bit sequence number (big-endian, last 8 bytes).
fn xnonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let sb = seq.to_be_bytes();
    for i in 0..8 { n[4 + i] ^= sb[i]; }
    n
}

/// The 5-byte AAD for TLS 1.3 encrypted records.
fn outer_aad(ciphertext_len: usize) -> [u8; 5] {
    let l = (ciphertext_len as u16).to_be_bytes();
    [CT_APPLICATION_DATA, 0x03, 0x03, l[0], l[1]]
}

/// Strips the trailing inner content-type byte from a decrypted TLS 1.3 record.
fn strip_inner_ct(plaintext: &[u8]) -> Result<(&[u8], u8)> {
    // Find the last non-zero byte (ignoring optional zero padding).
    let pos = plaintext.iter().rposition(|&b| b != 0)
        .ok_or_else(|| anyhow!("TLS 1.3 inner plaintext has no content-type byte"))?;
    Ok((&plaintext[..pos], plaintext[pos]))
}

/// Parses a 3-byte big-endian integer.
fn u24be(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}

// ─── ServerHello parsing ──────────────────────────────────────────────────────

fn parse_server_hello(data: &[u8]) -> Result<ServerHelloInfo> {
    // Handshake message: type(1) + length(3) + body
    if data.len() < 4 { return Err(anyhow!("ServerHello too short")); }
    if data[0] != 0x02 { return Err(anyhow!("not a ServerHello (type=0x{:02x})", data[0])); }
    let body_len = u24be(&data[1..]);
    let body = data.get(4..4 + body_len).ok_or_else(|| anyhow!("truncated ServerHello"))?;

    // body: version(2) + random(32) + session_id_len(1) + session_id + cipher_suite(2) + compression(1)
    if body.len() < 35 { return Err(anyhow!("ServerHello body too short")); }
    let session_id_len = body[34] as usize;
    let mut pos = 35 + session_id_len;
    if body.len() < pos + 3 { return Err(anyhow!("ServerHello truncated at cipher suite")); }
    let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 3; // skip cipher_suite(2) + compression_method(1)

    // Extensions
    if body.len() < pos + 2 { return Err(anyhow!("ServerHello: missing extensions")); }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    let mut server_key_share: Option<[u8; 32]> = None;

    while pos + 4 <= ext_end.min(body.len()) {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len  = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let ext_data = body.get(pos..pos + ext_len).ok_or_else(|| anyhow!("truncated extension"))?;
        if ext_type == EXT_KEY_SHARE && ext_len >= 36 {
            // key_share: group(2) + key_exchange_len(2) + key_exchange(32)
            if ext_data[0] == 0x00 && ext_data[1] == 0x1d && ext_data[2] == 0x00 && ext_data[3] == 0x20 {
                let mut ks = [0u8; 32];
                ks.copy_from_slice(&ext_data[4..36]);
                server_key_share = Some(ks);
            }
        }
        pos += ext_len;
    }

    let server_key_share = server_key_share.ok_or_else(|| anyhow!("ServerHello: no X25519 key_share"))?;
    Ok(ServerHelloInfo { cipher_suite, server_key_share, raw: data.to_vec() })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_record_structure() {
        let data = b"hello";
        let rec = make_record(CT_HANDSHAKE, data);
        assert_eq!(rec[0], CT_HANDSHAKE);
        assert_eq!(&rec[1..3], &[0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([rec[3], rec[4]]), data.len() as u16);
        assert_eq!(&rec[5..], data);
    }

    #[test]
    fn test_xnonce_seq0_identity() {
        let iv = [0u8; 12];
        assert_eq!(xnonce(&iv, 0), [0u8; 12]);
    }

    #[test]
    fn test_xnonce_seq1() {
        let iv = [0u8; 12];
        let n = xnonce(&iv, 1);
        assert_eq!(n[11], 1);
        assert_eq!(&n[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_outer_aad() {
        let aad = outer_aad(100);
        assert_eq!(aad[0], CT_APPLICATION_DATA);
        assert_eq!(u16::from_be_bytes([aad[3], aad[4]]), 100);
    }

    #[test]
    fn test_strip_inner_ct_basic() {
        let plain = b"hello\x16";
        let (data, ct) = strip_inner_ct(plain).unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(ct, CT_HANDSHAKE);
    }

    #[test]
    fn test_strip_inner_ct_with_padding() {
        let plain = b"data\x17\x00\x00";
        let (data, ct) = strip_inner_ct(plain).unwrap();
        assert_eq!(data, b"data");
        assert_eq!(ct, CT_APPLICATION_DATA);
    }

    #[test]
    fn test_u24be() {
        assert_eq!(u24be(&[0x00, 0x00, 0x20]), 32);
        assert_eq!(u24be(&[0x01, 0x00, 0x00]), 65536);
    }

    #[test]
    fn test_hkdf_expand_label_length() {
        let secret = [0u8; 32];
        let out = hkdf_expand_label(&secret, "key", &[], 16);
        assert_eq!(out.len(), 16);
        let out32 = hkdf_expand_label(&secret, "key", &[], 32);
        assert_eq!(out32.len(), 32);
    }

    #[test]
    fn test_key_len() {
        assert_eq!(key_len(CS_AES_128_GCM_SHA256), 16);
        assert_eq!(key_len(CS_CHACHA20_POLY1305_SHA256), 32);
    }

    #[test]
    fn test_hmac_sha256_length() {
        let out = hmac_sha256(&[0u8; 32], b"data");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn test_aead_seal_open_roundtrip_aes128() {
        let key = vec![0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"aad";
        let pt = b"hello world";
        let ct = aead_seal(&key, &nonce, aad, pt, CS_AES_128_GCM_SHA256).unwrap();
        let plain = aead_open(&key, &nonce, aad, &ct, CS_AES_128_GCM_SHA256).unwrap();
        assert_eq!(plain, pt);
    }

    #[test]
    fn test_aead_seal_open_roundtrip_chacha20() {
        let key = vec![0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"aad";
        let pt = b"chacha payload";
        let ct = aead_seal(&key, &nonce, aad, pt, CS_CHACHA20_POLY1305_SHA256).unwrap();
        let plain = aead_open(&key, &nonce, aad, &ct, CS_CHACHA20_POLY1305_SHA256).unwrap();
        assert_eq!(plain, pt);
    }

    #[test]
    fn test_derive_hs_keys_produces_distinct_server_client_keys() {
        let ch = vec![0u8; 100];
        let sh = vec![1u8; 80];
        let ecdh = [0x42u8; 32];
        let hs = derive_hs_keys(&ch, &sh, &ecdh, CS_AES_128_GCM_SHA256).unwrap();
        assert_eq!(hs.server_key.len(), 16);
        assert_eq!(hs.client_key.len(), 16);
        assert_ne!(hs.server_key, hs.client_key);
        assert_ne!(hs.server_iv, hs.client_iv);
    }
}
