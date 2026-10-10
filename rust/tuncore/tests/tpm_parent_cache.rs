//! swtpm tests for the TPM attest key's kept connection.
//!
//! Through a resource manager (`/dev/tpmrm0`) a `TpmAttestKey` keeps one TPM
//! connection, with its parent key loaded, so a sign skips making the parent
//! again. swtpm serves one connection at a time, like a raw `/dev/tpm0`, so a
//! key there keeps no connection unless a test turns it on; the tests that do
//! use one key per swtpm and nothing else on it while it is kept. The harness
//! is a small copy of the one in `tpm_swtpm.rs`, plus a TPM reset and a
//! restart, so that file stays as it is.
#![cfg(feature = "tpm-attest")]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use tuncore::device_attest_tpm::TpmAttestKey;

/// Max time to wait for the swtpm command port to start accepting.
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll interval while waiting for the command port.
const READINESS_POLL: Duration = Duration::from_millis(20);
/// A step that would hang if a key still held its connection (swtpm keeps a
/// second connection waiting) fails after this long instead.
const NO_HANG: Duration = Duration::from_secs(20);

/// RAII swtpm instance: per-test state dir and a `swtpm socket` child.
struct Swtpm {
    child: Child,
    state_dir: PathBuf,
    tcti: String,
    port: u16,
}

impl Swtpm {
    fn start() -> Self {
        let state_dir = unique_state_dir();
        std::fs::create_dir_all(&state_dir).expect("create swtpm state dir");
        let setup = Command::new("swtpm_setup")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(&state_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn swtpm_setup (is swtpm installed?)");
        assert!(setup.success(), "swtpm_setup failed to author TPM state");
        let port = free_port_pair();
        let child = spawn_swtpm(&state_dir, port);
        let me = Self {
            child,
            state_dir,
            tcti: format!("swtpm:host=127.0.0.1,port={port}"),
            port,
        };
        me.wait_until_ready();
        me
    }

    /// Reset the TPM through swtpm's control channel, as a power cycle of
    /// the chip would: every loaded object is gone and the TPM wants a
    /// `TPM2_Startup` again. Open connections stay open.
    fn reset(&self) {
        let status = Command::new("swtpm_ioctl")
            .arg("--tcp")
            .arg(format!("127.0.0.1:{}", self.port + 1))
            .arg("-i")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn swtpm_ioctl (is swtpm installed?)");
        assert!(status.success(), "swtpm_ioctl -i failed");
    }

    /// Kill swtpm and start it again on the same ports and state, as a
    /// resource manager that restarts looks to its clients: every connection
    /// breaks and every loaded object is gone. Keys made before still load
    /// (same state, so the same parent seed).
    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = spawn_swtpm(&self.state_dir, self.port);
        self.wait_until_ready();
    }

    /// Bounded poll-connect on the command port; never a fixed sleep.
    fn wait_until_ready(&self) {
        let deadline = Instant::now() + READINESS_TIMEOUT;
        loop {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "swtpm did not start accepting on 127.0.0.1:{} within {:?}",
                self.port,
                READINESS_TIMEOUT
            );
            thread::sleep(READINESS_POLL);
        }
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        // Best effort; never panic in Drop.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

fn spawn_swtpm(state_dir: &Path, port: u16) -> Child {
    Command::new("swtpm")
        .arg("socket")
        .arg("--tpm2")
        .arg("--flags")
        .arg("not-need-init,startup-clear")
        .arg("--tpmstate")
        .arg(format!("dir={}", state_dir.display()))
        .arg("--server")
        .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
        .arg("--ctrl")
        .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn swtpm (is it installed?)")
}

/// A per-test temp state dir, unique across processes and quick calls.
fn unique_state_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("dsm-swtpm-cache-{}-{}", std::process::id(), nanos))
}

/// A free loopback port pair (`p`, `p + 1`): swtpm's control channel is at
/// `p + 1`. A small window remains after the probes close; fine for tests.
fn free_port_pair() -> u16 {
    for _ in 0..50 {
        let Ok(primary) = TcpListener::bind("127.0.0.1:0") else {
            continue;
        };
        let p = primary
            .local_addr()
            .expect("local_addr of ephemeral listener")
            .port();
        if p == u16::MAX {
            continue;
        }
        if let Ok(successor) = TcpListener::bind(("127.0.0.1", p + 1)) {
            drop(successor);
            drop(primary);
            return p;
        }
    }
    panic!("could not reserve a free consecutive TCP port pair for swtpm");
}

/// A new key on `tpm` that keeps its connection, as on `/dev/tpmrm0`.
fn kept_key(tpm: &Swtpm) -> TpmAttestKey {
    let mut key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    assert!(
        !key.keeps_connection(),
        "swtpm serves one connection at a time: off by default"
    );
    key.set_keep_connection(true);
    key
}

fn assert_verifies(key: &TpmAttestKey, msg: &[u8], sig_der: &[u8]) {
    let vk =
        VerifyingKey::from_public_key_der(key.public_spki_der().expect("spki")).expect("parse vk");
    let sig = Signature::from_der(sig_der).expect("parse DER signature");
    vk.verify(msg, &sig)
        .expect("signature must verify under the key's SPKI");
}

/// Run `f` on its own thread; fail instead of hanging the suite if it does
/// not finish within `NO_HANG` (a connection still held by a key would make
/// swtpm keep a new one waiting forever).
fn within_time<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(NO_HANG).unwrap_or_else(|_| {
        panic!("{what} did not finish in {NO_HANG:?} (a TPM connection still held?)")
    })
}

/// Make and use a second key on `tpm` from another thread. It reaches the
/// TPM only if no other connection is held.
fn reach_tpm(tpm: &Swtpm, when: &str) {
    let tcti = tpm.tcti.clone();
    within_time(when, move || {
        let other = TpmAttestKey::generate_with_tcti(&tcti).expect("generate a second key");
        other.sign(b"second key").expect("sign with a second key");
    });
}

#[test]
fn without_a_kept_connection_each_sign_makes_its_parent() {
    let tpm = Swtpm::start();
    let key = TpmAttestKey::generate_with_tcti(&tpm.tcti).expect("generate");
    assert!(!key.keeps_connection());
    for i in 0..3 {
        let msg = format!("per-sign parent {i}");
        let sig = key.sign(msg.as_bytes()).expect("sign");
        assert_verifies(&key, msg.as_bytes(), &sig);
    }
    assert_eq!(
        key.parents_made(),
        3,
        "without a kept connection every sign makes its parent"
    );
}

#[test]
fn only_a_resource_manager_tcti_keeps_the_connection() {
    let tpm = Swtpm::start();
    let blob = TpmAttestKey::generate_with_tcti(&tpm.tcti)
        .expect("generate")
        .to_store_blob()
        .expect("blob");
    for (tcti, keeps) in [
        ("device:/dev/tpmrm0", true),
        ("device:/dev/tpmrm1", true),
        ("tabrmd", true),
        ("tabrmd:bus_type=system", true),
        ("device:/dev/tpm0", false),
        ("device", false),
        ("mssim:host=localhost,port=2321", false),
        (tpm.tcti.as_str(), false),
    ] {
        // Restoring a blob does not touch the TPM, so any TCTI string works.
        let key = TpmAttestKey::from_store_blob_with_tcti(&blob, tcti).expect("restore");
        assert_eq!(key.keeps_connection(), keeps, "{tcti}");
    }
}

#[test]
fn a_kept_connection_makes_the_parent_once() {
    let tpm = Swtpm::start();
    let key = kept_key(&tpm);
    for i in 0..10 {
        let msg = format!("kept parent {i}");
        let sig = key
            .sign(msg.as_bytes())
            .expect("sign on the kept connection");
        assert_verifies(&key, msg.as_bytes(), &sig);
    }
    // Ten signs on a TPM with about three object slots also prove the child
    // is flushed after each sign while the parent stays.
    assert_eq!(key.parents_made(), 1, "ten signs, one parent");
}

#[test]
fn a_kept_connection_comes_back_after_a_tpm_reset() {
    let tpm = Swtpm::start();
    let key = kept_key(&tpm);
    key.sign(b"before the reset").expect("first sign");
    tpm.reset();
    let msg = b"after the reset";
    let sig = key
        .sign(msg)
        .expect("the sign after a reset must recover on a new connection");
    assert_verifies(&key, msg, &sig);
    assert_eq!(key.parents_made(), 2, "one new parent for the recovery");
    key.sign(b"and the next one")
        .expect("the new connection is kept");
    assert_eq!(key.parents_made(), 2);
}

#[test]
fn a_kept_connection_comes_back_after_the_tpm_restarts() {
    let mut tpm = Swtpm::start();
    let key = Arc::new(kept_key(&tpm));
    key.sign(b"before the restart").expect("first sign");
    tpm.restart();
    let signer = Arc::clone(&key);
    let sig = within_time("the sign after a restart", move || {
        signer
            .sign(b"after the restart")
            .expect("the sign after a restart must recover on a new connection")
    });
    assert_verifies(&key, b"after the restart", &sig);
    assert_eq!(key.parents_made(), 2, "one new parent for the recovery");
}

#[test]
fn a_wrong_passphrase_is_never_tried_twice() {
    let tpm = Swtpm::start();
    let blob = TpmAttestKey::generate_with_tcti(&tpm.tcti)
        .expect("generate")
        .encrypt_to_store(b"the right passphrase")
        .expect("bind the passphrase");
    let mut key =
        TpmAttestKey::decrypt_from_store_with_tcti(&blob, &tpm.tcti, b"a wrong passphrase")
            .expect("parse (a wrong passphrase still parses)");
    key.set_keep_connection(true);
    for round in 0..2 {
        let err = key
            .sign(b"must not sign")
            .expect_err("a wrong passphrase must not sign");
        assert!(
            err.to_ascii_lowercase().contains("authorization"),
            "round {round}: {err}"
        );
    }
    // The second failure was on the kept connection. A retry would have made
    // a second parent; a refused authorization is never retried, because the
    // TPM counts each refused try toward its lockout.
    assert_eq!(key.parents_made(), 1);
}

#[test]
fn another_error_on_a_kept_connection_is_tried_once_more() {
    // A key from another TPM: loading it fails with an integrity error, not
    // a refused authorization, on every connection.
    let other = Swtpm::start();
    let blob = TpmAttestKey::generate_with_tcti(&other.tcti)
        .expect("generate on the other TPM")
        .to_store_blob()
        .expect("blob");
    let tpm = Swtpm::start();
    let mut key = TpmAttestKey::from_store_blob_with_tcti(&blob, &tpm.tcti)
        .expect("restore (no TPM call yet)");
    key.set_keep_connection(true);
    for round in 1..=3_u64 {
        let err = key
            .sign(b"must not sign")
            .expect_err("a key from another TPM must not sign");
        assert!(
            err.to_ascii_lowercase().contains("integrity check failed"),
            "round {round}: {err}"
        );
        // The first sign had no kept connection: it made one parent and kept
        // that connection. Each later sign failed on the kept connection,
        // then once more on a new one: one new parent per sign, never more.
        assert_eq!(key.parents_made(), round, "round {round}");
    }
}

#[test]
fn signs_from_several_threads_take_turns() {
    let tpm = Swtpm::start();
    let key = Arc::new(kept_key(&tpm));
    let workers: Vec<_> = (0..4)
        .map(|t| {
            let key = Arc::clone(&key);
            thread::spawn(move || {
                for i in 0..3 {
                    let msg = format!("thread {t} sign {i}");
                    let sig = key.sign(msg.as_bytes()).expect("sign from a thread");
                    assert_verifies(&key, msg.as_bytes(), &sig);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("a signing thread panicked");
    }
    assert_eq!(
        key.parents_made(),
        1,
        "twelve signs from four threads, one kept connection"
    );
}

#[test]
fn the_kept_connection_closes_on_zeroize_drop_and_turning_it_off() {
    let tpm = Swtpm::start();

    let mut key = kept_key(&tpm);
    key.sign(b"open the kept connection").expect("sign");
    key.zeroize();
    reach_tpm(&tpm, "a second key after zeroize");

    let key = kept_key(&tpm);
    key.sign(b"open the kept connection").expect("sign");
    drop(key);
    reach_tpm(&tpm, "a second key after drop");

    let mut key = kept_key(&tpm);
    key.sign(b"open the kept connection").expect("sign");
    key.set_keep_connection(false);
    assert!(!key.keeps_connection());
    reach_tpm(&tpm, "a second key after turning the kept connection off");
}
