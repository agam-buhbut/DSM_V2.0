# DSM Offline CA Runbook

This runbook covers the operational lifecycle of the DSM internal CA that
issues device certs for clients and servers. The CA is the **single root of
trust** for the DSM fleet; if the CA private key is compromised, the entire
fleet must be reissued.

## Threat model summary

The CA private key never leaves an air-gapped laptop. Devices walk CSRs and
signed certs over USB. Network compromise of any DSM host does not give an
attacker the ability to mint new certs. Cold-storage backup theft of a
device's `identity.key` + `attest.key` does not enable impersonation
because the daemon refuses to start without the matching cert AND because
the CSR signature requires live access to the attest private key (already
on the laptop you stole, but in production this is a hardware-bound TPM
key that cannot leave the device).

Out of scope: physical compromise of the CA laptop, supply-chain
compromise of the OS image installed on the CA laptop, side-channel
attacks against the CA private key during signing.

## Required hardware / setup

- **CA laptop**: dedicated machine, never connected to a network after
  initial OS install. Disk encryption (LUKS) required. Live image OK
  (Tails) or a thin Debian install with the wifi card physically removed.
- **Encrypted USB drives**: at least three, holding the CA private key
  + database. The drive label and per-drive passphrase are stored in a
  physical safe alongside the printed root cert SHA-256 fingerprint.
- **Transport USB**: separate from the CA storage USBs. Wiped (`shred -v`)
  between every walk. Used to carry CSRs in and signed certs out.

## Files

- `deploy/openssl-ca.cnf` — OpenSSL config bundled with this repo. Walk
  it onto the CA laptop alongside the CA private key.
- `deploy/CA_RUNBOOK.md` — this file. Walk it too; the CA operator works
  from the printed copy in the safe.

## Custom OID

`id-dsm-noiseStaticBinding ::= 1.3.6.1.4.1.99999.1.1`

OCTET STRING of length 32, carrying the device's X25519 Noise static
pubkey. MUST be marked **critical** on every issued leaf. The DSM
runtime refuses to load a leaf where this extension is missing,
non-critical, or the wrong length. The OID lives in the IETF
"experimental" arc — replace before production fleet deployment if
your organization owns a registered Private Enterprise Number.

---

## §1. One-time CA bootstrap

Run this exactly once, on the air-gapped laptop.

```sh
# Set up directory structure
mkdir -p ca/{certs,crl,newcerts,private}
cd ca
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

# Copy openssl-ca.cnf into ca/

# Generate the CA private key (P-384, 10y validity).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out private/dsm_ca.key
chmod 600 private/dsm_ca.key

# Self-sign the CA root cert.
openssl req -config openssl-ca.cnf \
    -x509 -new -key private/dsm_ca.key \
    -days 3650 \
    -out dsm_ca_root.pem

# Compute and PRINT the SHA-256 fingerprint of the root cert. Store the
# printout in the physical safe; this is the pinning anchor that every
# server/client checks at install time.
openssl x509 -in dsm_ca_root.pem -noout -fingerprint -sha256
sha256sum dsm_ca_root.pem
```

Snapshot the entire `ca/` directory onto your encrypted USB. Make at least
two redundant copies on separate USB sticks; store at least one in a
different physical location (off-site safe or safe deposit box).

**The CA private key never leaves these USBs.** When signing, mount the
USB read-write, sign, unmount, return to the safe.

---

## §2. CA root distribution

Walk `dsm_ca_root.pem` to every DSM host (servers + clients) and place at
the path configured by `ca_root_file` (default
`/opt/mtun/dsm_ca_root.pem`, mode `0o644`, owned by root).

Cross-check the SHA-256 against the printout in the safe. Operator
records the verified hash in the host inventory.

---

## §3. Per-device enrollment

For each new device:

### 3a. On the device

```sh
dsm enroll --csr-out /tmp/dsm-csr-<hostname>.der
```

The operator chooses a passphrase that protects both the identity
keypair and the attest key (Argon2id-wrapped XChaCha20-Poly1305). Same
passphrase, both stores. Daemon at runtime reads it once via
`DSM_PASSPHRASE_FILE` (mode `0600`) or `--passphrase-fd`.

The command prints:
- the device CN (default form `dsm-<8 hex>-<role>`)
- the Noise static pubkey hex

Record both in the device inventory, alongside the request date and
operator initials.

Walk the CSR file to the CA laptop on a freshly-wiped USB.

### 3b. On the CA laptop

```sh
cd ca

# 1. Sanity-check the CSR. THIS IS THE OPERATOR'S CRITICAL REVIEW STEP.
openssl req -in /mnt/transport/dsm-csr-<hostname>.der \
    -inform DER -text -noout -verify

# Verify by eye:
#   * Subject CN matches an approved entry on the inventory
#   * "1.3.6.1.4.1.99999.1.1: critical" is present
#   * "Certificate request self-signature verify OK" appears
#   * Subject Public Key is prime256v1 (256-bit ECDSA)
#
# If any of those is missing or different, REJECT. Wipe the transport
# USB. The operator double-checks the inventory against the requester
# before retrying.

# 2. Sign with the appropriate profile.
# For client devices:
openssl ca -config openssl-ca.cnf -extensions dsm_client_leaf \
    -in /mnt/transport/dsm-csr-<hostname>.der -inform DER \
    -out certs/<hostname>.pem -batch

# For server devices, use -extensions dsm_server_leaf instead.

# 3. Walk the cert (and only the cert — never the index.txt, never the
# CA key) back on the wiped transport USB.
cp certs/<hostname>.pem /mnt/transport/

# 4. Eject, lock, return USBs to the safe.
```

### 3c. On the device

```sh
dsm enroll --import /tmp/dsm-cert-<hostname>.pem
```

The local `dsm enroll --import` re-verifies:
- chain to the pinned `ca_root_file`
- `id-dsm-noiseStaticBinding` extension matches the device's local Noise pubkey
- cert subject pubkey SPKI matches the local attest key SPKI
- cert is currently within validity

On success, the cert is written to `cert_file` (default
`/opt/mtun/device.crt`) with mode `0o600`.

If any check fails, the file is NOT written and the operator must
return to step 3b with the original CSR.

---

## §4. Cert validity & rotation

- **Default validity**: 1 year (`default_days = 365` in `openssl-ca.cnf`).
- **Rotation**: 30 days before expiry, the device runs `dsm enroll
  --csr-out` again with a fresh keypair (the existing files must be
  removed by hand; the runbook is explicit about this step). Old cert
  remains valid until expiry; the operator updates the device, then
  revokes the old cert via §5.
- Tighter validity (e.g. 90 days) is operationally recommended once the
  walked-USB CRL cadence is comfortable.

## §5. Revocation

When a device is decommissioned, lost, or compromised, the operator
revokes its cert and re-issues the CRL.

### 5a. On the CA laptop

```sh
cd ca

# Revoke the cert. Pass the cert file the laptop already has in newcerts/.
openssl ca -config openssl-ca.cnf \
    -revoke newcerts/<serial>.pem -crl_reason <reason>

# Reasons: keyCompromise, cACompromise (DO NOT USE — would invalidate
# whole fleet), affiliationChanged, superseded, cessationOfOperation,
# certificateHold, removeFromCRL.

# Generate the fresh CRL.
openssl ca -config openssl-ca.cnf -gencrl -out crl/dsm_ca.crl
```

Record the new CRL number (auto-incremented in `crlnumber`).

### 5b. Distribute

Walk `crl/dsm_ca.crl` via fresh transport USB to every DSM host that
acts as a server (and to clients that have a CRL configured). Place at
`crl_file` path (default `/opt/mtun/dsm_ca.crl`).

Reload the daemon. The current implementation reads the CRL at startup;
operator restarts the dsm service after replacing the file. (`SIGHUP`
reload is on the Phase-2 punch list.)

## §6. CRL freshness cadence

- **Default**: 31 days (`default_crl_days = 31`).
- The DSM runtime computes `now - this_update` and treats CRLs older
  than `next_update` as stale (logged as a warning, but does not refuse
  to start). Operator should refresh the CRL monthly even when there
  are no revocations to publish — a stale CRL means a revocation issued
  yesterday is not yet enforced.
- Refresh cadence is the operational lever: tighten to weekly if
  threat model demands faster revocation propagation.

## §7. Disaster recovery

If the CA private key is lost (laptop dead, all USBs corrupted) AND no
backups remain:
1. Generate a new CA per §1.
2. Walk the new root cert to every DSM host.
3. Re-enroll every device per §3.

If a device's `identity.key` or `attest.key` is suspected compromised:
1. Revoke its cert per §5 immediately.
2. Re-enroll the device with a fresh keypair (the existing on-device
   files must be removed by hand).
3. Issue the new cert. Old cert is in the CRL.

If the CA private key is suspected compromised: the entire fleet must
be reissued under a freshly-bootstrapped CA. Document the incident,
notify all stakeholders, walk the new root, re-enroll every device.

---

## Checklist (laminate, keep on the CA laptop's keyboard)

For each enrollment:
- [ ] CSR opened, `openssl req -text` inspected
- [ ] CN matches inventory entry
- [ ] Binding extension present + critical + 34 bytes
- [ ] CSR self-signature verifies
- [ ] Signed with correct profile (client vs server)
- [ ] Cert walked back on wiped transport USB
- [ ] CA private key USB unmounted, back in safe
- [ ] Inventory line updated (serial, expiry, operator initials, date)

For each CRL refresh:
- [ ] All revocations for this cycle applied
- [ ] CRL number incremented
- [ ] CRL walked to every server (and clients with CRLs)
- [ ] Daemons restarted; logs confirm new CRL loaded
