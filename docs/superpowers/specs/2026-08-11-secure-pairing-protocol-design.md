# Secure Pairing Protocol — Design

Date: 2026-08-11
Status: Approved by user, ready for implementation planning

## Problem

The current Bluetooth chat app (`bluetooth_chat_app`) protects messages with a single
shared passphrase (`SecurityService`) that the user types by hand and that both devices
must already agree on out of band. Consequences of the current design:

- No device authentication: any BLE peer that also knows (or guesses) the passphrase
  can impersonate either side. There is no proof of *which* device you are talking to.
- `IV.fromLength(16)` in both `BluetoothChatService` and `ChatStorageService` produces a
  **fixed, all-zero IV** reused for every AES-CBC encryption — a real confidentiality bug
  (identical plaintexts leak identical ciphertext prefixes, and CBC malleability is
  unmitigated since there is no MAC).
- No replay protection: a captured encrypted frame can be replayed into a new session
  and will decrypt successfully because the key never changes.
- No transcript/session binding: nothing stops a captured handshake or message from
  being replayed, reordered, or spliced.
- Manual passphrase entry is required before two devices can talk at all.

## Goals

1. Mutual device authentication: both sides cryptographically prove which long-term
   identity they are, every connection.
2. A stricter exchange protocol: authenticated key agreement with forward secrecy
   (fresh session keys every connection), replacing the static shared-secret cipher.
3. Protection against spoofing and replay: AEAD encryption, strictly-increasing
   per-direction counters, and long-term identity keys that can't be forged without the
   private key.
4. No mandatory manual key entry to start chatting. Optional out-of-band QR verification
   available for users who want cryptographic proof they aren't being MITM'd, but not
   required for the basic flow (which stays: browse nearby BLE devices → tap Connect).

Non-goals: this is not a formally verified/audited protocol (e.g. full Noise Protocol
Framework compliance). It borrows established patterns (ephemeral X25519 ECDH,
Ed25519 identity signatures, HKDF key separation, AEAD with counter nonces, TOFU trust
model) but is a purpose-built implementation for this app, not a drop-in of a certified
library. That tradeoff is acceptable for this project's scope.

## Architecture Overview

```
 IdentityService        long-term Ed25519 keypair per device (secure storage)
        |
 TrustStoreService      known peer identity pubkeys, TOFU state, verified flag (sqlite)
        |
 SecureChannelService   handshake state machine + per-message AEAD encrypt/decrypt
        |                (transport-agnostic: takes byte-send/receive callbacks)
        |
 BluetoothChatService   BLE transport + binary framing, drives SecureChannelService,
        |                exposes channel-state / trust-event streams to UI
        |
 ChatScreen             connect flow now blocks on handshake, shows trust dialogs,
                         "Verify safety" QR entry point
        |
 SafetyVerificationScreen   show own QR + scan peer's QR, compares against live session
```

`SecurityService` is repurposed to manage only a local, never-shared, random master key
used for at-rest database encryption (unrelated to peer identity or session keys).

## Cryptographic Design

**Primitives** (via the `cryptography` pub package, pure-Dart + platform-accelerated
where available):
- Identity keys: **Ed25519** (signing).
- Ephemeral key agreement: **X25519** (ECDH).
- KDF: **HKDF-SHA256**.
- AEAD: **ChaCha20-Poly1305** (chosen over AES-GCM for consistent performance without
  depending on AES-NI on low/mid-range Android hardware).

**Identity keys.** Generated once per install by `IdentityService`, private key stored
in `flutter_secure_storage`, never transmitted. The Ed25519 public key is the device's
durable "identity" — independent of BLE MAC address (which can rotate).

**Handshake (per BLE connection).** Roles: *initiator* (taps "Connect"), *responder*
(already listening/advertising). Both generate a fresh X25519 ephemeral keypair for this
session only.

1. **Hello** (initiator → responder):
   `initiator_identity_pub (32B) | initiator_ephemeral_pub (32B) | nonce_i (16B) | timestamp`
2. **Response** (responder → initiator):
   `responder_identity_pub | responder_ephemeral_pub | nonce_r | timestamp | sig_r`
   where `sig_r = Ed25519.sign(responder_identity_priv, transcript)` and
   `transcript = nonce_i ‖ epk_i ‖ epk_r ‖ nonce_r`.
   Responder computes `shared_secret = X25519(esk_r, epk_i)`.
3. **Finished** (initiator → responder):
   Initiator verifies `sig_r` against `responder_identity_pub` (looked up / TOFU-prompted
   via `TrustStoreService`, see below). Computes the same `shared_secret =
   X25519(esk_i, epk_r)`. Sends `sig_i = Ed25519.sign(initiator_identity_priv,
   transcript)` — this is what makes authentication **mutual**: the responder now also
   verifies the initiator's identity. Also includes an AEAD-encrypted empty "confirm"
   payload keyed by the derived traffic key, so both sides positively confirm they
   derived matching keys (a TLS-Finished-style check) before any real data is sent.

   Both sides reject the handshake (and tear down the connection) if:
   - the timestamp is more than 2 minutes outside local clock (defense in depth against
     stale/replayed handshake messages),
   - the signature doesn't verify,
   - the responder's identity is known-but-changed and the user hasn't re-confirmed.

4. **Key derivation.** `HKDF-SHA256(shared_secret, salt = nonce_i ‖ nonce_r, info =
   "i2r" | "r2i")` produces two independent 32-byte traffic keys, one per direction —
   avoids both directions ever reusing a nonce under the same key.

**Why this stops replay/spoofing:**
- Every connection uses fresh ephemeral keys, so the shared secret (and thus traffic
  keys) differ every session. A captured ciphertext from a past session fails AEAD
  authentication under a new session's keys — replaying old traffic into a new session
  is not possible.
- Within a session, each direction keeps a strictly-increasing 64-bit counter used to
  build the AEAD nonce (`00000000 ‖ counter`, big-endian). The receiver requires the
  counter to equal `lastAccepted + 1`; anything else (duplicate, reordered, injected) is
  rejected and the connection is dropped. This is safe here because the existing BLE
  transport already serializes writes one-at-a-time (see `_writeBytes`'s delay) — there
  is no legitimate reordering to accommodate.
- Spoofing a device's identity requires forging an Ed25519 signature, i.e. the private
  identity key — not feasible without it.

## Trust Model (TOFU + change warning)

New sqlite table `trusted_peers`, keyed by identity public key (base64) — not by BLE
address, since BLE addresses can rotate:

```sql
CREATE TABLE trusted_peers (
  identity_pubkey TEXT PRIMARY KEY,
  ble_id TEXT,
  display_name TEXT,
  first_seen TEXT,
  last_seen TEXT,
  verified INTEGER DEFAULT 0
)
```

- **New device** (identity pubkey never seen before): after a successful handshake,
  `BluetoothChatService` emits a `TrustEvent(isNew: true, ...)`. `ChatScreen` shows a
  dialog: "New device — trust and start chatting?" Accepting inserts a row
  (`verified = 0`). This is the TOFU step — normal flow, not a blocker.
- **Known device, same identity key**: silent — proceeds straight to `established`.
- **Known BLE id, but a *different* identity key than previously recorded for it**:
  `TrustEvent(isChanged: true, ...)`. `ChatScreen` shows a hard warning dialog ("Device
  key changed — this could mean the app was reinstalled, or an attack. Continue only if
  you're sure.") and requires explicit re-confirmation before the connection is usable.
  No silent auto-accept.

## Optional QR / Live Verification

Accessible from the chat via a "Verify safety" action once a session is `established`
(not a separate pairing screen, not required to start chatting):

- `SafetyVerificationScreen` renders own identity pubkey as a QR (via `qr_flutter`) plus
  a short numeric fingerprint (`SHA-256(identity_pub)` truncated, grouped like a Signal
  safety number) for manual comparison as a fallback if the camera is unavailable.
- A "Scan" button opens `mobile_scanner`; the scanned bytes are compared directly
  against the identity public key actually used in the *live, currently-connected*
  session (not just "whatever the QR says") — so a match cryptographically proves you're
  talking to the physical device you scanned, not a relay/MITM. Match sets
  `verified = 1` on the trust-store row; mismatch shows a red warning and leaves
  `verified = 0`.

## Wire Framing

Replaces the current ASCII `TYPE|len\n` + payload scheme (fragile: a literal `\n` byte
inside binary handshake/ciphertext would corrupt parsing) with fixed binary framing:

```
[1 byte frame type][4 bytes big-endian length][payload...]
```

Frame types: `0x01 HELLO`, `0x02 RESPONSE`, `0x03 FINISHED`, `0x04 DATA`.

`DATA` frame payload is the AEAD ciphertext of an inner plaintext:
`[1 byte inner type: 0=MSG,1=FILE][8 byte counter][content]`
(`FILE` content = `[2-byte name length][name bytes][file bytes]`). The counter is
authenticated as associated data even though it's also encoded in the nonce, so tampering
with it is detected even if nonce handling ever changes.

`BluetoothChatService._handleIncomingBytes` is rewritten around this fixed-size header
parser instead of newline scanning. Per-direction counters start at `0` for the first
`DATA` frame after the handshake completes and increment by one per frame; the
handshake's own `Finished`-confirm payload is encrypted separately (counter space
`0` reserved for it, `DATA` counters start at `0` independently per direction after
that) so handshake framing and chat framing never share nonce space ambiguity.

## Channel State Machine

`SecureChannelState`: `idle → handshaking → (awaitingTrustConfirmation |
identityMismatch)? → established`, or `failed` from any state on a validation error.
`BluetoothChatService.sendMessage`/`sendFile` are no-ops (throw) unless the current
state is `established`. `ChatScreen` subscribes to state changes to drive the connect
button, a handshake progress indicator, and the trust dialogs described above.

## Local Storage Changes

- `SecurityService` no longer manages a shared/typed passphrase. It generates (once) a
  random 32-byte local master key, stored in `flutter_secure_storage`, used **only** for
  at-rest encryption of the local chat database. It is never transmitted or derived from
  anything peer-related.
- `ChatStorageService` switches from AES-CBC with the fixed zero IV to ChaCha20-Poly1305
  with a fresh random 12-byte nonce per encrypted field, using the local master key.
- `ProfileScreen` loses the "Ключ безопасности" (shared passphrase) card entirely — there
  is nothing for the user to type or share by hand anymore.
- DB schema version bumps; `onUpgrade` drops and recreates `chat_messages` (old rows are
  encrypted under a scheme/key that no longer exists and can't be migrated). Acceptable
  because this is pre-release starter-app local data, per user confirmation.

## New/Changed Files

New:
- `lib/services/identity_service.dart`
- `lib/services/trust_store_service.dart`
- `lib/services/secure_channel_service.dart`
- `lib/screens/safety_verification_screen.dart`
- `lib/models/trusted_peer.dart`
- `lib/models/secure_channel_state.dart`

Changed:
- `pubspec.yaml` — add `cryptography`, `qr_flutter`, `mobile_scanner`
- `lib/services/security_service.dart` — repurposed to local master key only
- `lib/services/chat_storage_service.dart` — AEAD + random nonce, drop passphrase param
- `lib/services/bluetooth_chat_service.dart` — binary framing, handshake integration,
  trust/channel-state streams, gate `sendMessage`/`sendFile` on `established` state
- `lib/screens/chat_screen.dart` — handshake progress UI, trust dialogs, "Verify safety"
  entry point, drop passphrase plumbing
- `lib/screens/profile_screen.dart` — remove passphrase card

## Testing Plan

Real BLE hardware isn't available in this environment, so:
- **Automated**: pure-Dart unit tests for `SecureChannelService` using an in-memory
  loopback (two instances wired directly to each other's byte streams, no BLE). Cases:
  successful handshake + bidirectional message exchange; rejected forged signature;
  rejected replayed/duplicated counter; rejected tampered ciphertext; identity-changed
  detection surfaces the right trust event.
- **Manual** (documented, not run by me): once on real devices, verify the full
  discover → connect → TOFU prompt → chat → "Verify safety" QR scan flow end to end, and
  the "identity changed" warning by clearing one device's secure storage and
  reconnecting under the same BLE identity.
