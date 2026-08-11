# Secure Pairing Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the shared-passphrase AES-CBC scheme in `bluetooth_chat_app` with mutual device authentication (Ed25519 identity + X25519 ephemeral ECDH handshake), AEAD encryption with replay-safe counters, a TOFU trust store with change-detection warnings, and an optional QR-based live safety verification — with no mandatory manual key entry.

**Architecture:** A transport-agnostic `SecureChannelService` implements the 3-message mutual-auth handshake and per-message AEAD framing, driven purely by `(FrameType, Uint8List)` callbacks so it needs no BLE to test. `BluetoothChatService` wraps it with real BLE bytes (via a small `BluetoothFrameCodec`) and a `TrustStoreService` (SQLite, keyed by identity public key) that decides whether a peer needs a TOFU prompt. `IdentityService` owns each device's long-term Ed25519 keypair. Local chat history moves from the old shared-passphrase cipher to a device-local random key. UI layers (`ChatScreen`, `ProfileScreen`, new `SafetyVerificationScreen`) are updated to match.

**Tech Stack:** Flutter/Dart, `cryptography` (Ed25519/X25519/HKDF/ChaCha20-Poly1305), `flutter_secure_storage`, `sqflite`, `qr_flutter`, `mobile_scanner`, `flutter_blue_plus` (existing), `flutter_test` for unit tests.

## Global Constraints

- No manual passphrase/key entry anywhere in the normal connect flow (per spec goal 4).
- Identity private keys never leave `flutter_secure_storage`; session/traffic keys never touch disk.
- `SecureChannelService` must be testable without Flutter platform channels or BLE (pure Dart + `cryptography`).
- Wire framing is binary (`[1 byte frame type][4 byte BE length][payload]`), replacing the old newline-delimited ASCII framing.
- DB schema bump for `chat_messages` is destructive on upgrade (old rows encrypted under the removed passphrase scheme are discarded) — confirmed acceptable by the user for this pre-release starter app.
- Reference spec: `docs/superpowers/specs/2026-08-11-secure-pairing-protocol-design.md`.

---

## Task 1: Add crypto dependencies and `IdentityService`

**Files:**
- Modify: `pubspec.yaml`
- Create: `lib/services/identity_service.dart`

**Interfaces:**
- Produces: `class IdentityService` with:
  - `IdentityService({FlutterSecureStorage? secureStorage})`
  - `@visibleForTesting IdentityService.withSeedForTesting(Uint8List seed)`
  - `Future<Uint8List> getPublicKeyBytes()`
  - `Future<Uint8List> sign(List<int> message)`
  - `Future<bool> verify(List<int> message, {required List<int> signatureBytes, required List<int> publicKeyBytes})`

- [ ] **Step 1: Add dependencies**

Run:
```bash
flutter pub add cryptography
```

- [ ] **Step 2: Verify pubspec resolved**

Run: `flutter pub get`
Expected: completes without errors; `cryptography` appears in `pubspec.lock`.

- [ ] **Step 3: Write `lib/services/identity_service.dart`**

```dart
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Manages this device's long-term Ed25519 identity keypair. The private
/// key never leaves secure storage; the public key is this device's
/// durable identity, independent of its BLE address.
class IdentityService {
  static const _seedStorageKey = 'device_identity_seed_v1';
  static const _seedLength = 32;

  final FlutterSecureStorage? _secureStorage;
  final Uint8List? _fixedSeedForTesting;
  final Ed25519 _algorithm = Ed25519();
  SimpleKeyPair? _cachedKeyPair;

  IdentityService({FlutterSecureStorage? secureStorage})
      : _secureStorage = secureStorage ?? const FlutterSecureStorage(),
        _fixedSeedForTesting = null;

  @visibleForTesting
  IdentityService.withSeedForTesting(Uint8List seed)
      : _secureStorage = null,
        _fixedSeedForTesting = seed;

  Future<SimpleKeyPair> _getOrCreateKeyPair() async {
    final cached = _cachedKeyPair;
    if (cached != null) {
      return cached;
    }

    final fixedSeed = _fixedSeedForTesting;
    if (fixedSeed != null) {
      final keyPair = await _algorithm.newKeyPairFromSeed(fixedSeed);
      _cachedKeyPair = keyPair;
      return keyPair;
    }

    final storage = _secureStorage!;
    final storedSeed = await storage.read(key: _seedStorageKey);
    if (storedSeed != null && storedSeed.isNotEmpty) {
      final seedBytes = base64.decode(storedSeed);
      final keyPair = await _algorithm.newKeyPairFromSeed(seedBytes);
      _cachedKeyPair = keyPair;
      return keyPair;
    }

    final random = Random.secure();
    final seedBytes = Uint8List.fromList(
        List.generate(_seedLength, (_) => random.nextInt(256)));
    await storage.write(
        key: _seedStorageKey, value: base64.encode(seedBytes));
    final keyPair = await _algorithm.newKeyPairFromSeed(seedBytes);
    _cachedKeyPair = keyPair;
    return keyPair;
  }

  Future<Uint8List> getPublicKeyBytes() async {
    final keyPair = await _getOrCreateKeyPair();
    final publicKey = await keyPair.extractPublicKey();
    return Uint8List.fromList(publicKey.bytes);
  }

  Future<Uint8List> sign(List<int> message) async {
    final keyPair = await _getOrCreateKeyPair();
    final signature = await _algorithm.sign(message, keyPair: keyPair);
    return Uint8List.fromList(signature.bytes);
  }

  Future<bool> verify(
    List<int> message, {
    required List<int> signatureBytes,
    required List<int> publicKeyBytes,
  }) async {
    if (signatureBytes.length != 64 || publicKeyBytes.length != 32) {
      return false;
    }
    final signature = Signature(
      signatureBytes,
      publicKey: SimplePublicKey(publicKeyBytes, type: KeyPairType.ed25519),
    );
    try {
      return await _algorithm.verify(message, signature: signature);
    } catch (_) {
      return false;
    }
  }
}
```

- [ ] **Step 4: Analyze**

Run: `flutter analyze lib/services/identity_service.dart`
Expected: no errors. If the `cryptography` API names in Step 3 don't match the resolved package version (check with `flutter pub deps | grep cryptography` and the local `.dart_tool/package_config.json` cache docs), adjust method names to match — the intent (Ed25519 sign/verify from a stored 32-byte seed) must stay the same.

- [ ] **Step 5: Commit**

```bash
git add pubspec.yaml pubspec.lock lib/services/identity_service.dart
git commit -m "feat: add device identity keypair service"
```

---

## Task 2: Trust store (TOFU) — pure decision logic + SQLite-backed service

**Files:**
- Create: `lib/models/trusted_peer.dart`
- Create: `lib/services/trust_store_service.dart`
- Test: `test/services/trust_store_decision_test.dart`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `class TrustedPeer { identityPublicKeyBase64, bleId, displayName, firstSeen, lastSeen, verified }` (`lib/models/trusted_peer.dart`)
  - `class TrustDecision { isNewDevice, isChanged, previousIdentityPublicKeyBase64 }` (`lib/models/trusted_peer.dart`)
  - top-level `TrustDecision evaluateTrustDecision({required bool identityKnown, required String? conflictingBleIdIdentity})` (`lib/models/trusted_peer.dart`)
  - `class TrustStoreService` with `initialize()`, `Future<TrustDecision> evaluate({required String identityPublicKeyBase64, String? bleId, String? displayName})`, `Future<void> trust({required String identityPublicKeyBase64, String? bleId, String? displayName})`, `Future<void> markVerified(String identityPublicKeyBase64)`.

- [ ] **Step 1: Write `lib/models/trusted_peer.dart`**

```dart
class TrustedPeer {
  final String identityPublicKeyBase64;
  final String? bleId;
  final String? displayName;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final bool verified;

  const TrustedPeer({
    required this.identityPublicKeyBase64,
    this.bleId,
    this.displayName,
    required this.firstSeen,
    required this.lastSeen,
    required this.verified,
  });
}

/// Result of comparing a freshly-authenticated peer identity against what's
/// already known locally.
class TrustDecision {
  final bool isNewDevice;
  final bool isChanged;
  final String? previousIdentityPublicKeyBase64;

  const TrustDecision({
    required this.isNewDevice,
    required this.isChanged,
    this.previousIdentityPublicKeyBase64,
  });
}

/// Pure decision function (no I/O) so the trust-on-first-use policy can be
/// unit tested without a database.
///
/// [identityKnown] is true if a `trusted_peers` row already exists for the
/// exact identity public key just authenticated in the handshake.
/// [conflictingBleIdIdentity] is the identity public key (base64) previously
/// recorded for this connection's BLE id, if any, and if it differs from the
/// identity that just authenticated.
TrustDecision evaluateTrustDecision({
  required bool identityKnown,
  required String? conflictingBleIdIdentity,
}) {
  if (identityKnown) {
    return const TrustDecision(isNewDevice: false, isChanged: false);
  }
  if (conflictingBleIdIdentity != null) {
    return TrustDecision(
      isNewDevice: false,
      isChanged: true,
      previousIdentityPublicKeyBase64: conflictingBleIdIdentity,
    );
  }
  return const TrustDecision(isNewDevice: true, isChanged: false);
}
```

- [ ] **Step 2: Write the failing test for the decision function**

Create `test/services/trust_store_decision_test.dart`:

```dart
import 'package:bluetooth_chat_app/models/trusted_peer.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('evaluateTrustDecision', () {
    test('known identity is neither new nor changed', () {
      final decision = evaluateTrustDecision(
        identityKnown: true,
        conflictingBleIdIdentity: null,
      );
      expect(decision.isNewDevice, isFalse);
      expect(decision.isChanged, isFalse);
    });

    test('unknown identity with no ble-id conflict is new', () {
      final decision = evaluateTrustDecision(
        identityKnown: false,
        conflictingBleIdIdentity: null,
      );
      expect(decision.isNewDevice, isTrue);
      expect(decision.isChanged, isFalse);
    });

    test('unknown identity but ble-id previously belonged to another '
        'identity is a change, not new', () {
      final decision = evaluateTrustDecision(
        identityKnown: false,
        conflictingBleIdIdentity: 'old-key-base64',
      );
      expect(decision.isNewDevice, isFalse);
      expect(decision.isChanged, isTrue);
      expect(decision.previousIdentityPublicKeyBase64, 'old-key-base64');
    });
  });
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `flutter test test/services/trust_store_decision_test.dart`
Expected: FAIL — `evaluateTrustDecision` and `TrustDecision` undefined (file doesn't exist yet if Step 1 hasn't landed; if Step 1 already ran, skip straight to Step 4).

- [ ] **Step 4: Run test to verify it passes**

Run: `flutter test test/services/trust_store_decision_test.dart`
Expected: PASS (3 tests).

- [ ] **Step 5: Write `lib/services/trust_store_service.dart`**

```dart
import 'package:path/path.dart' as p;
import 'package:sqflite/sqflite.dart';

import '../models/trusted_peer.dart';

class TrustStoreService {
  static const _databaseName = 'trust_store.db';
  static const _tableName = 'trusted_peers';

  Database? _database;

  Future<void> initialize() async {
    final databasePath = await getDatabasesPath();
    final path = p.join(databasePath, _databaseName);
    _database = await openDatabase(
      path,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE $_tableName (
            identity_pubkey TEXT PRIMARY KEY,
            ble_id TEXT,
            display_name TEXT,
            first_seen TEXT,
            last_seen TEXT,
            verified INTEGER DEFAULT 0
          )
        ''');
      },
    );
  }

  Database get _db {
    final database = _database;
    if (database == null) {
      throw StateError('TrustStoreService is not initialized');
    }
    return database;
  }

  Future<TrustDecision> evaluate({
    required String identityPublicKeyBase64,
    String? bleId,
    String? displayName,
  }) async {
    final existingByIdentity = await _db.query(
      _tableName,
      where: 'identity_pubkey = ?',
      whereArgs: [identityPublicKeyBase64],
      limit: 1,
    );

    String? conflictingBleIdIdentity;
    if (existingByIdentity.isEmpty && bleId != null) {
      final existingByBleId = await _db.query(
        _tableName,
        where: 'ble_id = ?',
        whereArgs: [bleId],
        limit: 1,
      );
      if (existingByBleId.isNotEmpty) {
        conflictingBleIdIdentity =
            existingByBleId.first['identity_pubkey'] as String;
      }
    }

    final decision = evaluateTrustDecision(
      identityKnown: existingByIdentity.isNotEmpty,
      conflictingBleIdIdentity: conflictingBleIdIdentity,
    );

    if (existingByIdentity.isNotEmpty) {
      await _db.update(
        _tableName,
        {
          'ble_id': bleId,
          'display_name': displayName,
          'last_seen': DateTime.now().toIso8601String(),
        },
        where: 'identity_pubkey = ?',
        whereArgs: [identityPublicKeyBase64],
      );
    }

    return decision;
  }

  Future<void> trust({
    required String identityPublicKeyBase64,
    String? bleId,
    String? displayName,
  }) async {
    if (bleId != null) {
      await _db.delete(
        _tableName,
        where: 'ble_id = ? AND identity_pubkey != ?',
        whereArgs: [bleId, identityPublicKeyBase64],
      );
    }

    final now = DateTime.now().toIso8601String();
    await _db.insert(
      _tableName,
      {
        'identity_pubkey': identityPublicKeyBase64,
        'ble_id': bleId,
        'display_name': displayName,
        'first_seen': now,
        'last_seen': now,
        'verified': 0,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<void> markVerified(String identityPublicKeyBase64) async {
    await _db.update(
      _tableName,
      {'verified': 1},
      where: 'identity_pubkey = ?',
      whereArgs: [identityPublicKeyBase64],
    );
  }

  Future<TrustedPeer?> find(String identityPublicKeyBase64) async {
    final rows = await _db.query(
      _tableName,
      where: 'identity_pubkey = ?',
      whereArgs: [identityPublicKeyBase64],
      limit: 1,
    );
    if (rows.isEmpty) {
      return null;
    }
    final row = rows.first;
    return TrustedPeer(
      identityPublicKeyBase64: row['identity_pubkey'] as String,
      bleId: row['ble_id'] as String?,
      displayName: row['display_name'] as String?,
      firstSeen: DateTime.parse(row['first_seen'] as String),
      lastSeen: DateTime.parse(row['last_seen'] as String),
      verified: (row['verified'] as int?) == 1,
    );
  }
}
```

- [ ] **Step 6: Analyze**

Run: `flutter analyze lib/models/trusted_peer.dart lib/services/trust_store_service.dart`
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add lib/models/trusted_peer.dart lib/services/trust_store_service.dart test/services/trust_store_decision_test.dart
git commit -m "feat: add TOFU trust store with pure decision logic"
```

---

## Task 3: `SecureChannelState` enum

**Files:**
- Create: `lib/models/secure_channel_state.dart`

**Interfaces:**
- Produces: `enum SecureChannelState { idle, handshaking, awaitingTrustConfirmation, identityMismatch, established, failed }`

- [ ] **Step 1: Write `lib/models/secure_channel_state.dart`**

```dart
/// Composite state of a BLE connection's secure channel, combining
/// handshake progress (owned by SecureChannelService) with the trust
/// decision (owned by TrustStoreService). Consumed by BluetoothChatService
/// and the UI layer.
enum SecureChannelState {
  idle,
  handshaking,
  awaitingTrustConfirmation,
  identityMismatch,
  established,
  failed,
}
```

- [ ] **Step 2: Analyze**

Run: `flutter analyze lib/models/secure_channel_state.dart`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add lib/models/secure_channel_state.dart
git commit -m "feat: add SecureChannelState enum"
```

---

## Task 4: `SecureChannelService` core (handshake + AEAD framing)

**Files:**
- Create: `lib/services/secure_channel_service.dart`
- Test: `test/services/secure_channel_service_test.dart`

**Interfaces:**
- Consumes: `IdentityService` from Task 1 (`getPublicKeyBytes()`, `sign()`, `verify()`, `IdentityService.withSeedForTesting`).
- Produces:
  - `enum FrameType { hello, response, finished, data }`
  - `class HandshakeResult { final Uint8List peerIdentityPublicKey; }`
  - `class SecureChannelService` with constructor `SecureChannelService({required IdentityService identityService, required bool isInitiator, required Future<void> Function(FrameType type, Uint8List payload) sendFrame, required void Function(HandshakeResult result) onHandshakeComplete, required void Function(String reason) onHandshakeFailed, required void Function(Uint8List innerPlaintext) onData, required void Function(String reason) onChannelError})`, methods `Future<void> start()`, `Future<void> receiveFrame(FrameType type, Uint8List payload)`, `Future<void> sendData(Uint8List innerPlaintext)`.

- [ ] **Step 1: Write `lib/services/secure_channel_service.dart`**

```dart
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity_service.dart';

enum FrameType { hello, response, finished, data }

class HandshakeResult {
  final Uint8List peerIdentityPublicKey;
  const HandshakeResult(this.peerIdentityPublicKey);
}

class _HandshakeException implements Exception {
  final String reason;
  const _HandshakeException(this.reason);
}

/// Transport-agnostic mutual-authentication handshake and per-message AEAD
/// channel. Driven entirely through the [sendFrame] callback and
/// [receiveFrame] method so it can run over BLE, an in-memory loopback in
/// tests, or any other byte transport.
///
/// Handshake (3 messages): HELLO (initiator->responder) carries the
/// initiator's long-term Ed25519 identity public key, a fresh X25519
/// ephemeral public key, and a nonce. RESPONSE (responder->initiator) does
/// the same and additionally signs the transcript
/// (nonce_i||epk_i||epk_r||nonce_r) with the responder's identity key.
/// FINISHED (initiator->responder) signs the same transcript with the
/// initiator's identity key and includes an AEAD-sealed confirmation,
/// proving both sides derived the same session keys. Traffic afterwards is
/// ChaCha20-Poly1305 with a nonce built from a strictly-increasing
/// per-direction counter, so replays and reordering are rejected outright.
class SecureChannelService {
  static const _nonceLength = 12;
  static const _nonceRandomLength = 16;
  static const _handshakeTimestampWindow = Duration(minutes: 2);

  final IdentityService identityService;
  final bool isInitiator;
  final Future<void> Function(FrameType type, Uint8List payload) sendFrame;
  final void Function(HandshakeResult result) onHandshakeComplete;
  final void Function(String reason) onHandshakeFailed;
  final void Function(Uint8List innerPlaintext) onData;
  final void Function(String reason) onChannelError;

  final Ed25519 _ed25519 = Ed25519();
  final X25519 _x25519 = X25519();
  final Chacha20 _aead = Chacha20.poly1305Aead();
  final Hkdf _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  SimpleKeyPair? _ephemeralKeyPair;
  Uint8List? _localNonce;
  Uint8List? _peerIdentityPublicKey;
  Uint8List? _peerEphemeralPublicKey;
  Uint8List? _peerNonce;

  SecretKey? _i2rKey;
  SecretKey? _r2iKey;
  int _i2rSendCounter = 0;
  int _i2rRecvCounter = 0;
  int _r2iSendCounter = 0;
  int _r2iRecvCounter = 0;

  bool _handshakeComplete = false;
  bool _failed = false;

  SecureChannelService({
    required this.identityService,
    required this.isInitiator,
    required this.sendFrame,
    required this.onHandshakeComplete,
    required this.onHandshakeFailed,
    required this.onData,
    required this.onChannelError,
  });

  Future<void> start() async {
    if (!isInitiator) {
      return;
    }
    await _sendHello();
  }

  Future<void> _sendHello() async {
    final ephemeralKeyPair = await _x25519.newKeyPair();
    _ephemeralKeyPair = ephemeralKeyPair;
    final ephemeralPublic = await ephemeralKeyPair.extractPublicKey();

    final nonce = _randomBytes(_nonceRandomLength);
    _localNonce = nonce;

    final identityPublicKey = await identityService.getPublicKeyBytes();
    final timestamp = _timestampBytes();

    final payload = Uint8List.fromList([
      ...identityPublicKey,
      ...ephemeralPublic.bytes,
      ...nonce,
      ...timestamp,
    ]);

    await sendFrame(FrameType.hello, payload);
  }

  Future<void> receiveFrame(FrameType type, Uint8List payload) async {
    if (_failed) {
      return;
    }
    try {
      switch (type) {
        case FrameType.hello:
          await _handleHello(payload);
          break;
        case FrameType.response:
          await _handleResponse(payload);
          break;
        case FrameType.finished:
          await _handleFinished(payload);
          break;
        case FrameType.data:
          await _handleData(payload);
          break;
      }
    } catch (e) {
      _fail(e is _HandshakeException ? e.reason : e.toString());
    }
  }

  Future<void> _handleHello(Uint8List payload) async {
    if (isInitiator) {
      throw const _HandshakeException('Initiator cannot receive HELLO');
    }
    if (payload.length != 88) {
      throw const _HandshakeException('Malformed HELLO payload');
    }

    final peerIdentityPublicKey = payload.sublist(0, 32);
    final peerEphemeralPublicKey = payload.sublist(32, 64);
    final peerNonce = payload.sublist(64, 80);
    final timestampBytes = payload.sublist(80, 88);
    _checkTimestamp(timestampBytes);

    _peerIdentityPublicKey = peerIdentityPublicKey;
    _peerEphemeralPublicKey = peerEphemeralPublicKey;
    _peerNonce = peerNonce;

    final ephemeralKeyPair = await _x25519.newKeyPair();
    _ephemeralKeyPair = ephemeralKeyPair;
    final ephemeralPublic = await ephemeralKeyPair.extractPublicKey();

    final localNonce = _randomBytes(_nonceRandomLength);
    _localNonce = localNonce;

    final transcript = Uint8List.fromList([
      ...peerNonce,
      ...peerEphemeralPublicKey,
      ...ephemeralPublic.bytes,
      ...localNonce,
    ]);

    final identityPublicKey = await identityService.getPublicKeyBytes();
    final signature = await identityService.sign(transcript);
    final timestamp = _timestampBytes();

    await _deriveSessionKeys();

    final payloadOut = Uint8List.fromList([
      ...identityPublicKey,
      ...ephemeralPublic.bytes,
      ...localNonce,
      ...timestamp,
      ...signature,
    ]);

    await sendFrame(FrameType.response, payloadOut);
  }

  Future<void> _handleResponse(Uint8List payload) async {
    if (!isInitiator) {
      throw const _HandshakeException('Responder cannot receive RESPONSE');
    }
    if (payload.length != 152) {
      throw const _HandshakeException('Malformed RESPONSE payload');
    }

    final peerIdentityPublicKey = payload.sublist(0, 32);
    final peerEphemeralPublicKey = payload.sublist(32, 64);
    final peerNonce = payload.sublist(64, 80);
    final timestampBytes = payload.sublist(80, 88);
    final signature = payload.sublist(88, 152);
    _checkTimestamp(timestampBytes);

    final localNonce = _localNonce;
    final ephemeralKeyPair = _ephemeralKeyPair;
    if (localNonce == null || ephemeralKeyPair == null) {
      throw const _HandshakeException(
          'HELLO was not sent before RESPONSE arrived');
    }
    final localEphemeralPublic = await ephemeralKeyPair.extractPublicKey();

    final transcript = Uint8List.fromList([
      ...localNonce,
      ...localEphemeralPublic.bytes,
      ...peerEphemeralPublicKey,
      ...peerNonce,
    ]);

    final verified = await identityService.verify(
      transcript,
      signatureBytes: signature,
      publicKeyBytes: peerIdentityPublicKey,
    );
    if (!verified) {
      throw const _HandshakeException('RESPONSE signature verification failed');
    }

    _peerIdentityPublicKey = peerIdentityPublicKey;
    _peerEphemeralPublicKey = peerEphemeralPublicKey;
    _peerNonce = peerNonce;

    await _deriveSessionKeys();

    final identitySignature = await identityService.sign(transcript);
    final confirmSealed = await _seal(
      key: _i2rKey!,
      counter: 0,
      plainText: utf8.encode('OK'),
    );

    final payloadOut = Uint8List.fromList([
      ...identitySignature,
      ...confirmSealed,
    ]);

    _i2rSendCounter = 1;

    await sendFrame(FrameType.finished, payloadOut);

    _handshakeComplete = true;
    onHandshakeComplete(
        HandshakeResult(Uint8List.fromList(peerIdentityPublicKey)));
  }

  Future<void> _handleFinished(Uint8List payload) async {
    if (isInitiator) {
      throw const _HandshakeException('Initiator cannot receive FINISHED');
    }
    if (payload.length != 82) {
      throw const _HandshakeException('Malformed FINISHED payload');
    }

    final signature = payload.sublist(0, 64);
    final confirmSealed = payload.sublist(64, 82);

    final localNonce = _localNonce;
    final peerNonce = _peerNonce;
    final peerEphemeralPublicKey = _peerEphemeralPublicKey;
    final peerIdentityPublicKey = _peerIdentityPublicKey;
    final ephemeralKeyPair = _ephemeralKeyPair;
    if (localNonce == null ||
        peerNonce == null ||
        peerEphemeralPublicKey == null ||
        peerIdentityPublicKey == null ||
        ephemeralKeyPair == null) {
      throw const _HandshakeException(
          'FINISHED arrived before RESPONSE was sent');
    }
    final localEphemeralPublic = await ephemeralKeyPair.extractPublicKey();

    final transcript = Uint8List.fromList([
      ...peerNonce,
      ...peerEphemeralPublicKey,
      ...localEphemeralPublic.bytes,
      ...localNonce,
    ]);

    final verified = await identityService.verify(
      transcript,
      signatureBytes: signature,
      publicKeyBytes: peerIdentityPublicKey,
    );
    if (!verified) {
      throw const _HandshakeException('FINISHED signature verification failed');
    }

    final confirmPlainText = await _open(
      key: _i2rKey!,
      counter: 0,
      sealed: confirmSealed,
    );
    if (utf8.decode(confirmPlainText) != 'OK') {
      throw const _HandshakeException('FINISHED confirmation payload mismatch');
    }

    _i2rRecvCounter = 1;
    _handshakeComplete = true;
    onHandshakeComplete(
        HandshakeResult(Uint8List.fromList(peerIdentityPublicKey)));
  }

  Future<void> sendData(Uint8List innerPlaintext) async {
    if (!_handshakeComplete) {
      throw StateError('Cannot send data before handshake completes');
    }

    final Uint8List sealed;
    if (isInitiator) {
      sealed = await _seal(
          key: _i2rKey!, counter: _i2rSendCounter, plainText: innerPlaintext);
      _i2rSendCounter += 1;
    } else {
      sealed = await _seal(
          key: _r2iKey!, counter: _r2iSendCounter, plainText: innerPlaintext);
      _r2iSendCounter += 1;
    }

    await sendFrame(FrameType.data, sealed);
  }

  Future<void> _handleData(Uint8List payload) async {
    if (!_handshakeComplete) {
      throw const _HandshakeException('DATA received before handshake completed');
    }

    final Uint8List clearText;
    if (isInitiator) {
      clearText =
          await _open(key: _r2iKey!, counter: _r2iRecvCounter, sealed: payload);
      _r2iRecvCounter += 1;
    } else {
      clearText =
          await _open(key: _i2rKey!, counter: _i2rRecvCounter, sealed: payload);
      _i2rRecvCounter += 1;
    }

    onData(clearText);
  }

  Future<void> _deriveSessionKeys() async {
    final ephemeralKeyPair = _ephemeralKeyPair;
    final peerEphemeralPublicKey = _peerEphemeralPublicKey;
    final localNonce = _localNonce;
    final peerNonce = _peerNonce;
    if (ephemeralKeyPair == null ||
        peerEphemeralPublicKey == null ||
        localNonce == null ||
        peerNonce == null) {
      throw const _HandshakeException('Missing handshake state for key derivation');
    }

    final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: ephemeralKeyPair,
      remotePublicKey:
          SimplePublicKey(peerEphemeralPublicKey, type: KeyPairType.x25519),
    );

    final initiatorNonce = isInitiator ? localNonce : peerNonce;
    final responderNonce = isInitiator ? peerNonce : localNonce;
    final salt = Uint8List.fromList([...initiatorNonce, ...responderNonce]);

    _i2rKey = await _hkdf.deriveKey(
      secretKey: sharedSecret,
      nonce: salt,
      info: utf8.encode('i2r'),
    );
    _r2iKey = await _hkdf.deriveKey(
      secretKey: sharedSecret,
      nonce: salt,
      info: utf8.encode('r2i'),
    );
  }

  Future<Uint8List> _seal({
    required SecretKey key,
    required int counter,
    required List<int> plainText,
  }) async {
    final nonce = _nonceForCounter(counter);
    final secretBox =
        await _aead.encrypt(plainText, secretKey: key, nonce: nonce);
    return Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
  }

  Future<Uint8List> _open({
    required SecretKey key,
    required int counter,
    required Uint8List sealed,
  }) async {
    if (sealed.length < 16) {
      throw const _HandshakeException('Sealed payload too short');
    }
    final nonce = _nonceForCounter(counter);
    final cipherText = sealed.sublist(0, sealed.length - 16);
    final mac = sealed.sublist(sealed.length - 16);
    final clearText = await _aead.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(mac)),
      secretKey: key,
    );
    return Uint8List.fromList(clearText);
  }

  Uint8List _nonceForCounter(int counter) {
    final nonce = Uint8List(_nonceLength);
    ByteData.sublistView(nonce).setUint64(4, counter, Endian.big);
    return nonce;
  }

  Uint8List _timestampBytes() {
    final bytes = Uint8List(8);
    ByteData.sublistView(bytes)
        .setInt64(0, DateTime.now().millisecondsSinceEpoch, Endian.big);
    return bytes;
  }

  void _checkTimestamp(Uint8List timestampBytes) {
    final millis = ByteData.sublistView(timestampBytes).getInt64(0, Endian.big);
    final peerTime = DateTime.fromMillisecondsSinceEpoch(millis);
    final drift = DateTime.now().difference(peerTime).abs();
    if (drift > _handshakeTimestampWindow) {
      throw const _HandshakeException('Handshake timestamp outside allowed window');
    }
  }

  Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
  }

  void _fail(String reason) {
    _failed = true;
    if (_handshakeComplete) {
      onChannelError(reason);
    } else {
      onHandshakeFailed(reason);
    }
  }
}
```

- [ ] **Step 2: Write the happy-path test**

Create `test/services/secure_channel_service_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:bluetooth_chat_app/services/identity_service.dart';
import 'package:bluetooth_chat_app/services/secure_channel_service.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List _seed(int fill) => Uint8List.fromList(List.filled(32, fill));

class _Peer {
  final IdentityService identity;
  late final SecureChannelService channel;
  _Peer? other;
  Uint8List Function(FrameType type, Uint8List payload)? outgoingTransform;

  HandshakeResult? handshakeResult;
  String? handshakeFailure;
  String? channelError;
  final List<Uint8List> received = [];
  final List<MapEntry<FrameType, Uint8List>> sentFrames = [];

  _Peer(Uint8List seed, {required bool isInitiator})
      : identity = IdentityService.withSeedForTesting(seed) {
    channel = SecureChannelService(
      identityService: identity,
      isInitiator: isInitiator,
      sendFrame: (type, payload) async {
        sentFrames.add(MapEntry(type, payload));
        final transform = outgoingTransform;
        final outgoing = transform != null ? transform(type, payload) : payload;
        final target = other;
        if (target == null) return;
        await target.channel.receiveFrame(type, outgoing);
      },
      onHandshakeComplete: (result) => handshakeResult = result,
      onHandshakeFailed: (reason) => handshakeFailure = reason,
      onData: (data) => received.add(data),
      onChannelError: (reason) => channelError = reason,
    );
  }
}

void main() {
  group('SecureChannelService', () {
    test('completes a handshake and exchanges authenticated data both ways',
        () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;

      await initiator.channel.start();

      expect(initiator.handshakeResult, isNotNull);
      expect(responder.handshakeResult, isNotNull);

      final responderIdentityPublicKey = await responder.identity.getPublicKeyBytes();
      final initiatorIdentityPublicKey = await initiator.identity.getPublicKeyBytes();

      expect(initiator.handshakeResult!.peerIdentityPublicKey,
          equals(responderIdentityPublicKey));
      expect(responder.handshakeResult!.peerIdentityPublicKey,
          equals(initiatorIdentityPublicKey));

      await initiator.channel.sendData(Uint8List.fromList(utf8.encode('hello')));
      expect(responder.received, hasLength(1));
      expect(utf8.decode(responder.received.first), equals('hello'));

      await responder.channel.sendData(Uint8List.fromList(utf8.encode('hi back')));
      expect(initiator.received, hasLength(1));
      expect(utf8.decode(initiator.received.first), equals('hi back'));
    });
  });
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `flutter test test/services/secure_channel_service_test.dart`
Expected: FAIL — `SecureChannelService` undefined (if Step 1 hasn't landed yet; otherwise skip to Step 4).

- [ ] **Step 4: Run test to verify it passes**

Run: `flutter test test/services/secure_channel_service_test.dart`
Expected: PASS. If the `cryptography` API calls in Step 1 don't compile against the resolved package version, fix the method/class names (keep the algorithm choices — Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305 — intact) until this test passes.

- [ ] **Step 5: Commit**

```bash
git add lib/services/secure_channel_service.dart test/services/secure_channel_service_test.dart
git commit -m "feat: add mutual-auth handshake and AEAD channel (happy path)"
```

---

## Task 5: `SecureChannelService` negative-path tests (forged signature, replay, tamper)

**Files:**
- Modify: `test/services/secure_channel_service_test.dart`

**Interfaces:**
- Consumes: `SecureChannelService`, `_Peer` test helper from Task 4 (same file).

- [ ] **Step 1: Add the forged-signature test**

Append inside the `group('SecureChannelService', ...)` block in `test/services/secure_channel_service_test.dart`:

```dart
    test('rejects a forged RESPONSE signature', () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;
      responder.outgoingTransform = (type, payload) {
        if (type != FrameType.response) return payload;
        final tampered = Uint8List.fromList(payload);
        tampered[tampered.length - 1] ^= 0xFF; // flip a bit inside sig_r
        return tampered;
      };

      await initiator.channel.start();

      expect(initiator.handshakeResult, isNull);
      expect(initiator.handshakeFailure, isNotNull);
      expect(initiator.handshakeFailure, contains('signature'));
    });

    test('rejects a replayed DATA frame', () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;
      await initiator.channel.start();

      await initiator.channel.sendData(Uint8List.fromList(utf8.encode('once')));
      expect(responder.received, hasLength(1));

      final dataFrame =
          initiator.sentFrames.lastWhere((entry) => entry.key == FrameType.data);
      await responder.channel.receiveFrame(dataFrame.key, dataFrame.value);

      expect(responder.received, hasLength(1));
      expect(responder.channelError, isNotNull);
    });

    test('rejects a tampered DATA ciphertext', () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;
      await initiator.channel.start();

      initiator.outgoingTransform = (type, payload) {
        if (type != FrameType.data) return payload;
        final tampered = Uint8List.fromList(payload);
        tampered[0] ^= 0xFF;
        return tampered;
      };

      await initiator.channel.sendData(Uint8List.fromList(utf8.encode('tamper me')));

      expect(responder.received, isEmpty);
      expect(responder.channelError, isNotNull);
    });
```

- [ ] **Step 2: Run tests to verify the new ones fail before any fix is needed**

Run: `flutter test test/services/secure_channel_service_test.dart`
Expected: all 4 tests PASS immediately, since Task 4's implementation already has to satisfy these properties by construction (signature verification, strictly-increasing counters, AEAD authentication). If any fails, it indicates a real bug in `secure_channel_service.dart` — fix the implementation (not the test) until all 4 pass.

- [ ] **Step 3: Commit**

```bash
git add test/services/secure_channel_service_test.dart
git commit -m "test: cover forged signature, replay, and tamper rejection"
```

---

## Task 6: Binary BLE frame codec

**Files:**
- Modify: `lib/services/secure_channel_service.dart` (export nothing new; `FrameType` already public)
- Create: `lib/services/bluetooth_frame_codec.dart`
- Test: `test/services/bluetooth_frame_codec_test.dart`

**Interfaces:**
- Consumes: `enum FrameType` from Task 4 (`lib/services/secure_channel_service.dart`).
- Produces: `class BluetoothFrameCodec` with `BluetoothFrameCodec({required void Function(FrameType type, Uint8List payload) onFrame})`, `void feed(List<int> chunk)`, static `Uint8List encode(FrameType type, Uint8List payload)`.

- [ ] **Step 1: Write `lib/services/bluetooth_frame_codec.dart`**

```dart
import 'dart:typed_data';

import 'secure_channel_service.dart';

/// Encodes/decodes the BLE wire format: `[1 byte frame type][4 byte
/// big-endian length][payload]`. Replaces the old newline-delimited ASCII
/// framing, which could corrupt on any binary payload containing a literal
/// newline byte.
class BluetoothFrameCodec {
  static const _headerLength = 5;

  final void Function(FrameType type, Uint8List payload) onFrame;
  final List<int> _buffer = [];

  BluetoothFrameCodec({required this.onFrame});

  static Uint8List encode(FrameType type, Uint8List payload) {
    final frame = Uint8List(_headerLength + payload.length);
    frame[0] = _tagFor(type);
    ByteData.sublistView(frame, 1, 5).setUint32(0, payload.length, Endian.big);
    frame.setRange(_headerLength, frame.length, payload);
    return frame;
  }

  void feed(List<int> chunk) {
    _buffer.addAll(chunk);

    while (true) {
      if (_buffer.length < _headerLength) {
        return;
      }

      final tag = _buffer[0];
      final lengthBytes = Uint8List.fromList(_buffer.sublist(1, _headerLength));
      final length = ByteData.sublistView(lengthBytes).getUint32(0, Endian.big);

      if (_buffer.length < _headerLength + length) {
        return;
      }

      final payload = Uint8List.fromList(
          _buffer.sublist(_headerLength, _headerLength + length));
      _buffer.removeRange(0, _headerLength + length);

      final type = _typeFor(tag);
      if (type != null) {
        onFrame(type, payload);
      }
    }
  }

  static int _tagFor(FrameType type) {
    switch (type) {
      case FrameType.hello:
        return 0x01;
      case FrameType.response:
        return 0x02;
      case FrameType.finished:
        return 0x03;
      case FrameType.data:
        return 0x04;
    }
  }

  static FrameType? _typeFor(int tag) {
    switch (tag) {
      case 0x01:
        return FrameType.hello;
      case 0x02:
        return FrameType.response;
      case 0x03:
        return FrameType.finished;
      case 0x04:
        return FrameType.data;
      default:
        return null;
    }
  }
}
```

- [ ] **Step 2: Write the failing test**

Create `test/services/bluetooth_frame_codec_test.dart`:

```dart
import 'dart:typed_data';

import 'package:bluetooth_chat_app/services/bluetooth_frame_codec.dart';
import 'package:bluetooth_chat_app/services/secure_channel_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('BluetoothFrameCodec', () {
    test('encodes and decodes a single frame', () {
      final frames = <MapEntry<FrameType, Uint8List>>[];
      final codec = BluetoothFrameCodec(onFrame: (t, p) => frames.add(MapEntry(t, p)));

      final encoded =
          BluetoothFrameCodec.encode(FrameType.data, Uint8List.fromList([1, 2, 3]));
      codec.feed(encoded);

      expect(frames, hasLength(1));
      expect(frames.first.key, FrameType.data);
      expect(frames.first.value, equals([1, 2, 3]));
    });

    test('handles a frame split across multiple chunks', () {
      final frames = <MapEntry<FrameType, Uint8List>>[];
      final codec = BluetoothFrameCodec(onFrame: (t, p) => frames.add(MapEntry(t, p)));

      final payload = Uint8List.fromList(List.generate(200, (i) => i % 256));
      final encoded = BluetoothFrameCodec.encode(FrameType.hello, payload);

      codec.feed(encoded.sublist(0, 3));
      expect(frames, isEmpty);
      codec.feed(encoded.sublist(3));

      expect(frames, hasLength(1));
      expect(frames.first.value, equals(payload));
    });

    test('handles two frames arriving in a single chunk', () {
      final frames = <MapEntry<FrameType, Uint8List>>[];
      final codec = BluetoothFrameCodec(onFrame: (t, p) => frames.add(MapEntry(t, p)));

      final a = BluetoothFrameCodec.encode(FrameType.finished, Uint8List.fromList([9, 9]));
      final b = BluetoothFrameCodec.encode(FrameType.data, Uint8List.fromList([7]));
      codec.feed([...a, ...b]);

      expect(frames, hasLength(2));
      expect(frames[0].key, FrameType.finished);
      expect(frames[1].key, FrameType.data);
    });
  });
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `flutter test test/services/bluetooth_frame_codec_test.dart`
Expected: FAIL — `BluetoothFrameCodec` undefined (if Step 1 hasn't landed yet; otherwise skip to Step 4).

- [ ] **Step 4: Run test to verify it passes**

Run: `flutter test test/services/bluetooth_frame_codec_test.dart`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/services/bluetooth_frame_codec.dart test/services/bluetooth_frame_codec_test.dart
git commit -m "feat: add binary BLE frame codec"
```

---

## Task 7: Repurpose `SecurityService` to a local-only storage key

**Files:**
- Modify: `lib/services/security_service.dart` (full rewrite)

**Interfaces:**
- Produces: `class SecurityService` with `SecurityService({FlutterSecureStorage? secureStorage})`, `Future<SecretKey> getLocalStorageKey()`. Drops `getPassphrase()`/`setPassphrase()`.
- Consumed by: Task 8 (`ChatStorageService`), Task 9/10 (`ChatScreen` no longer calls this at all for BLE, only for local storage).

- [ ] **Step 1: Rewrite `lib/services/security_service.dart`**

```dart
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Manages a random, device-local key used only to encrypt the local chat
/// database at rest. Unlike the old shared-passphrase design, this key is
/// never shared with a peer and has nothing to do with the BLE pairing
/// protocol (see SecureChannelService for that).
class SecurityService {
  static const _localKeyStorageKey = 'local_storage_master_key_v1';
  static const _keyLength = 32;

  final FlutterSecureStorage _secureStorage;
  SecretKey? _cachedKey;

  SecurityService({FlutterSecureStorage? secureStorage})
      : _secureStorage = secureStorage ?? const FlutterSecureStorage();

  Future<SecretKey> getLocalStorageKey() async {
    final cached = _cachedKey;
    if (cached != null) {
      return cached;
    }

    final stored = await _secureStorage.read(key: _localKeyStorageKey);
    if (stored != null && stored.isNotEmpty) {
      final key = SecretKey(base64.decode(stored));
      _cachedKey = key;
      return key;
    }

    final random = Random.secure();
    final keyBytes = Uint8List.fromList(
        List.generate(_keyLength, (_) => random.nextInt(256)));
    await _secureStorage.write(
        key: _localKeyStorageKey, value: base64.encode(keyBytes));
    final key = SecretKey(keyBytes);
    _cachedKey = key;
    return key;
  }
}
```

- [ ] **Step 2: Analyze**

Run: `flutter analyze lib/services/security_service.dart`
Expected: no errors. Other files that still call `getPassphrase()`/`setPassphrase()` (`chat_screen.dart`, `profile_screen.dart`, `chat_storage_service.dart`) will now show errors — that's expected and fixed in Tasks 8, 9, and 11. Do not fix them here.

- [ ] **Step 3: Commit**

```bash
git add lib/services/security_service.dart
git commit -m "refactor: SecurityService now manages a local-only storage key"
```

---

## Task 8: `ChatStorageService` — AEAD field encryption with random nonces

**Files:**
- Modify: `lib/services/chat_storage_service.dart` (full rewrite)
- Test: `test/services/chat_storage_service_cipher_test.dart`

**Interfaces:**
- Consumes: `SecretKey` from `SecurityService.getLocalStorageKey()` (Task 7).
- Produces: `class ChatStorageService` with `initialize()`, `Future<List<ChatMessage>> loadMessages(SecretKey localKey)`, `Future<void> saveMessages(List<ChatMessage> messages, SecretKey localKey)`, `Future<String> encryptField(String value, SecretKey key)`, `Future<String> decryptField(String? value, SecretKey key)`.

- [ ] **Step 1: Write the failing test for the pure cipher round trip**

Create `test/services/chat_storage_service_cipher_test.dart`:

```dart
import 'package:bluetooth_chat_app/services/chat_storage_service.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ChatStorageService field cipher', () {
    late ChatStorageService storage;
    late SecretKey key;

    setUp(() async {
      storage = ChatStorageService();
      key = SecretKey(List.generate(32, (i) => i));
    });

    test('empty string round-trips to empty string without encrypting', () async {
      final encrypted = await storage.encryptField('', key);
      expect(encrypted, isEmpty);
      final decrypted = await storage.decryptField(encrypted, key);
      expect(decrypted, isEmpty);
    });

    test('encrypts and decrypts back to the original value', () async {
      final encrypted = await storage.encryptField('hello world', key);
      expect(encrypted, isNotEmpty);
      expect(encrypted, isNot(contains('hello world')));

      final decrypted = await storage.decryptField(encrypted, key);
      expect(decrypted, equals('hello world'));
    });

    test('two encryptions of the same value produce different ciphertext',
        () async {
      final a = await storage.encryptField('same value', key);
      final b = await storage.encryptField('same value', key);
      expect(a, isNot(equals(b)));
    });

    test('decrypting with the wrong key returns empty instead of throwing',
        () async {
      final encrypted = await storage.encryptField('secret', key);
      final wrongKey = SecretKey(List.generate(32, (i) => 255 - i));
      final decrypted = await storage.decryptField(encrypted, wrongKey);
      expect(decrypted, isEmpty);
    });
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `flutter test test/services/chat_storage_service_cipher_test.dart`
Expected: FAIL — current `encryptField`/`decryptField` don't exist yet (the file still has the old passphrase-based `_encryptValue`/`_decryptValue`).

- [ ] **Step 3: Rewrite `lib/services/chat_storage_service.dart`**

```dart
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:path/path.dart' as p;
import 'package:sqflite/sqflite.dart';

import '../models/chat_message.dart';

class ChatStorageService {
  static const _databaseName = 'chat_history.db';
  static const _tableName = 'chat_messages';
  static const _databaseVersion = 2;

  static const _createTableSql = '''
    CREATE TABLE $_tableName (
      id TEXT PRIMARY KEY,
      text TEXT,
      sender_name TEXT,
      is_mine INTEGER,
      created_at TEXT,
      avatar_path TEXT,
      type INTEGER,
      file_path TEXT,
      file_name TEXT
    )
  ''';

  final Chacha20 _cipher = Chacha20.poly1305Aead();
  Database? _database;

  Future<void> initialize() async {
    final databasePath = await getDatabasesPath();
    final path = p.join(databasePath, _databaseName);
    _database = await openDatabase(
      path,
      version: _databaseVersion,
      onCreate: (db, version) async {
        await db.execute(_createTableSql);
      },
      onUpgrade: (db, oldVersion, newVersion) async {
        // Rows from schema version 1 were encrypted under the removed
        // shared-passphrase scheme and cannot be migrated to the new
        // per-device local key. This is a pre-release app with no
        // production user data, so the table is simply recreated.
        await db.execute('DROP TABLE IF EXISTS $_tableName');
        await db.execute(_createTableSql);
      },
    );
  }

  Database get _db {
    final database = _database;
    if (database == null) {
      throw StateError('Chat storage is not initialized');
    }
    return database;
  }

  Future<List<ChatMessage>> loadMessages(SecretKey localKey) async {
    final rows = await _db.query(_tableName, orderBy: 'created_at ASC');

    final messages = <ChatMessage>[];
    for (final row in rows) {
      final typeIndex = row['type'] as int? ?? 0;
      messages.add(ChatMessage(
        id: row['id'] as String,
        text: await decryptField(row['text'] as String?, localKey),
        senderName:
            await decryptField(row['sender_name'] as String?, localKey).then(
                (value) => value.isEmpty ? 'You' : value),
        isMine: (row['is_mine'] as int?) == 1,
        createdAt: DateTime.parse(row['created_at'] as String),
        avatarPath: row['avatar_path'] as String?,
        type: MessageType.values[typeIndex],
        filePath: row['file_path'] as String?,
        fileName: await decryptField(row['file_name'] as String?, localKey),
      ));
    }
    return messages;
  }

  Future<void> saveMessages(
      List<ChatMessage> messages, SecretKey localKey) async {
    final encodedRows = <Map<String, Object?>>[];
    for (final message in messages) {
      encodedRows.add({
        'id': message.id,
        'text': await encryptField(message.text, localKey),
        'sender_name': await encryptField(message.senderName, localKey),
        'is_mine': message.isMine ? 1 : 0,
        'created_at': message.createdAt.toIso8601String(),
        'avatar_path': message.avatarPath,
        'type': message.type.index,
        'file_path': message.filePath,
        'file_name': await encryptField(message.fileName ?? '', localKey),
      });
    }

    await _db.transaction((txn) async {
      await txn.delete(_tableName);
      for (final row in encodedRows) {
        await txn.insert(_tableName, row);
      }
    });
  }

  Future<String> encryptField(String value, SecretKey key) async {
    if (value.isEmpty) {
      return '';
    }
    final nonce = _cipher.newNonce();
    final secretBox =
        await _cipher.encrypt(utf8.encode(value), secretKey: key, nonce: nonce);
    final combined = <int>[
      ...secretBox.nonce,
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ];
    return base64.encode(combined);
  }

  Future<String> decryptField(String? value, SecretKey key) async {
    if (value == null || value.isEmpty) {
      return '';
    }
    try {
      final combined = base64.decode(value);
      if (combined.length < 12 + 16) {
        return '';
      }
      final nonce = combined.sublist(0, 12);
      final mac = combined.sublist(combined.length - 16);
      final cipherText = combined.sublist(12, combined.length - 16);
      final clearText = await _cipher.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: Mac(mac)),
        secretKey: key,
      );
      return utf8.decode(clearText);
    } catch (_) {
      return '';
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `flutter test test/services/chat_storage_service_cipher_test.dart`
Expected: PASS (4 tests).

- [ ] **Step 5: Analyze**

Run: `flutter analyze lib/services/chat_storage_service.dart`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add lib/services/chat_storage_service.dart test/services/chat_storage_service_cipher_test.dart
git commit -m "feat: switch chat storage to AEAD with a local-only key"
```

---

## Task 9: Rewrite `BluetoothChatService` around the secure channel

**Files:**
- Modify: `lib/services/bluetooth_chat_service.dart` (full rewrite)

**Interfaces:**
- Consumes: `IdentityService` (Task 1), `TrustStoreService`/`TrustDecision` (Task 2), `SecureChannelState` (Task 3), `SecureChannelService`/`FrameType`/`HandshakeResult` (Task 4), `BluetoothFrameCodec` (Task 6).
- Produces:
  - `class TrustPromptEvent { identityPublicKeyBase64, bleId, displayName, isNewDevice, isChanged }`
  - `class BluetoothChatService` with existing `discoveredDevices`, `connectedDevice`, `incomingTransfers`, `incomingTextMessages`, plus new `Stream<SecureChannelState> channelStateChanges`, `Stream<TrustPromptEvent> trustPrompts`, `Future<void> respondToTrustPrompt(bool accept)`, `Uint8List? get connectedPeerIdentityPublicKey`. `sendMessage`/`sendFile` now no-op/throw unless the channel is `established`. `setPassphrase` is removed.

- [ ] **Step 1: Rewrite `lib/services/bluetooth_chat_service.dart`**

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

import '../models/secure_channel_state.dart';
import 'bluetooth_frame_codec.dart';
import 'identity_service.dart';
import 'secure_channel_service.dart';
import 'trust_store_service.dart';

class BluetoothDeviceInfo {
  final String id;
  final String name;
  final bool isConnected;
  final BluetoothDevice? device;

  const BluetoothDeviceInfo({
    required this.id,
    required this.name,
    required this.isConnected,
    this.device,
  });
}

class IncomingTransfer {
  final String fileName;
  final String filePath;

  const IncomingTransfer({required this.fileName, required this.filePath});
}

class IncomingTextMessage {
  final String senderName;
  final String text;

  const IncomingTextMessage({required this.senderName, required this.text});
}

class TrustPromptEvent {
  final String identityPublicKeyBase64;
  final String? bleId;
  final String? displayName;
  final bool isNewDevice;
  final bool isChanged;

  const TrustPromptEvent({
    required this.identityPublicKeyBase64,
    this.bleId,
    this.displayName,
    required this.isNewDevice,
    required this.isChanged,
  });
}

class BluetoothChatService {
  final List<BluetoothDeviceInfo> discoveredDevices = [];
  BluetoothDeviceInfo? connectedDevice;

  final IdentityService _identityService;
  final TrustStoreService _trustStore;

  BluetoothChatService({
    IdentityService? identityService,
    TrustStoreService? trustStore,
  })  : _identityService = identityService ?? IdentityService(),
        _trustStore = trustStore ?? TrustStoreService();

  final StreamController<IncomingTransfer> _incomingTransferController =
      StreamController.broadcast();
  final StreamController<IncomingTextMessage> _incomingTextController =
      StreamController.broadcast();
  final StreamController<SecureChannelState> _channelStateController =
      StreamController.broadcast();
  final StreamController<TrustPromptEvent> _trustPromptController =
      StreamController.broadcast();

  Stream<IncomingTransfer> get incomingTransfers => _incomingTransferController.stream;
  Stream<IncomingTextMessage> get incomingTextMessages => _incomingTextController.stream;
  Stream<SecureChannelState> get channelStateChanges => _channelStateController.stream;
  Stream<TrustPromptEvent> get trustPrompts => _trustPromptController.stream;

  BluetoothDevice? _device;
  BluetoothCharacteristic? _transferCharacteristic;
  StreamSubscription<List<int>>? _notifySubscription;
  StreamSubscription<List<ScanResult>>? _scanSubscription;
  Directory? _downloadsDir;

  BluetoothFrameCodec? _frameCodec;
  SecureChannelService? _secureChannel;
  SecureChannelState _channelState = SecureChannelState.idle;
  BluetoothDeviceInfo? _pendingDeviceInfo;
  Completer<bool>? _pendingTrustDecision;
  Uint8List? _connectedPeerIdentityPublicKey;

  Uint8List? get connectedPeerIdentityPublicKey => _connectedPeerIdentityPublicKey;

  Future<void> initialize() async {
    if (Platform.isAndroid) {
      await Permission.bluetooth.request();
      await Permission.bluetoothScan.request();
      await Permission.bluetoothConnect.request();
      await Permission.locationWhenInUse.request();
    }

    await FlutterBluePlus.turnOn();
    _downloadsDir ??= await getApplicationDocumentsDirectory();
    await _trustStore.initialize();
  }

  Future<void> startScanning() async {
    discoveredDevices.clear();
    await _scanSubscription?.cancel();

    _scanSubscription = FlutterBluePlus.scanResults.listen((results) {
      final devices = <BluetoothDeviceInfo>{};
      for (final result in results) {
        final device = result.device;
        final id = device.remoteId.toString();
        final name = device.platformName.isNotEmpty ? device.platformName : id;
        devices.add(
          BluetoothDeviceInfo(id: id, name: name, isConnected: false, device: device),
        );
      }
      discoveredDevices
        ..clear()
        ..addAll(devices.toList());
    });

    await FlutterBluePlus.startScan(timeout: const Duration(seconds: 4));
    await Future<void>.delayed(const Duration(milliseconds: 500));
    await FlutterBluePlus.stopScan();
    await _scanSubscription?.cancel();
    _scanSubscription = null;
  }

  Future<void> connectToDevice(BluetoothDeviceInfo deviceInfo) async {
    await _notifySubscription?.cancel();
    _pendingDeviceInfo = deviceInfo;
    _device = deviceInfo.device ?? BluetoothDevice.fromId(deviceInfo.id);
    await _device!.connect(timeout: const Duration(seconds: 15));

    final services = await _device!.discoverServices();
    for (final service in services) {
      for (final characteristic in service.characteristics) {
        if (characteristic.properties.write && characteristic.properties.notify) {
          _transferCharacteristic = characteristic;
          break;
        }
      }
      if (_transferCharacteristic != null) {
        break;
      }
    }

    if (_transferCharacteristic == null) {
      throw Exception('No compatible characteristic found');
    }

    await _transferCharacteristic!.setNotifyValue(true);

    connectedDevice = BluetoothDeviceInfo(
      id: deviceInfo.id,
      name: deviceInfo.name,
      isConnected: true,
      device: _device,
    );

    _setChannelState(SecureChannelState.handshaking);

    _frameCodec = BluetoothFrameCodec(onFrame: (type, payload) {
      _secureChannel?.receiveFrame(type, payload);
    });

    _secureChannel = SecureChannelService(
      identityService: _identityService,
      isInitiator: true,
      sendFrame: (type, payload) async {
        await _writeBytes(BluetoothFrameCodec.encode(type, payload));
      },
      onHandshakeComplete: (result) => _onHandshakeComplete(result),
      onHandshakeFailed: (reason) => _setChannelState(SecureChannelState.failed),
      onData: (data) => _handleDecryptedData(data),
      onChannelError: (reason) => _setChannelState(SecureChannelState.failed),
    );

    _notifySubscription = _transferCharacteristic!.lastValueStream.listen((data) {
      _frameCodec?.feed(data);
    });

    await _secureChannel!.start();
  }

  Future<void> _onHandshakeComplete(HandshakeResult result) async {
    final identityBase64 = base64.encode(result.peerIdentityPublicKey);
    final decision = await _trustStore.evaluate(
      identityPublicKeyBase64: identityBase64,
      bleId: _pendingDeviceInfo?.id,
      displayName: _pendingDeviceInfo?.name,
    );

    if (decision.isNewDevice || decision.isChanged) {
      _setChannelState(decision.isChanged
          ? SecureChannelState.identityMismatch
          : SecureChannelState.awaitingTrustConfirmation);

      final completer = Completer<bool>();
      _pendingTrustDecision = completer;
      _trustPromptController.add(TrustPromptEvent(
        identityPublicKeyBase64: identityBase64,
        bleId: _pendingDeviceInfo?.id,
        displayName: _pendingDeviceInfo?.name,
        isNewDevice: decision.isNewDevice,
        isChanged: decision.isChanged,
      ));

      final accepted = await completer.future;
      if (!accepted) {
        _setChannelState(SecureChannelState.failed);
        await _teardownConnection();
        return;
      }

      await _trustStore.trust(
        identityPublicKeyBase64: identityBase64,
        bleId: _pendingDeviceInfo?.id,
        displayName: _pendingDeviceInfo?.name,
      );
    }

    _connectedPeerIdentityPublicKey = result.peerIdentityPublicKey;
    _setChannelState(SecureChannelState.established);
  }

  Future<void> respondToTrustPrompt(bool accept) async {
    _pendingTrustDecision?.complete(accept);
    _pendingTrustDecision = null;
  }

  void _setChannelState(SecureChannelState state) {
    _channelState = state;
    _channelStateController.add(state);
  }

  Future<void> sendMessage(String text) async {
    final channel = _secureChannel;
    if (_channelState != SecureChannelState.established || channel == null) {
      return;
    }
    final content = utf8.encode(text);
    final inner = Uint8List.fromList([0, ...content]);
    await channel.sendData(inner);
  }

  Future<void> sendFile(String filePath, {required String fileName}) async {
    final channel = _secureChannel;
    if (_channelState != SecureChannelState.established || channel == null) {
      throw Exception('Secure channel is not established');
    }

    final file = File(filePath);
    final bytes = await file.readAsBytes();
    final nameBytes = utf8.encode(fileName);
    final nameLength = Uint8List(2);
    ByteData.sublistView(nameLength).setUint16(0, nameBytes.length, Endian.big);
    final inner = Uint8List.fromList([1, ...nameLength, ...nameBytes, ...bytes]);
    await channel.sendData(inner);
  }

  void _handleDecryptedData(Uint8List inner) {
    if (inner.isEmpty) {
      return;
    }
    final innerType = inner[0];
    if (innerType == 0) {
      final text = utf8.decode(inner.sublist(1));
      _incomingTextController
          .add(IncomingTextMessage(senderName: 'Nearby device', text: text));
    } else if (innerType == 1) {
      if (inner.length < 3) {
        return;
      }
      final nameLengthBytes = Uint8List.fromList(inner.sublist(1, 3));
      final nameLength = ByteData.sublistView(nameLengthBytes).getUint16(0, Endian.big);
      final nameStart = 3;
      final nameEnd = nameStart + nameLength;
      if (inner.length < nameEnd) {
        return;
      }
      final fileName = utf8.decode(inner.sublist(nameStart, nameEnd));
      final fileBytes = inner.sublist(nameEnd);
      final safeName = fileName.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '_');
      unawaited(_writeIncomingFile(safeName, fileBytes));
    }
  }

  Future<void> _writeIncomingFile(String safeName, List<int> fileBytes) async {
    final filePath = '${_downloadsDir!.path}/$safeName';
    final file = File(filePath);
    await file.writeAsBytes(fileBytes, flush: true);
    _incomingTransferController.add(IncomingTransfer(fileName: safeName, filePath: filePath));
  }

  Future<void> _writeBytes(List<int> data) async {
    if (_transferCharacteristic == null) {
      return;
    }
    await _transferCharacteristic!.write(data, withoutResponse: false);
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }

  Future<void> _teardownConnection() async {
    await _notifySubscription?.cancel();
    _notifySubscription = null;
    await _device?.disconnect();
    _device = null;
    _transferCharacteristic = null;
    _secureChannel = null;
    _frameCodec = null;
    connectedDevice = null;
    _connectedPeerIdentityPublicKey = null;
  }

  Future<void> dispose() async {
    await _notifySubscription?.cancel();
    await _scanSubscription?.cancel();
    await _device?.disconnect();
    await _incomingTextController.close();
    await _incomingTransferController.close();
    await _channelStateController.close();
    await _trustPromptController.close();
  }
}
```

- [ ] **Step 2: Analyze**

Run: `flutter analyze lib/services/bluetooth_chat_service.dart`
Expected: no errors related to this file itself. `chat_screen.dart` will show errors from calling the now-removed `setPassphrase` — expected, fixed in Task 10.

- [ ] **Step 3: Commit**

```bash
git add lib/services/bluetooth_chat_service.dart
git commit -m "feat: drive BLE transport through the secure channel and trust store"
```

---

## Task 10: Update `ChatScreen` — handshake states, trust dialogs, drop passphrase wiring

**Files:**
- Modify: `lib/screens/chat_screen.dart`

**Interfaces:**
- Consumes: `BluetoothChatService.channelStateChanges`, `.trustPrompts`, `.respondToTrustPrompt()`, `.connectedPeerIdentityPublicKey` (Task 9); `SecurityService.getLocalStorageKey()` (Task 7); `ChatStorageService.loadMessages/saveMessages(SecretKey)` (Task 8).

- [ ] **Step 1: Update imports and state fields**

In `lib/screens/chat_screen.dart`, add imports:

```dart
import 'package:cryptography/cryptography.dart';

import '../models/secure_channel_state.dart';
import 'safety_verification_screen.dart';
```

(`safety_verification_screen.dart` is created in Task 12 — this import will not resolve until then; that's expected and fine to leave red until Task 12 lands if executing tasks out of order is ever necessary, but this plan executes them in order so it will already exist.)

Add new state fields alongside the existing ones in `_ChatScreenState`:

```dart
  SecretKey? _localStorageKey;
  SecureChannelState _channelState = SecureChannelState.idle;
  late final StreamSubscription<SecureChannelState> _channelStateSubscription;
  late final StreamSubscription<TrustPromptEvent> _trustPromptSubscription;
```

- [ ] **Step 2: Replace `initState`/`dispose` wiring**

Replace the existing subscription setup in `initState` (the two `_incoming...Subscription = ...` lines) with:

```dart
    _incomingTransferSubscription =
        _service.incomingTransfers.listen(_handleIncomingTransfer);
    _incomingTextSubscription =
        _service.incomingTextMessages.listen(_handleIncomingText);
    _channelStateSubscription =
        _service.channelStateChanges.listen(_handleChannelStateChange);
    _trustPromptSubscription =
        _service.trustPrompts.listen(_handleTrustPrompt);
```

Update `dispose()` to also cancel the two new subscriptions:

```dart
  @override
  void dispose() {
    _messageController.dispose();
    _incomingTransferSubscription.cancel();
    _incomingTextSubscription.cancel();
    _channelStateSubscription.cancel();
    _trustPromptSubscription.cancel();
    _service.dispose();
    super.dispose();
  }
```

- [ ] **Step 3: Replace passphrase-based bootstrap/persist with the local storage key**

Replace `_bootstrap()`'s passphrase lines:

```dart
    final passphrase = await _security.getPassphrase();
    _service.setPassphrase(passphrase);

    final persistedMessages = await _storage.loadMessages(passphrase);
```

with:

```dart
    _localStorageKey = await _security.getLocalStorageKey();

    final persistedMessages = await _storage.loadMessages(_localStorageKey!);
```

Replace `_persistMessages()`:

```dart
  Future<void> _persistMessages() async {
    final passphrase = await _security.getPassphrase();
    await _storage.saveMessages(_messages, passphrase);
  }
```

with:

```dart
  Future<void> _persistMessages() async {
    final key = _localStorageKey ??= await _security.getLocalStorageKey();
    await _storage.saveMessages(_messages, key);
  }
```

- [ ] **Step 4: Add channel-state and trust-prompt handlers**

Add these methods to `_ChatScreenState` (near `_handleIncomingText`):

```dart
  void _handleChannelStateChange(SecureChannelState state) {
    if (!mounted) {
      return;
    }
    setState(() => _channelState = state);
  }

  Future<void> _handleTrustPrompt(TrustPromptEvent event) async {
    if (!mounted) {
      return;
    }

    final accepted = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: Text(event.isChanged ? 'Ключ устройства изменился' : 'Новое устройство'),
        content: Text(
          event.isChanged
              ? 'У устройства "${event.displayName ?? event.bleId}" изменился ключ безопасности. '
                  'Это может значить переустановку приложения — или атаку. Продолжить, только если вы уверены.'
              : 'Устройство "${event.displayName ?? event.bleId}" подключается впервые. Доверять и начать общение?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Отмена'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(event.isChanged ? 'Всё равно продолжить' : 'Доверять'),
          ),
        ],
      ),
    );

    await _service.respondToTrustPrompt(accepted ?? false);
  }
```

- [ ] **Step 5: Replace `_connectToDevice` to remove blind success assumption and reflect handshake state**

Replace the existing `_connectToDevice` body's `setState` block:

```dart
    if (mounted) {
      setState(() {
        _isConnecting = false;
        _messages.add(
          ChatMessage(
            id: DateTime.now().toIso8601String(),
            text: 'Подключились к ${device.name}',
            senderName: 'System',
            isMine: false,
            createdAt: DateTime.now(),
            type: MessageType.text,
          ),
        );
      });
      await _persistMessages();
    }
```

with:

```dart
    if (mounted) {
      setState(() => _isConnecting = false);
    }
```

(The "connected" system message is now added when the channel reaches `established`, not right after the raw BLE connect — add this to `_handleChannelStateChange`:)

```dart
  void _handleChannelStateChange(SecureChannelState state) {
    if (!mounted) {
      return;
    }
    setState(() => _channelState = state);

    if (state == SecureChannelState.established) {
      setState(() {
        _messages.add(
          ChatMessage(
            id: DateTime.now().toIso8601String(),
            text: 'Защищённое соединение установлено с ${_service.connectedDevice?.name ?? 'устройством'}',
            senderName: 'System',
            isMine: false,
            createdAt: DateTime.now(),
            type: MessageType.text,
          ),
        );
      });
      _persistMessages();
    }
  }
```

(Remove the duplicate simpler version added in Step 4 — keep only this one.)

- [ ] **Step 6: Gate sending on `established` and add the "Verify safety" entry point**

In `_sendMessage`, guard the actual send:

```dart
    await _service.sendMessage(text);
```

stays as-is (`BluetoothChatService.sendMessage` already no-ops when not established, per Task 9), but disable the send button visually — in `_buildMessageComposer`, change the send `IconButton`'s `onPressed`:

```dart
                          onPressed: _channelState == SecureChannelState.established
                              ? () => _sendMessage()
                              : null,
```

Add a "Verify safety" action in the app bar, next to the avatar button in `build()`:

```dart
        actions: [
          if (_channelState == SecureChannelState.established &&
              _myIdentityPublicKey != null)
            IconButton(
              onPressed: () {
                final peerKey = _service.connectedPeerIdentityPublicKey;
                final myKey = _myIdentityPublicKey;
                if (peerKey == null || myKey == null) {
                  return;
                }
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => SafetyVerificationScreen(
                      myIdentityPublicKey: myKey,
                      peerIdentityPublicKey: peerKey,
                    ),
                  ),
                );
              },
              icon: const Icon(Icons.verified_user_outlined),
              tooltip: 'Проверить безопасность',
            ),
          IconButton(
            onPressed: _pickAvatar,
            icon: const Icon(Icons.account_circle_outlined),
            tooltip: 'Выбрать аватар',
          ),
        ],
```

This references `_myIdentityPublicKey`, a new field. Add it and populate it during bootstrap — add near the other fields:

```dart
  Uint8List? _myIdentityPublicKey;
  late final IdentityService _identity;
```

and in `initState`, alongside the other service instantiations:

```dart
    _identity = IdentityService();
```

and in `_bootstrap()`, after setting `_localStorageKey`:

```dart
    _myIdentityPublicKey = await _identity.getPublicKeyBytes();
```

Add the corresponding import:

```dart
import 'dart:typed_data';

import '../services/identity_service.dart';
```

- [ ] **Step 7: Analyze**

Run: `flutter analyze lib/screens/chat_screen.dart`
Expected: no errors (assuming Task 12's `SafetyVerificationScreen` already exists per execution order; if run before Task 12, the only error will be the unresolved import, which is expected and resolved by Task 12).

- [ ] **Step 8: Commit**

```bash
git add lib/screens/chat_screen.dart
git commit -m "feat: wire ChatScreen to handshake state, trust prompts, and safety check"
```

---

## Task 11: Remove the shared-passphrase card from `ProfileScreen`

**Files:**
- Modify: `lib/screens/profile_screen.dart`

- [ ] **Step 1: Remove passphrase state and logic**

Delete the `SecurityService _securityService`, `TextEditingController _passphraseController` fields, the `_loadPassphrase()` and `_savePassphrase()` methods, and their calls in `initState`/`dispose`. Remove the `onPassphraseChanged` constructor parameter and its usages.

The resulting constructor becomes:

```dart
class ProfileScreen extends StatefulWidget {
  final ChatProfile profile;
  final ValueChanged<ChatProfile> onProfileChanged;

  const ProfileScreen({
    super.key,
    required this.profile,
    required this.onProfileChanged,
  });

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}
```

And `_ProfileScreenState` keeps only `_profile`, with `_pickAvatar()` unchanged.

- [ ] **Step 2: Remove the "Ключ безопасности" card from `build()`**

Delete the entire `Container` block that renders the "Ключ безопасности" title, `TextField`, and "Сохранить ключ" button (the block between the profile name/subtitle and the "Премиум-план" card).

- [ ] **Step 3: Update the call site in `chat_screen.dart`**

In `lib/screens/chat_screen.dart`, find the `ProfileScreen(...)` construction inside `_buildHeroCard` and remove the `onPassphraseChanged` argument:

```dart
                  builder: (_) => ProfileScreen(
                    profile: _myProfile,
                    onProfileChanged: (profile) {
                      setState(() => _myProfile = profile);
                    },
                  ),
```

- [ ] **Step 4: Analyze**

Run: `flutter analyze lib/screens/profile_screen.dart lib/screens/chat_screen.dart`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add lib/screens/profile_screen.dart lib/screens/chat_screen.dart
git commit -m "refactor: remove shared-passphrase UI from profile screen"
```

---

## Task 12: `SafetyVerificationScreen` — QR display + live scan comparison

**Files:**
- Modify: `pubspec.yaml`
- Create: `lib/screens/safety_verification_screen.dart`

**Interfaces:**
- Consumes: `myIdentityPublicKey: Uint8List`, `peerIdentityPublicKey: Uint8List` (constructor params, sourced from `chat_screen.dart` Task 10 Step 6).

- [ ] **Step 1: Add QR dependencies**

Run:
```bash
flutter pub add qr_flutter mobile_scanner
```

- [ ] **Step 2: Verify pubspec resolved**

Run: `flutter pub get`
Expected: completes without errors.

- [ ] **Step 3: Write `lib/screens/safety_verification_screen.dart`**

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Optional out-of-band verification: shows this device's identity as a QR
/// code and a short numeric fingerprint, and can scan the peer's QR to
/// confirm — cryptographically, not just visually — that the identity key
/// used in the *current live session* matches what the peer is showing.
/// A match rules out a relay/MITM sitting between the two BLE devices.
class SafetyVerificationScreen extends StatefulWidget {
  final Uint8List myIdentityPublicKey;
  final Uint8List peerIdentityPublicKey;

  const SafetyVerificationScreen({
    super.key,
    required this.myIdentityPublicKey,
    required this.peerIdentityPublicKey,
  });

  @override
  State<SafetyVerificationScreen> createState() => _SafetyVerificationScreenState();
}

class _SafetyVerificationScreenState extends State<SafetyVerificationScreen> {
  bool? _scanMatched;

  String get _myQrData => base64.encode(widget.myIdentityPublicKey);

  String _fingerprintFor(Uint8List publicKey) {
    final digest = sha256.convert(publicKey).bytes;
    final groups = <String>[];
    for (var i = 0; i < 4; i++) {
      final chunk = digest.sublist(i * 2, i * 2 + 2);
      final value = (chunk[0] << 8) | chunk[1];
      groups.add(value.toString().padLeft(5, '0'));
    }
    return groups.join(' ');
  }

  void _onDetect(BarcodeCapture capture) {
    if (_scanMatched != null) {
      return;
    }
    final barcodes = capture.barcodes;
    if (barcodes.isEmpty) {
      return;
    }
    final raw = barcodes.first.rawValue;
    if (raw == null) {
      return;
    }

    Uint8List scannedKey;
    try {
      scannedKey = base64.decode(raw);
    } catch (_) {
      return;
    }

    final matches = scannedKey.length == widget.peerIdentityPublicKey.length &&
        _constantTimeEquals(scannedKey, widget.peerIdentityPublicKey);

    setState(() => _scanMatched = matches);
  }

  bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Проверка безопасности')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            const Text(
              'Покажите этот QR собеседнику или отсканируйте его QR, чтобы '
              'убедиться, что вы общаетесь напрямую, а не через посредника.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 20),
            QrImageView(data: _myQrData, size: 220),
            const SizedBox(height: 12),
            Text('Мой код: ${_fingerprintFor(widget.myIdentityPublicKey)}'),
            Text('Код собеседника: ${_fingerprintFor(widget.peerIdentityPublicKey)}'),
            const SizedBox(height: 24),
            if (_scanMatched == null) ...[
              const Text('Отсканируйте QR собеседника:'),
              const SizedBox(height: 12),
              SizedBox(
                height: 260,
                child: MobileScanner(onDetect: _onDetect),
              ),
            ] else if (_scanMatched == true)
              const Column(
                children: [
                  Icon(Icons.verified, color: Colors.green, size: 48),
                  Text('Совпадает — соединение подтверждено',
                      style: TextStyle(fontWeight: FontWeight.w700)),
                ],
              )
            else
              const Column(
                children: [
                  Icon(Icons.error, color: Colors.red, size: 48),
                  Text('НЕ совпадает — возможна атака',
                      style: TextStyle(fontWeight: FontWeight.w700, color: Colors.red)),
                ],
              ),
          ],
        ),
      ),
    );
  }
}
```

- [ ] **Step 4: Analyze**

Run: `flutter analyze lib/screens/safety_verification_screen.dart`
Expected: no errors. If `QrImageView`/`MobileScanner`/`BarcodeCapture` names don't match the resolved package versions, check `flutter pub deps` output and adjust to the actual widget/class names from the installed `qr_flutter`/`mobile_scanner` versions — the intent (render own key as QR, scan peer's QR, compare bytes) must stay the same.

- [ ] **Step 5: Add required Android/iOS permissions for camera scanning**

In `android/app/src/main/AndroidManifest.xml`, ensure a camera permission entry exists (add if missing, alongside existing `<uses-permission>` entries):

```xml
    <uses-permission android:name="android.permission.CAMERA" />
```

In `ios/Runner/Info.plist`, add (if missing) inside the top-level `<dict>`:

```xml
	<key>NSCameraUsageDescription</key>
	<string>Камера нужна, чтобы отсканировать QR-код для проверки безопасности соединения</string>
```

- [ ] **Step 6: Commit**

```bash
git add pubspec.yaml pubspec.lock lib/screens/safety_verification_screen.dart android/app/src/main/AndroidManifest.xml ios/Runner/Info.plist
git commit -m "feat: add optional QR-based safety verification screen"
```

---

## Task 13: Final integration pass

**Files:**
- Modify: `README.md`
- No new source files.

- [ ] **Step 1: Run the full analyzer**

Run: `flutter analyze`
Expected: no errors across the whole project (the `test/widget_test.dart` smoke test and all files from Tasks 1–12 included). Fix anything that surfaces — most likely leftover references to removed passphrase APIs.

- [ ] **Step 2: Run the full test suite**

Run: `flutter test`
Expected: all tests pass — `test/widget_test.dart` plus every test added in Tasks 2, 4, 5, 6, 8.

- [ ] **Step 3: Update `README.md`**

In the "Notes" section, replace:

```markdown
The current version is a polished starter UI. For a production Bluetooth transport, you can connect the service layer to `flutter_blue_plus` and implement real BLE messaging.
```

with:

```markdown
The current version is a polished starter UI. Messages are protected by a mutual-authentication handshake (Ed25519 device identity + ephemeral X25519 ECDH, ChaCha20-Poly1305 AEAD with replay-safe counters) instead of a shared passphrase — see `docs/superpowers/specs/2026-08-11-secure-pairing-protocol-design.md` for the protocol design. Note: this app currently only implements the BLE *central/client* role (`connectToDevice`), so two phones running this app cannot yet connect to each other directly — a BLE peripheral/GATT-server role is a separate, not-yet-implemented piece of work.
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: describe the new mutual-auth protocol and note the missing peripheral role"
```
