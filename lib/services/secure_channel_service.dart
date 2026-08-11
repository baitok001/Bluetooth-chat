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
