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
