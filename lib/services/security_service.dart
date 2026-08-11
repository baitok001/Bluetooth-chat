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
