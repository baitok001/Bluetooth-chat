import 'dart:math';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecurityService {
  static const _passphraseKey = 'chat_passphrase';
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();

  Future<String> getPassphrase() async {
    final stored = await _secureStorage.read(key: _passphraseKey);
    if (stored != null && stored.isNotEmpty) {
      return stored;
    }

    final generated = _generatePassphrase();
    await _secureStorage.write(key: _passphraseKey, value: generated);
    return generated;
  }

  Future<void> setPassphrase(String passphrase) async {
    await _secureStorage.write(key: _passphraseKey, value: passphrase);
  }

  String _generatePassphrase() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    final random = Random.secure();
    return List.generate(16, (_) => chars[random.nextInt(chars.length)]).join();
  }
}
