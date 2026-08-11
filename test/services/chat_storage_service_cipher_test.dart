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
