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
      final senderName =
          await decryptField(row['sender_name'] as String?, localKey);
      messages.add(ChatMessage(
        id: row['id'] as String,
        text: await decryptField(row['text'] as String?, localKey),
        senderName: senderName.isEmpty ? 'You' : senderName,
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
