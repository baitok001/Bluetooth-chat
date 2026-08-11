import 'dart:convert';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:sqflite/sqflite.dart';

import '../models/chat_message.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class ChatStorageService {
  static const _databaseName = 'chat_history.db';
  static const _tableName = 'chat_messages';

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
        ''');
      },
    );
  }

  Future<List<ChatMessage>> loadMessages(String passphrase) async {
    final database = _database;
    if (database == null) {
      throw StateError('Chat storage is not initialized');
    }

    final rows = await database.query(
      _tableName,
      orderBy: 'created_at ASC',
    );

    return rows.map((row) {
      final typeIndex = row['type'] as int? ?? 0;
      return ChatMessage(
        id: row['id'] as String,
        text: _decryptValue(row['text'] as String?, passphrase),
        senderName:
            _decryptValue(row['sender_name'] as String?, passphrase) ?? 'You',
        isMine: (row['is_mine'] as int?) == 1,
        createdAt: DateTime.parse(row['created_at'] as String),
        avatarPath: row['avatar_path'] as String?,
        type: MessageType.values[typeIndex],
        filePath: row['file_path'] as String?,
        fileName: _decryptValue(row['file_name'] as String?, passphrase),
      );
    }).toList();
  }

  Future<void> saveMessages(
      List<ChatMessage> messages, String passphrase) async {
    final database = _database;
    if (database == null) {
      throw StateError('Chat storage is not initialized');
    }

    await database.transaction((txn) async {
      await txn.delete(_tableName);
      for (final message in messages) {
        await txn.insert(_tableName, {
          'id': message.id,
          'text': _encryptValue(message.text, passphrase),
          'sender_name': _encryptValue(message.senderName, passphrase),
          'is_mine': message.isMine ? 1 : 0,
          'created_at': message.createdAt.toIso8601String(),
          'avatar_path': message.avatarPath,
          'type': message.type.index,
          'file_path': message.filePath,
          'file_name': _encryptValue(message.fileName ?? '', passphrase),
        });
      }
    });
  }

  String _encryptValue(String value, String passphrase) {
    if (value.isEmpty) {
      return '';
    }

    final key = Key(_deriveKey(passphrase));
    final iv = IV.fromLength(16);
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
    final encrypted = encrypter.encrypt(value, iv: iv);
    return '${base64.encode(iv.bytes)}:${encrypted.base64}';
  }

  String _decryptValue(String? value, String passphrase) {
    if (value == null || value.isEmpty) {
      return '';
    }

    final split = value.split(':');
    if (split.length != 2) {
      return value;
    }

    final key = Key(_deriveKey(passphrase));
    final iv = IV(base64.decode(split.first));
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
    return encrypter.decrypt64(split.last, iv: iv);
  }

  Uint8List _deriveKey(String passphrase) {
    final digest = sha256.convert(utf8.encode(passphrase)).bytes;
    final padded = List<int>.from(digest);
    while (padded.length < 32) {
      padded.addAll(digest);
    }
    return Uint8List.fromList(padded.take(32).toList());
  }
}
