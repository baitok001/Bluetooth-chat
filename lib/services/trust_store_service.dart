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
