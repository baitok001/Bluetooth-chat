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
