import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

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

class BluetoothChatService {
  final List<BluetoothDeviceInfo> discoveredDevices = [];
  BluetoothDeviceInfo? connectedDevice;

  final StreamController<IncomingTransfer> _incomingTransferController =
      StreamController.broadcast();
  final StreamController<IncomingTextMessage> _incomingTextController =
      StreamController.broadcast();

  Stream<IncomingTransfer> get incomingTransfers =>
      _incomingTransferController.stream;
  Stream<IncomingTextMessage> get incomingTextMessages =>
      _incomingTextController.stream;

  BluetoothDevice? _device;
  BluetoothCharacteristic? _transferCharacteristic;
  StreamSubscription<List<int>>? _notifySubscription;
  StreamSubscription<List<ScanResult>>? _scanSubscription;
  Directory? _downloadsDir;
  String? _passphrase;

  final List<int> _receiveBuffer = [];
  bool _waitingForPayload = false;
  String? _pendingType;
  String? _pendingFileName;
  int? _pendingPayloadSize;
  final List<int> _pendingPayload = [];

  Future<void> initialize() async {
    if (Platform.isAndroid) {
      await Permission.bluetooth.request();
      await Permission.bluetoothScan.request();
      await Permission.bluetoothConnect.request();
      await Permission.locationWhenInUse.request();
    }

    await FlutterBluePlus.turnOn();
    _downloadsDir ??= await getApplicationDocumentsDirectory();
  }

  void setPassphrase(String passphrase) {
    _passphrase = passphrase;
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
          BluetoothDeviceInfo(
              id: id, name: name, isConnected: false, device: device),
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
    _device = deviceInfo.device ?? BluetoothDevice.fromId(deviceInfo.id);
    await _device!.connect(timeout: const Duration(seconds: 15));

    final services = await _device!.discoverServices();
    for (final service in services) {
      for (final characteristic in service.characteristics) {
        if (characteristic.properties.write &&
            characteristic.properties.notify) {
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
    _notifySubscription =
        _transferCharacteristic!.lastValueStream.listen(_handleIncomingBytes);

    connectedDevice = BluetoothDeviceInfo(
      id: deviceInfo.id,
      name: deviceInfo.name,
      isConnected: true,
      device: _device,
    );
  }

  Future<void> sendMessage(String text) async {
    if (_transferCharacteristic == null) {
      return;
    }

    final payload = utf8.encode(_encryptText(text));
    await _writeBytes(utf8.encode('MSG|${payload.length}\n'));
    await _writeBytes(payload);
  }

  Future<void> sendFile(String filePath, {required String fileName}) async {
    if (_transferCharacteristic == null) {
      throw Exception('No Bluetooth connection');
    }

    final file = File(filePath);
    final bytes = await file.readAsBytes();
    final payload = _encryptBytes(bytes);
    final header = utf8.encode('FILE|$fileName|${payload.length}\n');
    await _writeBytes(header);
    await _writeBytes(payload);
  }

  Future<void> _writeBytes(List<int> data) async {
    if (_transferCharacteristic == null) {
      return;
    }

    await _transferCharacteristic!.write(data, withoutResponse: false);
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }

  void _handleIncomingBytes(List<int> data) {
    _receiveBuffer.addAll(data);

    while (true) {
      if (!_waitingForPayload) {
        final newlineIndex = _receiveBuffer.indexOf(10);
        if (newlineIndex < 0) {
          return;
        }

        final headerBytes = _receiveBuffer.sublist(0, newlineIndex);
        _receiveBuffer.removeRange(0, newlineIndex + 1);
        final header = utf8.decode(headerBytes);
        final parts = header.split('|');
        if (parts.isNotEmpty && parts[0] == 'MSG' && parts.length == 2) {
          _pendingType = 'MSG';
          _pendingPayloadSize = int.tryParse(parts[1]) ?? 0;
          _pendingPayload.clear();
          _waitingForPayload = true;
          if (_pendingPayloadSize == 0) {
            _completeIncomingPayload();
            return;
          }
          continue;
        }

        if (parts.isNotEmpty && parts[0] == 'FILE' && parts.length == 3) {
          _pendingType = 'FILE';
          _pendingFileName = parts[1];
          _pendingPayloadSize = int.tryParse(parts[2]) ?? 0;
          _pendingPayload.clear();
          _waitingForPayload = true;
          if (_pendingPayloadSize == 0) {
            _completeIncomingPayload();
            return;
          }
          continue;
        }

        return;
      }

      if (_pendingPayloadSize == null) {
        _resetPending();
        return;
      }

      final bytesNeeded = _pendingPayloadSize! - _pendingPayload.length;
      if (bytesNeeded <= 0) {
        _completeIncomingPayload();
        return;
      }

      final available = _receiveBuffer.length;
      final takeCount = bytesNeeded < available ? bytesNeeded : available;
      if (takeCount <= 0) {
        return;
      }

      _pendingPayload.addAll(_receiveBuffer.sublist(0, takeCount));
      _receiveBuffer.removeRange(0, takeCount);

      if (_pendingPayload.length >= _pendingPayloadSize!) {
        _completeIncomingPayload();
        return;
      }

      return;
    }
  }

  Future<void> _completeIncomingPayload() async {
    if (_pendingPayloadSize == null) {
      _resetPending();
      return;
    }

    if (_pendingPayload.length < _pendingPayloadSize!) {
      _resetPending();
      return;
    }

    final payloadBytes = List<int>.from(_pendingPayload);
    try {
      if (_pendingType == 'MSG') {
        final text = _decryptText(utf8.decode(payloadBytes));
        _incomingTextController.add(
          IncomingTextMessage(senderName: 'Nearby device', text: text),
        );
      } else if (_pendingType == 'FILE') {
        final fileBytes = _decryptBytes(payloadBytes);
        final safeName = (_pendingFileName ?? 'received_file')
            .replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '_');
        final filePath = '${_downloadsDir!.path}/$safeName';
        final file = File(filePath);
        await file.writeAsBytes(fileBytes, flush: true);
        _incomingTransferController.add(
          IncomingTransfer(fileName: safeName, filePath: filePath),
        );
      }
    } finally {
      _resetPending();
    }
  }

  String _encryptText(String text) {
    if ((_passphrase ?? '').isEmpty) {
      return text;
    }

    final key = Key(Uint8List.fromList(_deriveKeyBytes(_passphrase!)));
    final iv = IV.fromLength(16);
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
    final encrypted = encrypter.encrypt(text, iv: iv);
    return '${base64.encode(iv.bytes)}:${encrypted.base64}';
  }

  String _decryptText(String payload) {
    if ((_passphrase ?? '').isEmpty) {
      return payload;
    }

    final parts = payload.split(':');
    if (parts.length != 2) {
      return payload;
    }

    final key = Key(Uint8List.fromList(_deriveKeyBytes(_passphrase!)));
    final iv = IV(base64.decode(parts.first));
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
    return encrypter.decrypt64(parts.last, iv: iv);
  }

  List<int> _encryptBytes(List<int> input) {
    final plainText = base64.encode(input);
    return utf8.encode(_encryptText(plainText));
  }

  List<int> _decryptBytes(List<int> input) {
    final payload = utf8.decode(input);
    final plainText = _decryptText(payload);
    return base64.decode(plainText);
  }

  List<int> _deriveKeyBytes(String passphrase) {
    final digest = sha256.convert(utf8.encode(passphrase)).bytes;
    final padded = List<int>.from(digest);
    while (padded.length < 32) {
      padded.addAll(digest);
    }
    return padded.take(32).toList();
  }

  void _resetPending() {
    _waitingForPayload = false;
    _pendingType = null;
    _pendingFileName = null;
    _pendingPayloadSize = null;
    _pendingPayload.clear();
  }

  Future<void> dispose() async {
    await _notifySubscription?.cancel();
    await _scanSubscription?.cancel();
    await _device?.disconnect();
    await _incomingTextController.close();
    await _incomingTransferController.close();
  }
}
