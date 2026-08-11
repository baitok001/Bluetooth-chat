import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

import '../models/secure_channel_state.dart';
import 'bluetooth_frame_codec.dart';
import 'identity_service.dart';
import 'secure_channel_service.dart';
import 'trust_store_service.dart';

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

class TrustPromptEvent {
  final String identityPublicKeyBase64;
  final String? bleId;
  final String? displayName;
  final bool isNewDevice;
  final bool isChanged;

  const TrustPromptEvent({
    required this.identityPublicKeyBase64,
    this.bleId,
    this.displayName,
    required this.isNewDevice,
    required this.isChanged,
  });
}

class BluetoothChatService {
  final List<BluetoothDeviceInfo> discoveredDevices = [];
  BluetoothDeviceInfo? connectedDevice;

  final IdentityService _identityService;
  final TrustStoreService _trustStore;

  BluetoothChatService({
    IdentityService? identityService,
    TrustStoreService? trustStore,
  })  : _identityService = identityService ?? IdentityService(),
        _trustStore = trustStore ?? TrustStoreService();

  final StreamController<IncomingTransfer> _incomingTransferController =
      StreamController.broadcast();
  final StreamController<IncomingTextMessage> _incomingTextController =
      StreamController.broadcast();
  final StreamController<SecureChannelState> _channelStateController =
      StreamController.broadcast();
  final StreamController<TrustPromptEvent> _trustPromptController =
      StreamController.broadcast();

  Stream<IncomingTransfer> get incomingTransfers => _incomingTransferController.stream;
  Stream<IncomingTextMessage> get incomingTextMessages => _incomingTextController.stream;
  Stream<SecureChannelState> get channelStateChanges => _channelStateController.stream;
  Stream<TrustPromptEvent> get trustPrompts => _trustPromptController.stream;

  BluetoothDevice? _device;
  BluetoothCharacteristic? _transferCharacteristic;
  StreamSubscription<List<int>>? _notifySubscription;
  StreamSubscription<List<ScanResult>>? _scanSubscription;
  Directory? _downloadsDir;

  BluetoothFrameCodec? _frameCodec;
  SecureChannelService? _secureChannel;
  SecureChannelState _channelState = SecureChannelState.idle;
  BluetoothDeviceInfo? _pendingDeviceInfo;
  Completer<bool>? _pendingTrustDecision;
  Uint8List? _connectedPeerIdentityPublicKey;

  Uint8List? get connectedPeerIdentityPublicKey => _connectedPeerIdentityPublicKey;

  Future<void> initialize() async {
    if (Platform.isAndroid) {
      await Permission.bluetooth.request();
      await Permission.bluetoothScan.request();
      await Permission.bluetoothConnect.request();
      await Permission.locationWhenInUse.request();
    }

    await FlutterBluePlus.turnOn();
    _downloadsDir ??= await getApplicationDocumentsDirectory();
    await _trustStore.initialize();
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
          BluetoothDeviceInfo(id: id, name: name, isConnected: false, device: device),
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
    _pendingDeviceInfo = deviceInfo;
    _device = deviceInfo.device ?? BluetoothDevice.fromId(deviceInfo.id);
    await _device!.connect(timeout: const Duration(seconds: 15));

    final services = await _device!.discoverServices();
    for (final service in services) {
      for (final characteristic in service.characteristics) {
        if (characteristic.properties.write && characteristic.properties.notify) {
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

    connectedDevice = BluetoothDeviceInfo(
      id: deviceInfo.id,
      name: deviceInfo.name,
      isConnected: true,
      device: _device,
    );

    _setChannelState(SecureChannelState.handshaking);

    _frameCodec = BluetoothFrameCodec(onFrame: (type, payload) {
      _secureChannel?.receiveFrame(type, payload);
    });

    _secureChannel = SecureChannelService(
      identityService: _identityService,
      isInitiator: true,
      sendFrame: (type, payload) async {
        await _writeBytes(BluetoothFrameCodec.encode(type, payload));
      },
      onHandshakeComplete: (result) => _onHandshakeComplete(result),
      onHandshakeFailed: (reason) => _setChannelState(SecureChannelState.failed),
      onData: (data) => _handleDecryptedData(data),
      onChannelError: (reason) => _setChannelState(SecureChannelState.failed),
    );

    _notifySubscription = _transferCharacteristic!.lastValueStream.listen((data) {
      _frameCodec?.feed(data);
    });

    await _secureChannel!.start();
  }

  Future<void> _onHandshakeComplete(HandshakeResult result) async {
    final identityBase64 = base64.encode(result.peerIdentityPublicKey);
    final decision = await _trustStore.evaluate(
      identityPublicKeyBase64: identityBase64,
      bleId: _pendingDeviceInfo?.id,
      displayName: _pendingDeviceInfo?.name,
    );

    if (decision.isNewDevice || decision.isChanged) {
      _setChannelState(decision.isChanged
          ? SecureChannelState.identityMismatch
          : SecureChannelState.awaitingTrustConfirmation);

      final completer = Completer<bool>();
      _pendingTrustDecision = completer;
      _trustPromptController.add(TrustPromptEvent(
        identityPublicKeyBase64: identityBase64,
        bleId: _pendingDeviceInfo?.id,
        displayName: _pendingDeviceInfo?.name,
        isNewDevice: decision.isNewDevice,
        isChanged: decision.isChanged,
      ));

      final accepted = await completer.future;
      if (!accepted) {
        _setChannelState(SecureChannelState.failed);
        await _teardownConnection();
        return;
      }

      await _trustStore.trust(
        identityPublicKeyBase64: identityBase64,
        bleId: _pendingDeviceInfo?.id,
        displayName: _pendingDeviceInfo?.name,
      );
    }

    _connectedPeerIdentityPublicKey = result.peerIdentityPublicKey;
    _setChannelState(SecureChannelState.established);
  }

  Future<void> respondToTrustPrompt(bool accept) async {
    _pendingTrustDecision?.complete(accept);
    _pendingTrustDecision = null;
  }

  void _setChannelState(SecureChannelState state) {
    _channelState = state;
    _channelStateController.add(state);
  }

  Future<void> sendMessage(String text) async {
    final channel = _secureChannel;
    if (_channelState != SecureChannelState.established || channel == null) {
      return;
    }
    final content = utf8.encode(text);
    final inner = Uint8List.fromList([0, ...content]);
    await channel.sendData(inner);
  }

  Future<void> sendFile(String filePath, {required String fileName}) async {
    final channel = _secureChannel;
    if (_channelState != SecureChannelState.established || channel == null) {
      throw Exception('Secure channel is not established');
    }

    final file = File(filePath);
    final bytes = await file.readAsBytes();
    final nameBytes = utf8.encode(fileName);
    final nameLength = Uint8List(2);
    ByteData.sublistView(nameLength).setUint16(0, nameBytes.length, Endian.big);
    final inner = Uint8List.fromList([1, ...nameLength, ...nameBytes, ...bytes]);
    await channel.sendData(inner);
  }

  void _handleDecryptedData(Uint8List inner) {
    if (inner.isEmpty) {
      return;
    }
    final innerType = inner[0];
    if (innerType == 0) {
      final text = utf8.decode(inner.sublist(1));
      _incomingTextController
          .add(IncomingTextMessage(senderName: 'Nearby device', text: text));
    } else if (innerType == 1) {
      if (inner.length < 3) {
        return;
      }
      final nameLengthBytes = Uint8List.fromList(inner.sublist(1, 3));
      final nameLength = ByteData.sublistView(nameLengthBytes).getUint16(0, Endian.big);
      const nameStart = 3;
      final nameEnd = nameStart + nameLength;
      if (inner.length < nameEnd) {
        return;
      }
      final fileName = utf8.decode(inner.sublist(nameStart, nameEnd));
      final fileBytes = inner.sublist(nameEnd);
      final safeName = fileName.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '_');
      unawaited(_writeIncomingFile(safeName, fileBytes));
    }
  }

  Future<void> _writeIncomingFile(String safeName, List<int> fileBytes) async {
    final filePath = '${_downloadsDir!.path}/$safeName';
    final file = File(filePath);
    await file.writeAsBytes(fileBytes, flush: true);
    _incomingTransferController.add(IncomingTransfer(fileName: safeName, filePath: filePath));
  }

  Future<void> _writeBytes(List<int> data) async {
    if (_transferCharacteristic == null) {
      return;
    }
    await _transferCharacteristic!.write(data, withoutResponse: false);
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }

  Future<void> _teardownConnection() async {
    await _notifySubscription?.cancel();
    _notifySubscription = null;
    await _device?.disconnect();
    _device = null;
    _transferCharacteristic = null;
    _secureChannel = null;
    _frameCodec = null;
    connectedDevice = null;
    _connectedPeerIdentityPublicKey = null;
  }

  Future<void> dispose() async {
    await _notifySubscription?.cancel();
    await _scanSubscription?.cancel();
    await _device?.disconnect();
    await _incomingTextController.close();
    await _incomingTransferController.close();
    await _channelStateController.close();
    await _trustPromptController.close();
  }
}
