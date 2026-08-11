import 'dart:convert';
import 'dart:typed_data';

import 'package:bluetooth_chat_app/services/identity_service.dart';
import 'package:bluetooth_chat_app/services/secure_channel_service.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List _seed(int fill) => Uint8List.fromList(List.filled(32, fill));

class _Peer {
  final IdentityService identity;
  late final SecureChannelService channel;
  _Peer? other;
  Uint8List Function(FrameType type, Uint8List payload)? outgoingTransform;

  HandshakeResult? handshakeResult;
  String? handshakeFailure;
  String? channelError;
  final List<Uint8List> received = [];
  final List<MapEntry<FrameType, Uint8List>> sentFrames = [];

  _Peer(Uint8List seed, {required bool isInitiator})
      : identity = IdentityService.withSeedForTesting(seed) {
    channel = SecureChannelService(
      identityService: identity,
      isInitiator: isInitiator,
      sendFrame: (type, payload) async {
        sentFrames.add(MapEntry(type, payload));
        final transform = outgoingTransform;
        final outgoing = transform != null ? transform(type, payload) : payload;
        final target = other;
        if (target == null) return;
        await target.channel.receiveFrame(type, outgoing);
      },
      onHandshakeComplete: (result) => handshakeResult = result,
      onHandshakeFailed: (reason) => handshakeFailure = reason,
      onData: (data) => received.add(data),
      onChannelError: (reason) => channelError = reason,
    );
  }
}

void main() {
  group('SecureChannelService', () {
    test('completes a handshake and exchanges authenticated data both ways',
        () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;

      await initiator.channel.start();

      expect(initiator.handshakeResult, isNotNull);
      expect(responder.handshakeResult, isNotNull);

      final responderIdentityPublicKey = await responder.identity.getPublicKeyBytes();
      final initiatorIdentityPublicKey = await initiator.identity.getPublicKeyBytes();

      expect(initiator.handshakeResult!.peerIdentityPublicKey,
          equals(responderIdentityPublicKey));
      expect(responder.handshakeResult!.peerIdentityPublicKey,
          equals(initiatorIdentityPublicKey));

      await initiator.channel.sendData(Uint8List.fromList(utf8.encode('hello')));
      expect(responder.received, hasLength(1));
      expect(utf8.decode(responder.received.first), equals('hello'));

      await responder.channel.sendData(Uint8List.fromList(utf8.encode('hi back')));
      expect(initiator.received, hasLength(1));
      expect(utf8.decode(initiator.received.first), equals('hi back'));
    });

    test('rejects a forged RESPONSE signature', () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;
      responder.outgoingTransform = (type, payload) {
        if (type != FrameType.response) return payload;
        final tampered = Uint8List.fromList(payload);
        tampered[tampered.length - 1] ^= 0xFF; // flip a bit inside sig_r
        return tampered;
      };

      await initiator.channel.start();

      expect(initiator.handshakeResult, isNull);
      expect(initiator.handshakeFailure, isNotNull);
      expect(initiator.handshakeFailure, contains('signature'));
    });

    test('rejects a replayed DATA frame', () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;
      await initiator.channel.start();

      await initiator.channel.sendData(Uint8List.fromList(utf8.encode('once')));
      expect(responder.received, hasLength(1));

      final dataFrame =
          initiator.sentFrames.lastWhere((entry) => entry.key == FrameType.data);
      await responder.channel.receiveFrame(dataFrame.key, dataFrame.value);

      expect(responder.received, hasLength(1));
      expect(responder.channelError, isNotNull);
    });

    test('rejects a tampered DATA ciphertext', () async {
      final initiator = _Peer(_seed(1), isInitiator: true);
      final responder = _Peer(_seed(2), isInitiator: false);
      initiator.other = responder;
      responder.other = initiator;
      await initiator.channel.start();

      initiator.outgoingTransform = (type, payload) {
        if (type != FrameType.data) return payload;
        final tampered = Uint8List.fromList(payload);
        tampered[0] ^= 0xFF;
        return tampered;
      };

      await initiator.channel.sendData(Uint8List.fromList(utf8.encode('tamper me')));

      expect(responder.received, isEmpty);
      expect(responder.channelError, isNotNull);
    });
  });
}
