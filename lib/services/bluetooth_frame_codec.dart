import 'dart:typed_data';

import 'secure_channel_service.dart';

/// Encodes/decodes the BLE wire format: `[1 byte frame type][4 byte
/// big-endian length][payload]`. Replaces the old newline-delimited ASCII
/// framing, which could corrupt on any binary payload containing a literal
/// newline byte.
class BluetoothFrameCodec {
  static const _headerLength = 5;

  final void Function(FrameType type, Uint8List payload) onFrame;
  final List<int> _buffer = [];

  BluetoothFrameCodec({required this.onFrame});

  static Uint8List encode(FrameType type, Uint8List payload) {
    final frame = Uint8List(_headerLength + payload.length);
    frame[0] = _tagFor(type);
    ByteData.sublistView(frame, 1, 5).setUint32(0, payload.length, Endian.big);
    frame.setRange(_headerLength, frame.length, payload);
    return frame;
  }

  void feed(List<int> chunk) {
    _buffer.addAll(chunk);

    while (true) {
      if (_buffer.length < _headerLength) {
        return;
      }

      final tag = _buffer[0];
      final lengthBytes = Uint8List.fromList(_buffer.sublist(1, _headerLength));
      final length = ByteData.sublistView(lengthBytes).getUint32(0, Endian.big);

      if (_buffer.length < _headerLength + length) {
        return;
      }

      final payload = Uint8List.fromList(
          _buffer.sublist(_headerLength, _headerLength + length));
      _buffer.removeRange(0, _headerLength + length);

      final type = _typeFor(tag);
      if (type != null) {
        onFrame(type, payload);
      }
    }
  }

  static int _tagFor(FrameType type) {
    switch (type) {
      case FrameType.hello:
        return 0x01;
      case FrameType.response:
        return 0x02;
      case FrameType.finished:
        return 0x03;
      case FrameType.data:
        return 0x04;
    }
  }

  static FrameType? _typeFor(int tag) {
    switch (tag) {
      case 0x01:
        return FrameType.hello;
      case 0x02:
        return FrameType.response;
      case 0x03:
        return FrameType.finished;
      case 0x04:
        return FrameType.data;
      default:
        return null;
    }
  }
}
