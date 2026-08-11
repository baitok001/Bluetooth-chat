import 'dart:typed_data';

import 'package:bluetooth_chat_app/services/bluetooth_frame_codec.dart';
import 'package:bluetooth_chat_app/services/secure_channel_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('BluetoothFrameCodec', () {
    test('encodes and decodes a single frame', () {
      final frames = <MapEntry<FrameType, Uint8List>>[];
      final codec = BluetoothFrameCodec(onFrame: (t, p) => frames.add(MapEntry(t, p)));

      final encoded =
          BluetoothFrameCodec.encode(FrameType.data, Uint8List.fromList([1, 2, 3]));
      codec.feed(encoded);

      expect(frames, hasLength(1));
      expect(frames.first.key, FrameType.data);
      expect(frames.first.value, equals([1, 2, 3]));
    });

    test('handles a frame split across multiple chunks', () {
      final frames = <MapEntry<FrameType, Uint8List>>[];
      final codec = BluetoothFrameCodec(onFrame: (t, p) => frames.add(MapEntry(t, p)));

      final payload = Uint8List.fromList(List.generate(200, (i) => i % 256));
      final encoded = BluetoothFrameCodec.encode(FrameType.hello, payload);

      codec.feed(encoded.sublist(0, 3));
      expect(frames, isEmpty);
      codec.feed(encoded.sublist(3));

      expect(frames, hasLength(1));
      expect(frames.first.value, equals(payload));
    });

    test('handles two frames arriving in a single chunk', () {
      final frames = <MapEntry<FrameType, Uint8List>>[];
      final codec = BluetoothFrameCodec(onFrame: (t, p) => frames.add(MapEntry(t, p)));

      final a = BluetoothFrameCodec.encode(FrameType.finished, Uint8List.fromList([9, 9]));
      final b = BluetoothFrameCodec.encode(FrameType.data, Uint8List.fromList([7]));
      codec.feed([...a, ...b]);

      expect(frames, hasLength(2));
      expect(frames[0].key, FrameType.finished);
      expect(frames[1].key, FrameType.data);
    });
  });
}
