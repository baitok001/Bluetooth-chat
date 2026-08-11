// Basic smoke test.
//
// This intentionally does not pump the full BluetoothChatApp/ChatScreen
// tree: ChatScreen.initState kicks off real sqflite/flutter_secure_storage/
// path_provider plugin calls, which have no platform channel to answer in a
// headless `flutter test` run (this was true before the secure-pairing
// protocol work too — it's a plugin-testing limitation, not something this
// change introduced). Exercising that flow needs fakes/mocks for those
// plugins, which is out of scope here.

import 'package:bluetooth_chat_app/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('BluetoothChatApp can be constructed', () {
    expect(() => const BluetoothChatApp(), returnsNormally);
  });
}
