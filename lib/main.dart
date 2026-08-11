import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import 'screens/chat_screen.dart';

void main() {
  runApp(const BluetoothChatApp());
}

class BluetoothChatApp extends StatelessWidget {
  const BluetoothChatApp({super.key});

  @override
  Widget build(BuildContext context) {
    final baseTextTheme = Typography.material2021().black.apply(
      bodyColor: const Color(0xFF1E1B3A),
      displayColor: const Color(0xFF1E1B3A),
    );

    return MaterialApp(
      title: 'Nearby Chat',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF7B61FF)),
        scaffoldBackgroundColor: const Color(0xFFF8F7FF),
        appBarTheme: const AppBarTheme(
          backgroundColor: Colors.transparent,
          foregroundColor: Color(0xFF1E1B3A),
          elevation: 0,
        ),
        textTheme: GoogleFonts.plusJakartaSansTextTheme(baseTextTheme),
        useMaterial3: true,
      ),
      home: const ChatScreen(),
    );
  }
}
