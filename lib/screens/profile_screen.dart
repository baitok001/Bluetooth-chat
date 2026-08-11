import 'dart:io';

import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';

import '../models/chat_profile.dart';

class ProfileScreen extends StatefulWidget {
  final ChatProfile profile;
  final ValueChanged<ChatProfile> onProfileChanged;

  const ProfileScreen({
    super.key,
    required this.profile,
    required this.onProfileChanged,
  });

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  late ChatProfile _profile;

  @override
  void initState() {
    super.initState();
    _profile = widget.profile;
  }

  Future<void> _pickAvatar() async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(source: ImageSource.gallery);
    if (pickedFile == null) {
      return;
    }

    setState(() {
      _profile = _profile.copyWith(avatarPath: pickedFile.path);
    });
    widget.onProfileChanged(_profile);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF8F7FF),
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: const Text('Профиль'),
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              const SizedBox(height: 24),
              GestureDetector(
                onTap: _pickAvatar,
                child: Container(
                  padding: const EdgeInsets.all(3),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: const LinearGradient(
                        colors: [Color(0xFF7B61FF), Color(0xFF1FCEB4)]),
                  ),
                  child: CircleAvatar(
                    radius: 56,
                    backgroundColor: Colors.white,
                    backgroundImage: _profile.avatarPath != null
                        ? FileImage(File(_profile.avatarPath!))
                        : null,
                    child: _profile.avatarPath == null
                        ? Text(_profile.name.substring(0, 1),
                            style: const TextStyle(fontSize: 32))
                        : null,
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Text(_profile.name,
                  style: const TextStyle(
                      fontSize: 24, fontWeight: FontWeight.w800)),
              const SizedBox(height: 8),
              const Text('В сети • доступен для общения',
                  style: TextStyle(color: Colors.grey, fontSize: 14)),
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF111827),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Премиум-план',
                        style: TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.w800,
                            fontSize: 16)),
                    const SizedBox(height: 8),
                    const Text('• Безлимитные Bluetooth-сессии',
                        style: TextStyle(color: Colors.white70)),
                    const Text('• Облачное резервное копирование',
                        style: TextStyle(color: Colors.white70)),
                    const Text('• Премиум-стили и скрытые темы',
                        style: TextStyle(color: Colors.white70)),
                  ],
                ),
              ),
              const SizedBox(height: 24),
              ElevatedButton.icon(
                onPressed: _pickAvatar,
                icon: const Icon(Icons.photo_camera_outlined),
                label: const Text('Сменить аватар'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF7B61FF),
                  foregroundColor: Colors.white,
                  padding:
                      const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
