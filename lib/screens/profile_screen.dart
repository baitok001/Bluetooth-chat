import 'dart:io';

import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';

import '../models/chat_profile.dart';
import '../services/security_service.dart';

class ProfileScreen extends StatefulWidget {
  final ChatProfile profile;
  final ValueChanged<ChatProfile> onProfileChanged;
  final ValueChanged<String>? onPassphraseChanged;

  const ProfileScreen(
      {super.key,
      required this.profile,
      required this.onProfileChanged,
      this.onPassphraseChanged});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  late ChatProfile _profile;
  late final SecurityService _securityService;
  late final TextEditingController _passphraseController;

  @override
  void initState() {
    super.initState();
    _profile = widget.profile;
    _securityService = SecurityService();
    _passphraseController = TextEditingController();
    _loadPassphrase();
  }

  @override
  void dispose() {
    _passphraseController.dispose();
    super.dispose();
  }

  Future<void> _loadPassphrase() async {
    final passphrase = await _securityService.getPassphrase();
    if (mounted) {
      setState(() => _passphraseController.text = passphrase);
    }
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

  Future<void> _savePassphrase() async {
    final passphrase = _passphraseController.text.trim();
    if (passphrase.isEmpty) {
      return;
    }

    await _securityService.setPassphrase(passphrase);
    widget.onPassphraseChanged?.call(passphrase);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Ключ безопасности сохранён')));
    }
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
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(20),
                  boxShadow: [
                    BoxShadow(
                        color: Colors.black.withOpacity(0.05),
                        blurRadius: 12,
                        offset: const Offset(0, 6))
                  ],
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Ключ безопасности',
                        style: TextStyle(
                            fontSize: 15, fontWeight: FontWeight.w800)),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _passphraseController,
                      decoration: const InputDecoration(
                        hintText: 'Введите общий ключ для Bluetooth',
                        border: OutlineInputBorder(),
                      ),
                      obscureText: true,
                    ),
                    const SizedBox(height: 12),
                    ElevatedButton(
                      onPressed: _savePassphrase,
                      style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF7B61FF),
                          foregroundColor: Colors.white),
                      child: const Text('Сохранить ключ'),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
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
