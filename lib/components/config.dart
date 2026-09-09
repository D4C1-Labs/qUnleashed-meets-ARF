import 'package:flutter/material.dart';

class QAppConfig {
  const QAppConfig._();

  static const firmware = FirmwareConfig(
    firmwares: [
      FirmwareEntry(
        name: 'Unleashed',
        shortName: 'unlshd',
        icon: 'cfw.png',
        matchKeywords: ['unleashed', 'darkflippers'],
        colors: FirmwareColors(
          primary: Color(0xFFCC241D),
          secondary: Color(0xFFCC5F00),
          tertiary: Color(0xFFFFB347),
        ),
      ),
      FirmwareEntry(
        name: 'Official firmware',
        shortName: 'ofw',
        icon: 'ofw.png',
        matchKeywords: ['official', 'flipperdevices'],
        colors: FirmwareColors(
          primary: Color(0xFFFF8200),
          secondary: Color(0xFFCC5F00),
          tertiary: Color(0xFFFFD580),
        ),
      ),
      // [ARF] Flipper-ARF firmware (D4C1-Labs fork). Matched against the
      // device-reported origin.fork / version string via matchKeywords.
      FirmwareEntry(
        name: 'ARF',
        shortName: 'arf',
        icon: 'arf.png',
        matchKeywords: ['arf', 'flipper-arf', 'd4c1-labs', 'd4c1'],
        colors: FirmwareColors(
          primary: Color(0xFF2E9E7B),
          secondary: Color(0xFF1F6E56),
          tertiary: Color(0xFF7FD1B5),
        ),
      ),
    ],
  );

  static FirmwareEntry get defaultFirmware => firmware.firmwares.first;
}

class FirmwareColors {
  final Color primary;
  final Color secondary;
  final Color tertiary;

  const FirmwareColors({
    required this.primary,
    required this.secondary,
    required this.tertiary,
  });
}

class FirmwareEntry {
  final String name;
  final String shortName;
  final String icon;
  final List<String> matchKeywords;
  final FirmwareColors colors;

  const FirmwareEntry({
    required this.name,
    required this.shortName,
    required this.icon,
    this.matchKeywords = const [],
    required this.colors,
  });

  String get assetPath => 'assets/img/firmware/$icon';
}

class FirmwareConfig {
  final List<FirmwareEntry> firmwares;

  const FirmwareConfig({required this.firmwares});

  bool get isSingle => firmwares.length == 1;
}
