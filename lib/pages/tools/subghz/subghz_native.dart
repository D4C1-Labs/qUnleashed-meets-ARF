import 'dart:ffi';

import '../mifare/mifare_native.dart' show openNativeLibrary;

/// The `qunleashed_subghz` library: host-side Sub-GHz key recovery entry
/// points — PSA TEA bruteforce, KeeLoq decrypt/encrypt, and the Hitag2Hell
/// Fiat V1 attack (see `lib/modules/cpp/subghz`).
///
/// Reuses the cross-platform loader from the MIFARE tools so the .so/.dll/
/// .process() selection and the [NativeEngineUnavailable] contract stay in one
/// place.
DynamicLibrary openSubghzNativeLibrary() =>
    openNativeLibrary('qunleashed_subghz');
