import 'dart:ffi';

import 'subghz_native.dart';

// KeeLoq is a 32-bit block cipher: one NLFSR pass is ~cheap enough that there
// is no reason to cross an isolate boundary. Both directions are single-shot
// native calls.
//
// C signatures (qunleashed_subghz_bridge.c):
//   uint32_t qunleashed_keeloq_decrypt(uint32_t hop, uint64_t key);
//   uint32_t qunleashed_keeloq_encrypt(uint32_t data, uint64_t key);
typedef _KeeloqNative = Uint32 Function(Uint32 input, Uint64 key);
typedef _KeeloqDart = int Function(int input, int key);

/// KeeLoq block-cipher decrypt/encrypt over the native `qunleashed_subghz`
/// engine. Both operands are unsigned: `hop`/`data` are 32-bit and `key` is a
/// 64-bit manufacturer/learning key.
///
/// The library and symbols are resolved lazily on first use and cached, so a
/// missing build raises [NativeEngineUnavailable] the first time either method
/// is called rather than at import time.
abstract final class KeeloqRecoverer {
  static _KeeloqDart? _decrypt;
  static _KeeloqDart? _encrypt;

  static void _ensureLoaded() {
    if (_decrypt != null) return;
    final library = openSubghzNativeLibrary();
    _decrypt = library.lookupFunction<_KeeloqNative, _KeeloqDart>(
      'qunleashed_keeloq_decrypt',
    );
    _encrypt = library.lookupFunction<_KeeloqNative, _KeeloqDart>(
      'qunleashed_keeloq_encrypt',
    );
  }

  /// Decrypts one 32-bit KeeLoq [hop] block under the 64-bit [key], returning
  /// the recovered plaintext as an unsigned 32-bit int.
  static int decrypt(int hop, int key) {
    _ensureLoaded();
    return _decrypt!(hop, key);
  }

  /// Encrypts one 32-bit [data] block under the 64-bit [key], returning the
  /// resulting hopping code as an unsigned 32-bit int.
  static int encrypt(int data, int key) {
    _ensureLoaded();
    return _encrypt!(data, key);
  }
}
