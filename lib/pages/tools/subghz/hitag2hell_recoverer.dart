import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'subghz_native.dart';

/// One captured Hitag2 rolling code the Hitag2Hell attack cross-validates
/// against. Two or more captures from the same key sharply cut the candidate
/// key space. The active fields depend on [proto]:
///   * Fiat V1    : uid, button, counter (16-bit), hop.
///   * Fiat V2    : uid, raw (14-byte frame); hop/uid/IV re-derived natively.
///   * Renault V1 : uid, button, counter (8-bit), payload42.
class Hitag2Capture {
  const Hitag2Capture({
    required this.uid,
    this.button = 0,
    this.counter = 0,
    this.hop = 0,
    this.proto = 0,
    this.raw,
    this.payload42,
  });

  /// 32-bit tag UID (Renault V1: serial & 0xFFFFFF, from the header).
  final int uid;

  /// Button code (0..255).
  final int button;

  /// Rolling counter at capture time (16-bit Fiat V1, 8-bit Renault V1).
  final int counter;

  /// 32-bit captured hopping code (Fiat V1).
  final int hop;

  /// 0=Fiat V1, 1=Fiat V2, 2=Renault V1.
  final int proto;

  /// Fiat V2: the 14-byte verbatim frame (bytes 0..13). Null otherwise.
  final Uint8List? raw;

  /// Renault V1: the low 42 bits of the payload. Null otherwise.
  final int? payload42;
}

/// Outcome of a Hitag2Hell recovery: the 6-byte key when [found], else a
/// not-found / cancelled marker.
class Hitag2Result {
  const Hitag2Result.recovered(Uint8List this.key) : cancelled = false;

  const Hitag2Result.notFound({this.cancelled = false}) : key = null;

  /// The recovered 48-bit key as 6 bytes, or null when nothing was found.
  final Uint8List? key;

  /// True when the run was cancelled before a key was found.
  final bool cancelled;

  bool get found => key != null;
}

/// A progress tick from a running Hitag2Hell recovery.
class Hitag2Progress {
  const Hitag2Progress(this.percent, this.slotsDone);

  /// 0..100 completion estimate.
  final int percent;

  /// L0 slots processed so far.
  final int slotsDone;
}

/// A live Hitag2Hell recovery: await [result], listen to [progress], call
/// [cancel] to stop early. Mirrors [PsaBruteforceHandle].
class Hitag2RecoverHandle {
  Hitag2RecoverHandle._(this._result, this._progressController, this._cancel);

  final Future<Hitag2Result> _result;
  final StreamController<Hitag2Progress> _progressController;
  final void Function() _cancel;

  Future<Hitag2Result> get result => _result;
  Stream<Hitag2Progress> get progress => _progressController.stream;

  void cancel() => _cancel();
}

// C signature (qunleashed_subghz_bridge.c):
//   int qunleashed_hitag2hell_recover(
//       int32_t proto,
//       const uint32_t* uids, const uint8_t* btns,
//       const uint16_t* cnts, const uint32_t* hops,
//       const uint8_t* raws,        // Fiat V2: capture_count*14 bytes
//       const uint64_t* payload42s, // Renault V1: capture_count entries
//       uint32_t capture_count,
//       uint32_t l0_start, uint32_t l0_end,
//       uint8_t* out_key, int32_t* found,
//       uint64_t* progress_out, volatile int32_t* cancel);
//
// `proto`: 0=Fiat V1 (uids/btns/cnts/hops), 1=Fiat V2 (raws; uid/hop derived
// natively), 2=Renault V1 (uids/btns/cnts + payload42s). Unused arrays may be
// NULL (nullptr); we always pass allocated buffers to keep marshalling simple.
//
// Progress is a SHARED MEMORY cell (Pointer<Uint64>) the native code writes,
// NOT a Dart callback. Dart FFI callbacks may only be called from the isolate
// thread; the native worker pthreads cannot legally invoke one, which crashed
// the app. The bridge instead packs (pct<<56)|slots into *progress_out and the
// Dart side polls it with a Timer.
typedef _Hitag2Native =
    Int32 Function(
      Int32 proto,
      Pointer<Uint32> uids,
      Pointer<Uint8> btns,
      Pointer<Uint16> cnts,
      Pointer<Uint32> hops,
      Pointer<Uint8> raws,
      Pointer<Uint64> payload42s,
      Uint32 captureCount,
      Uint32 l0Start,
      Uint32 l0End,
      Pointer<Uint8> outKey,
      Pointer<Int32> found,
      Pointer<Uint64> progressOut,
      Pointer<Int32> cancel,
    );

typedef _Hitag2Dart =
    int Function(
      int proto,
      Pointer<Uint32> uids,
      Pointer<Uint8> btns,
      Pointer<Uint16> cnts,
      Pointer<Uint32> hops,
      Pointer<Uint8> raws,
      Pointer<Uint64> payload42s,
      int captureCount,
      int l0Start,
      int l0End,
      Pointer<Uint8> outKey,
      Pointer<Int32> found,
      Pointer<Uint64> progressOut,
      Pointer<Int32> cancel,
    );

/// Runs the Hitag2Hell Fiat V1 attack on a worker isolate.
///
/// Progress/cancel use a **shared native memory + polling** approach: a
/// `Pointer<Int32>` cancel flag and a `Pointer<Uint64>` packed
/// `(pct << 56) | slots` progress cell, both allocated on the parent and
/// addressed from the worker. The native engine writes progress directly into
/// that cell from its worker threads (a plain memory store, thread-safe), and
/// this side polls it with a Timer. No Dart callback is ever invoked from a
/// native thread, which would crash.
class NativeHitag2HellRecoverer {
  /// Starts a recovery over [captures]. The L0 sweep defaults to the full
  /// 2^20 space (`l0Start == l0End == 0`); pass a narrower `[l0Start, l0End)`
  /// range for testing or resumable runs.
  ///
  /// Throws [ArgumentError] when [captures] is empty; a missing native build
  /// surfaces as a [NativeEngineUnavailable] from [result].
  Hitag2RecoverHandle start({
    required List<Hitag2Capture> captures,
    int proto = 0,
    int l0Start = 0,
    int l0End = 0,
  }) {
    if (captures.isEmpty) {
      throw ArgumentError('at least one capture is required');
    }

    // Flatten to the parallel arrays the C entry point takes. `raws` is a
    // capture_count*14 flat byte array (Fiat V2); `payload42s` is one 64-bit
    // entry per capture (Renault V1). Unused arrays for a given proto are left
    // zero-filled and ignored natively.
    final n = captures.length;
    final uids = Uint32List(n);
    final btns = Uint8List(n);
    final cnts = Uint16List(n);
    final hops = Uint32List(n);
    final raws = Uint8List(n * 14);
    final payload42s = Uint64List(n);
    for (var i = 0; i < n; i++) {
      final c = captures[i];
      uids[i] = c.uid;
      btns[i] = c.button;
      cnts[i] = c.counter;
      hops[i] = c.hop;
      final raw = c.raw;
      if (raw != null) {
        final take = raw.length < 14 ? raw.length : 14;
        raws.setRange(i * 14, i * 14 + take, raw);
      }
      payload42s[i] = c.payload42 ?? 0;
    }

    final cancel = calloc<Int32>();
    final progressCounter = calloc<Uint64>();
    final progressController = StreamController<Hitag2Progress>.broadcast();

    var lastPacked = -1;
    final timer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      final packed = progressCounter.value;
      if (packed == lastPacked) return;
      lastPacked = packed;
      final pct = (packed >> 56) & 0xFF;
      final slots = packed & 0x00FFFFFFFFFFFFFF;
      if (!progressController.isClosed) {
        progressController.add(Hitag2Progress(pct, slots));
      }
    });

    final payload = _Hitag2Payload(
      proto: proto,
      uids: uids,
      btns: btns,
      cnts: cnts,
      hops: hops,
      raws: raws,
      payload42s: payload42s,
      l0Start: l0Start,
      l0End: l0End,
      cancelAddress: cancel.address,
      progressAddress: progressCounter.address,
    );

    // IMPORTANT: pass the static entry point directly as the isolate closure
    // (`Isolate.run(() => _runInIsolate(payload))` would capture `timer` and
    // `progressController` from this lexical scope, which are non-sendable and
    // trigger "object is unsendable - _Timer" at runtime). Building the future
    // first, before referencing `timer` in `whenComplete`, keeps the sent
    // closure free of any non-sendable capture.
    final Future<Hitag2Result> runFuture = _spawnRecovery(payload);
    final result = runFuture.whenComplete(() {
      timer.cancel();
      calloc.free(cancel);
      calloc.free(progressCounter);
      if (!progressController.isClosed) progressController.close();
    });

    return Hitag2RecoverHandle._(result, progressController, () {
      cancel.value = 1;
    });
  }

  /// Spawns the worker isolate. Kept as a separate static method so the
  /// closure sent to [Isolate.run] captures ONLY [payload] (which is sendable)
  /// and nothing from the caller's scope (timer / stream controller).
  static Future<Hitag2Result> _spawnRecovery(_Hitag2Payload payload) {
    return Isolate.run(() => _runInIsolate(payload));
  }

  static Hitag2Result _runInIsolate(_Hitag2Payload p) {
    final library = openSubghzNativeLibrary();
    final run = library.lookupFunction<_Hitag2Native, _Hitag2Dart>(
      'qunleashed_hitag2hell_recover',
    );

    final cancel = Pointer<Int32>.fromAddress(p.cancelAddress);
    final progressOut = Pointer<Uint64>.fromAddress(p.progressAddress);

    final n = p.uids.length;
    final uids = calloc<Uint32>(n);
    final btns = calloc<Uint8>(n);
    final cnts = calloc<Uint16>(n);
    final hops = calloc<Uint32>(n);
    final raws = calloc<Uint8>(n * 14);
    final payload42s = calloc<Uint64>(n);
    final outKey = calloc<Uint8>(6);
    final found = calloc<Int32>();
    try {
      uids.asTypedList(n).setAll(0, p.uids);
      btns.asTypedList(n).setAll(0, p.btns);
      cnts.asTypedList(n).setAll(0, p.cnts);
      hops.asTypedList(n).setAll(0, p.hops);
      raws.asTypedList(n * 14).setAll(0, p.raws);
      payload42s.asTypedList(n).setAll(0, p.payload42s);

      final rc = run(
        p.proto,
        uids,
        btns,
        cnts,
        hops,
        raws,
        payload42s,
        n,
        p.l0Start,
        p.l0End,
        outKey,
        found,
        progressOut, // native writes packed (pct<<56)|slots here
        cancel,
      );

      if (rc == 0 && found.value != 0) {
        // Copy out before the native buffer is freed.
        return Hitag2Result.recovered(
          Uint8List.fromList(outKey.asTypedList(6)),
        );
      }
      return Hitag2Result.notFound(cancelled: cancel.value != 0);
    } finally {
      calloc.free(uids);
      calloc.free(btns);
      calloc.free(cnts);
      calloc.free(hops);
      calloc.free(raws);
      calloc.free(payload42s);
      calloc.free(outKey);
      calloc.free(found);
    }
  }
}

class _Hitag2Payload {
  const _Hitag2Payload({
    required this.proto,
    required this.uids,
    required this.btns,
    required this.cnts,
    required this.hops,
    required this.raws,
    required this.payload42s,
    required this.l0Start,
    required this.l0End,
    required this.cancelAddress,
    required this.progressAddress,
  });

  final int proto;
  final Uint32List uids;
  final Uint8List btns;
  final Uint16List cnts;
  final Uint32List hops;
  final Uint8List raws;
  final Uint64List payload42s;
  final int l0Start;
  final int l0End;
  final int cancelAddress;
  final int progressAddress;
}
