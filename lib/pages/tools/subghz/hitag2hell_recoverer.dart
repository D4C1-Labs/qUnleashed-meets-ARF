import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'subghz_native.dart';

/// One captured Fiat V1 rolling code the Hitag2Hell attack cross-validates
/// against. Two or more captures from the same key sharply cut the candidate
/// key space.
class Hitag2Capture {
  const Hitag2Capture({
    required this.uid,
    required this.button,
    required this.counter,
    required this.hop,
  });

  /// 32-bit tag UID.
  final int uid;

  /// Button code (0..255).
  final int button;

  /// 16-bit rolling counter at capture time.
  final int counter;

  /// 32-bit captured hopping code.
  final int hop;
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
//       const uint32_t* uids, const uint8_t* btns,
//       const uint16_t* cnts, const uint32_t* hops,
//       uint32_t capture_count,
//       uint32_t l0_start, uint32_t l0_end,
//       uint8_t* out_key, int32_t* found,
//       uint64_t* progress_out, volatile int32_t* cancel);
//
// Progress is a SHARED MEMORY cell (Pointer<Uint64>) the native code writes,
// NOT a Dart callback. Dart FFI callbacks may only be called from the isolate
// thread; the native worker pthreads cannot legally invoke one, which crashed
// the app. The bridge instead packs (pct<<56)|slots into *progress_out and the
// Dart side polls it with a Timer.
typedef _Hitag2Native =
    Int32 Function(
      Pointer<Uint32> uids,
      Pointer<Uint8> btns,
      Pointer<Uint16> cnts,
      Pointer<Uint32> hops,
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
      Pointer<Uint32> uids,
      Pointer<Uint8> btns,
      Pointer<Uint16> cnts,
      Pointer<Uint32> hops,
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
    int l0Start = 0,
    int l0End = 0,
  }) {
    if (captures.isEmpty) {
      throw ArgumentError('at least one capture is required');
    }

    // Flatten to the parallel arrays the C entry point takes.
    final n = captures.length;
    final uids = Uint32List(n);
    final btns = Uint8List(n);
    final cnts = Uint16List(n);
    final hops = Uint32List(n);
    for (var i = 0; i < n; i++) {
      final c = captures[i];
      uids[i] = c.uid;
      btns[i] = c.button;
      cnts[i] = c.counter;
      hops[i] = c.hop;
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
      uids: uids,
      btns: btns,
      cnts: cnts,
      hops: hops,
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
    final outKey = calloc<Uint8>(6);
    final found = calloc<Int32>();
    try {
      uids.asTypedList(n).setAll(0, p.uids);
      btns.asTypedList(n).setAll(0, p.btns);
      cnts.asTypedList(n).setAll(0, p.cnts);
      hops.asTypedList(n).setAll(0, p.hops);

      final rc = run(
        uids,
        btns,
        cnts,
        hops,
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
      calloc.free(outKey);
      calloc.free(found);
    }
  }
}

class _Hitag2Payload {
  const _Hitag2Payload({
    required this.uids,
    required this.btns,
    required this.cnts,
    required this.hops,
    required this.l0Start,
    required this.l0End,
    required this.cancelAddress,
    required this.progressAddress,
  });

  final Uint32List uids;
  final Uint8List btns;
  final Uint16List cnts;
  final Uint32List hops;
  final int l0Start;
  final int l0End;
  final int cancelAddress;
  final int progressAddress;
}
