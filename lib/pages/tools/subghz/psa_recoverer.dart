import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'subghz_native.dart';

/// Outcome of a PSA TEA bruteforce: the recovered rolling-code fields when
/// [found] is true, or a not-found / cancelled marker otherwise.
class PsaResult {
  const PsaResult._({
    required this.found,
    required this.serial,
    required this.counter,
    required this.button,
    required this.type,
    required this.cancelled,
  });

  const PsaResult.notFound({bool cancelled = false})
    : this._(
        found: false,
        serial: 0,
        counter: 0,
        button: 0,
        type: 0,
        cancelled: cancelled,
      );

  const PsaResult.recovered({
    required int serial,
    required int counter,
    required int button,
    required int type,
  }) : this._(
         found: true,
         serial: serial,
         counter: counter,
         button: button,
         type: type,
         cancelled: false,
       );

  final bool found;

  /// 64-bit device serial (only meaningful when [found]).
  final int serial;

  /// Rolling counter value at capture time.
  final int counter;

  /// Button code.
  final int button;

  /// Protocol/subtype discriminator emitted by the engine.
  final int type;

  /// True when the run was stopped via [PsaBruteforceHandle.cancel] before a
  /// key was found.
  final bool cancelled;
}

/// A progress tick from a running PSA bruteforce.
class PsaProgress {
  const PsaProgress(this.percent, this.keysTested);

  /// 0..100 completion estimate from the engine.
  final int percent;

  /// Total keys tried so far.
  final int keysTested;
}

/// A live PSA bruteforce: await [result], listen to [progress] for a progress
/// bar, and call [cancel] to stop early.
///
/// The heavy work runs in a worker isolate; this handle stays on the calling
/// isolate and owns the shared native scratch that carries cancel/progress
/// across the boundary (see [NativePsaRecoverer]).
class PsaBruteforceHandle {
  PsaBruteforceHandle._(this._result, this._progressController, this._cancel);

  final Future<PsaResult> _result;
  final StreamController<PsaProgress> _progressController;
  final void Function() _cancel;

  /// Completes with the recovered fields, a not-found, or a cancelled result.
  Future<PsaResult> get result => _result;

  /// Progress ticks sampled from the engine while it runs.
  Stream<PsaProgress> get progress => _progressController.stream;

  /// Requests cancellation. The engine stops at its next progress checkpoint
  /// and [result] completes with `cancelled: true`.
  void cancel() => _cancel();
}

// C signature (qunleashed_subghz_bridge.c):
//   int qunleashed_psa_bruteforce(
//       const uint8_t* key1, const uint8_t* key2,
//       uint64_t* out_serial, uint32_t* out_cnt,
//       uint8_t* out_btn, uint8_t* out_type,
//       int32_t* found,
//       void (*progress)(uint32_t pct, uint64_t keys_tested, void* ctx),
//       void* ctx,
//       volatile int32_t* cancel);
typedef _PsaNative =
    Int32 Function(
      Pointer<Uint8> key1,
      Pointer<Uint8> key2,
      Pointer<Uint64> outSerial,
      Pointer<Uint32> outCnt,
      Pointer<Uint8> outBtn,
      Pointer<Uint8> outType,
      Pointer<Int32> found,
      Pointer<NativeFunction<_PsaProgressNative>> progress,
      Pointer<Void> ctx,
      Pointer<Int32> cancel,
    );

typedef _PsaDart =
    int Function(
      Pointer<Uint8> key1,
      Pointer<Uint8> key2,
      Pointer<Uint64> outSerial,
      Pointer<Uint32> outCnt,
      Pointer<Uint8> outBtn,
      Pointer<Uint8> outType,
      Pointer<Int32> found,
      Pointer<NativeFunction<_PsaProgressNative>> progress,
      Pointer<Void> ctx,
      Pointer<Int32> cancel,
    );

// The native progress callback: void(uint32_t pct, uint64_t keys_tested,
// void* ctx). We run it *inside the worker isolate* (a leaf callback with no
// Dart heap access beyond writing native scratch), so it can be a plain
// Pointer.fromFunction rather than a NativeCallable.listener bound to another
// isolate — see the class doc for why.
typedef _PsaProgressNative =
    Void Function(Uint32 pct, Uint64 keysTested, Pointer<Void> ctx);

/// Runs the PSA TEA bruteforce on a worker isolate.
///
/// ## Progress / cancel design
///
/// `Isolate.run` moves the whole attack off the UI isolate. Two facts shape how
/// progress and cancellation cross back:
///
/// * A `NativeCallable.listener` is bound to the isolate that created it, and
///   its `nativeFunction` may only be invoked from that isolate. The native
///   engine calls the progress callback from its own worker *threads* (spawned
///   by the C side, not Dart isolates), so a listener created on the UI isolate
///   cannot legally be invoked by them.
/// * Native heap is process-global: a pointer allocated on one isolate stays
///   valid on another. Only its integer address needs to travel.
///
/// So we use **shared native scratch + polling**, which is both simpler and
/// safe here:
///
/// * `cancel`  — a `Pointer<Int32>` allocated on the *parent*. Its address is
///   handed to the worker, which casts it back and passes it straight to C.
///   [PsaBruteforceHandle.cancel] writes 1; the C loop reads it at each
///   checkpoint (see `psa_bridge_progress`).
/// * `progress` — a `Pointer<Uint64>` counter packed as `(pct << 56) | keys`,
///   written by an in-worker `Pointer.fromFunction` callback. The parent polls
///   it every 250 ms with a `Timer` and republishes on the [Stream]. This
///   avoids any cross-isolate callback invocation entirely.
///
/// The callback runs on the worker's threads but only writes to native memory
/// (no Dart allocation), which is safe for a `Pointer.fromFunction` leaf.
class NativePsaRecoverer {
  /// Starts a bruteforce for the 8-byte [key1] / [key2] TEA halves and returns
  /// a handle to watch and cancel it.
  ///
  /// Throws [ArgumentError] if either key is not exactly 8 bytes; a missing
  /// native build surfaces as a [NativeEngineUnavailable] from [result].
  PsaBruteforceHandle start({
    required List<int> key1,
    required List<int> key2,
  }) {
    if (key1.length != 8 || key2.length != 8) {
      throw ArgumentError('PSA keys must be 8 bytes each');
    }

    // Allocated on the parent (this isolate). Native memory is process-scoped,
    // so both survive being read/written from the worker. The worker never
    // frees them — the parent does, once the future settles.
    final cancel = calloc<Int32>();
    final progressCounter = calloc<Uint64>();

    final progressController = StreamController<PsaProgress>.broadcast();

    // Poll the shared counter and republish. 250 ms is imperceptible for a
    // progress bar and keeps the parent isolate almost idle.
    var lastPacked = -1;
    final timer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      final packed = progressCounter.value;
      if (packed == lastPacked) return;
      lastPacked = packed;
      final pct = (packed >> 56) & 0xFF;
      final keys = packed & 0x00FFFFFFFFFFFFFF;
      if (!progressController.isClosed) {
        progressController.add(PsaProgress(pct, keys));
      }
    });

    final payload = _PsaPayload(
      key1: Uint8List.fromList(key1),
      key2: Uint8List.fromList(key2),
      cancelAddress: cancel.address,
      progressAddress: progressCounter.address,
    );

    final result = Isolate.run(() => _runInIsolate(payload)).whenComplete(() {
      timer.cancel();
      calloc.free(cancel);
      calloc.free(progressCounter);
      // The result future carries the final state; close the progress stream.
      if (!progressController.isClosed) progressController.close();
    });

    return PsaBruteforceHandle._(result, progressController, () {
      cancel.value = 1;
    });
  }

  static PsaResult _runInIsolate(_PsaPayload p) {
    final library = openSubghzNativeLibrary();
    final run = library.lookupFunction<_PsaNative, _PsaDart>(
      'qunleashed_psa_bruteforce',
    );

    // Re-materialise the parent's scratch from the transferred addresses.
    final cancel = Pointer<Int32>.fromAddress(p.cancelAddress);
    _progressSlot = Pointer<Uint64>.fromAddress(p.progressAddress);

    final key1 = calloc<Uint8>(8);
    final key2 = calloc<Uint8>(8);
    final outSerial = calloc<Uint64>();
    final outCnt = calloc<Uint32>();
    final outBtn = calloc<Uint8>();
    final outType = calloc<Uint8>();
    final found = calloc<Int32>();
    try {
      key1.asTypedList(8).setAll(0, p.key1);
      key2.asTypedList(8).setAll(0, p.key2);

      final progressPtr =
          Pointer.fromFunction<_PsaProgressNative>(_onProgress);

      final rc = run(
        key1,
        key2,
        outSerial,
        outCnt,
        outBtn,
        outType,
        found,
        progressPtr,
        nullptr,
        cancel,
      );

      if (rc == 0 && found.value != 0) {
        return PsaResult.recovered(
          serial: outSerial.value,
          counter: outCnt.value,
          button: outBtn.value,
          type: outType.value,
        );
      }
      // rc == -10 is "no key"; a non-zero cancel means the user stopped it.
      return PsaResult.notFound(cancelled: cancel.value != 0);
    } finally {
      calloc.free(key1);
      calloc.free(key2);
      calloc.free(outSerial);
      calloc.free(outCnt);
      calloc.free(outBtn);
      calloc.free(outType);
      calloc.free(found);
    }
  }

  // Worker-local slot the leaf callback writes into. A top-level static because
  // Pointer.fromFunction can only wrap a static/top-level function (no closure
  // capture). One bruteforce runs per isolate, so there is no aliasing.
  static Pointer<Uint64>? _progressSlot;

  static void _onProgress(int pct, int keysTested, Pointer<Void> ctx) {
    final slot = _progressSlot;
    if (slot == null) return;
    // Pack pct (0..100) in the top byte, keys in the low 56 bits. A single
    // aligned 64-bit store the parent reads without tearing on real targets.
    slot.value =
        ((pct & 0xFF) << 56) | (keysTested & 0x00FFFFFFFFFFFFFF);
  }
}

class _PsaPayload {
  const _PsaPayload({
    required this.key1,
    required this.key2,
    required this.cancelAddress,
    required this.progressAddress,
  });

  final Uint8List key1;
  final Uint8List key2;
  final int cancelAddress;
  final int progressAddress;
}
