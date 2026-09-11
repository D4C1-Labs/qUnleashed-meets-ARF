import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import '../subghz_native.dart';

/// Result of a PSA offload brute-force: the raw (counter, decV0, decV1) the
/// Flipper firmware expects back, or a not-found/cancelled marker.
class PsaOffloadResult {
  const PsaOffloadResult({
    required this.found,
    required this.counter,
    required this.decV0,
    required this.decV1,
    required this.cancelled,
  });

  const PsaOffloadResult.notFound({bool cancelled = false})
    : this(
        found: false,
        counter: 0,
        decV0: 0,
        decV1: 0,
        cancelled: cancelled,
      );

  final bool found;
  final int counter;
  final int decV0;
  final int decV1;
  final bool cancelled;
}

/// A progress tick (0..100 percent, cumulative keys tested).
class PsaOffloadProgress {
  const PsaOffloadProgress(this.percent, this.keysTested);
  final int percent;
  final int keysTested;
}

/// Live PSA offload run: await [result], listen to [progress], call [cancel].
class PsaOffloadHandle {
  PsaOffloadHandle(this._result, this._progressController, this._cancel);

  final Future<PsaOffloadResult> _result;
  final StreamController<PsaOffloadProgress> _progressController;
  final void Function() _cancel;

  Future<PsaOffloadResult> get result => _result;
  Stream<PsaOffloadProgress> get progress => _progressController.stream;
  void cancel() => _cancel();
}

// C signature (qunleashed_subghz_bridge.c):
//   int qunleashed_psa_bruteforce_offload(
//       uint32_t w0, uint32_t w1,
//       uint32_t* out_counter, uint32_t* out_dec_v0, uint32_t* out_dec_v1,
//       int32_t* found, uint64_t* progress_out, volatile int32_t* cancel);
typedef _PsaOffloadNative =
    Int32 Function(
      Uint32 w0,
      Uint32 w1,
      Pointer<Uint32> outCounter,
      Pointer<Uint32> outDecV0,
      Pointer<Uint32> outDecV1,
      Pointer<Int32> found,
      Pointer<Uint64> progressOut,
      Pointer<Int32> cancel,
    );

typedef _PsaOffloadDart =
    int Function(
      int w0,
      int w1,
      Pointer<Uint32> outCounter,
      Pointer<Uint32> outDecV0,
      Pointer<Uint32> outDecV1,
      Pointer<Int32> found,
      Pointer<Uint64> progressOut,
      Pointer<Int32> cancel,
    );

/// Runs the PSA offload brute-force (w0/w1 -> counter/decV0/decV1) on a worker
/// isolate, using the same shared-native-memory progress/cancel model as
/// [NativePsaRecoverer] (see psa_recoverer.dart for the full rationale).
class PsaOffloadRecoverer {
  PsaOffloadHandle start({required int w0, required int w1}) {
    final cancel = calloc<Int32>();
    final progressCounter = calloc<Uint64>();
    final progressController = StreamController<PsaOffloadProgress>.broadcast();

    var lastPacked = -1;
    final timer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      final packed = progressCounter.value;
      if (packed == lastPacked) return;
      lastPacked = packed;
      final pct = (packed >> 56) & 0xFF;
      final keys = packed & 0x00FFFFFFFFFFFFFF;
      if (!progressController.isClosed) {
        progressController.add(PsaOffloadProgress(pct, keys));
      }
    });

    final payload = _PsaOffloadPayload(
      w0: w0,
      w1: w1,
      cancelAddress: cancel.address,
      progressAddress: progressCounter.address,
    );

    final runFuture = Isolate.run(() => _runInIsolate(payload));
    final result = runFuture.whenComplete(() {
      timer.cancel();
      calloc.free(cancel);
      calloc.free(progressCounter);
      if (!progressController.isClosed) progressController.close();
    });

    return PsaOffloadHandle(result, progressController, () {
      cancel.value = 1;
    });
  }

  static PsaOffloadResult _runInIsolate(_PsaOffloadPayload p) {
    final library = openSubghzNativeLibrary();
    final run = library
        .lookupFunction<_PsaOffloadNative, _PsaOffloadDart>(
          'qunleashed_psa_bruteforce_offload',
        );

    final cancel = Pointer<Int32>.fromAddress(p.cancelAddress);
    final progressOut = Pointer<Uint64>.fromAddress(p.progressAddress);

    final outCounter = calloc<Uint32>();
    final outDecV0 = calloc<Uint32>();
    final outDecV1 = calloc<Uint32>();
    final found = calloc<Int32>();
    try {
      final rc = run(
        p.w0,
        p.w1,
        outCounter,
        outDecV0,
        outDecV1,
        found,
        progressOut,
        cancel,
      );

      if (rc == 0 && found.value != 0) {
        return PsaOffloadResult(
          found: true,
          counter: outCounter.value,
          decV0: outDecV0.value,
          decV1: outDecV1.value,
          cancelled: false,
        );
      }
      return PsaOffloadResult.notFound(cancelled: cancel.value != 0);
    } finally {
      calloc.free(outCounter);
      calloc.free(outDecV0);
      calloc.free(outDecV1);
      calloc.free(found);
    }
  }
}

class _PsaOffloadPayload {
  const _PsaOffloadPayload({
    required this.w0,
    required this.w1,
    required this.cancelAddress,
    required this.progressAddress,
  });

  final int w0;
  final int w1;
  final int cancelAddress;
  final int progressAddress;
}
