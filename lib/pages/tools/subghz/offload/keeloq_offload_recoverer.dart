import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import '../subghz_native.dart';

/// A recovered KeeLoq candidate device key.
class KeeloqCandidate {
  const KeeloqCandidate({
    required this.mfkey,
    required this.devkey,
    required this.counter,
    required this.learnType,
  });

  final int mfkey;
  final int devkey;
  final int counter;
  final int learnType;
}

class KeeloqOffloadProgress {
  const KeeloqOffloadProgress(this.percent, this.keysTested);
  final int percent;
  final int keysTested;
}

/// Result of a KeeLoq offload run: the candidates found (possibly empty).
class KeeloqOffloadResult {
  const KeeloqOffloadResult({
    required this.candidates,
    required this.cancelled,
  });

  final List<KeeloqCandidate> candidates;
  final bool cancelled;
}

class KeeloqOffloadHandle {
  KeeloqOffloadHandle(this._result, this._progressController, this._cancel);

  final Future<KeeloqOffloadResult> _result;
  final StreamController<KeeloqOffloadProgress> _progressController;
  final void Function() _cancel;

  Future<KeeloqOffloadResult> get result => _result;
  Stream<KeeloqOffloadProgress> get progress => _progressController.stream;
  void cancel() => _cancel();
}

// C signature (qunleashed_subghz_bridge.c):
//   int qunleashed_keeloq_bruteforce(
//       int learning_type, uint32_t serial, uint32_t fix,
//       uint32_t hop1, uint32_t hop2, int max_candidates,
//       uint64_t* out_mfkeys, uint64_t* out_devkeys,
//       uint32_t* out_counters, uint8_t* out_learn_types,
//       uint64_t* progress_out, volatile int32_t* cancel);
typedef _KlNative =
    Int32 Function(
      Int32 learningType,
      Uint32 serial,
      Uint32 fix,
      Uint32 hop1,
      Uint32 hop2,
      Int32 maxCandidates,
      Pointer<Uint64> outMfkeys,
      Pointer<Uint64> outDevkeys,
      Pointer<Uint32> outCounters,
      Pointer<Uint8> outLearnTypes,
      Pointer<Uint64> progressOut,
      Pointer<Int32> cancel,
    );

typedef _KlDart =
    int Function(
      int learningType,
      int serial,
      int fix,
      int hop1,
      int hop2,
      int maxCandidates,
      Pointer<Uint64> outMfkeys,
      Pointer<Uint64> outDevkeys,
      Pointer<Uint32> outCounters,
      Pointer<Uint8> outLearnTypes,
      Pointer<Uint64> progressOut,
      Pointer<Int32> cancel,
    );

const int _kMaxCandidates = 32;

/// Runs the KeeLoq manufacturer-key brute-force on a worker isolate. When
/// [learningType] is 0 (auto) it sweeps types 6, 7 then 8 in sequence, stopping
/// early once a candidate is found. Shared-memory progress/cancel as in
/// [NativePsaRecoverer].
class KeeloqOffloadRecoverer {
  KeeloqOffloadHandle start({
    required int learningType,
    required int serial,
    required int fix,
    required int hop1,
    required int hop2,
  }) {
    final cancel = calloc<Int32>();
    final progressCounter = calloc<Uint64>();
    final progressController =
        StreamController<KeeloqOffloadProgress>.broadcast();

    var lastPacked = -1;
    final timer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      final packed = progressCounter.value;
      if (packed == lastPacked) return;
      lastPacked = packed;
      final pct = (packed >> 56) & 0xFF;
      final keys = packed & 0x00FFFFFFFFFFFFFF;
      if (!progressController.isClosed) {
        progressController.add(KeeloqOffloadProgress(pct, keys));
      }
    });

    final payload = _KlPayload(
      learningType: learningType,
      serial: serial,
      fix: fix,
      hop1: hop1,
      hop2: hop2,
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

    return KeeloqOffloadHandle(result, progressController, () {
      cancel.value = 1;
    });
  }

  static KeeloqOffloadResult _runInIsolate(_KlPayload p) {
    final library = openSubghzNativeLibrary();
    final run = library.lookupFunction<_KlNative, _KlDart>(
      'qunleashed_keeloq_bruteforce',
    );

    final cancel = Pointer<Int32>.fromAddress(p.cancelAddress);
    final progressOut = Pointer<Uint64>.fromAddress(p.progressAddress);

    final mfkeys = calloc<Uint64>(_kMaxCandidates);
    final devkeys = calloc<Uint64>(_kMaxCandidates);
    final counters = calloc<Uint32>(_kMaxCandidates);
    final learnTypes = calloc<Uint8>(_kMaxCandidates);
    try {
      // Auto mode (0) tries 6, 7, 8; a specific type runs just once.
      final types = p.learningType == 0 ? const [6, 7, 8] : [p.learningType];
      final all = <KeeloqCandidate>[];

      for (final type in types) {
        if (cancel.value != 0) break;
        final n = run(
          type,
          p.serial,
          p.fix,
          p.hop1,
          p.hop2,
          _kMaxCandidates,
          mfkeys,
          devkeys,
          counters,
          learnTypes,
          progressOut,
          cancel,
        );
        if (n > 0) {
          for (var i = 0; i < n && i < _kMaxCandidates; i++) {
            all.add(
              KeeloqCandidate(
                mfkey: mfkeys[i],
                devkey: devkeys[i],
                counter: counters[i],
                learnType: learnTypes[i],
              ),
            );
          }
          // Found candidates for this type; stop the auto sweep.
          break;
        }
      }

      return KeeloqOffloadResult(
        candidates: all,
        cancelled: cancel.value != 0 && all.isEmpty,
      );
    } finally {
      calloc.free(mfkeys);
      calloc.free(devkeys);
      calloc.free(counters);
      calloc.free(learnTypes);
    }
  }
}

class _KlPayload {
  const _KlPayload({
    required this.learningType,
    required this.serial,
    required this.fix,
    required this.hop1,
    required this.hop2,
    required this.cancelAddress,
    required this.progressAddress,
  });

  final int learningType;
  final int serial;
  final int fix;
  final int hop1;
  final int hop2;
  final int cancelAddress;
  final int progressAddress;
}
