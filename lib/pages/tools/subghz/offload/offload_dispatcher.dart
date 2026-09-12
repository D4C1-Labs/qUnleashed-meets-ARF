import 'dart:async';
import 'dart:typed_data';

// flipperlib re-exports the Flipper RPC protobuf, which contains a generated
// `DateTime` message that shadows dart:core's DateTime. Hide it so DateTime.now()
// resolves to the core class.
import 'package:flipperlib/flipperlib.dart' hide DateTime;
import 'package:flutter/material.dart';

import '../../../../app/navigation_key.dart';
import '../hitag2hell_recoverer.dart';
import '../subghz_tools_page.dart';
import 'bf_protocol.dart';
import 'keeloq_offload_recoverer.dart';
import 'psa_offload_recoverer.dart';

/// Kind of offload job currently running.
enum OffloadJobKind { none, psa, keeloq, hitag }

/// Public status of the offload dispatcher, for the UI.
class OffloadStatus {
  const OffloadStatus({
    required this.kind,
    required this.running,
    required this.percent,
    required this.keysTested,
    this.keysPerSec = 0,
    this.lastMessage,
  });

  const OffloadStatus.idle()
    : kind = OffloadJobKind.none,
      running = false,
      percent = 0,
      keysTested = 0,
      keysPerSec = 0,
      lastMessage = null;

  final OffloadJobKind kind;
  final bool running;
  final int percent;
  final int keysTested;

  /// Keys/sec computed on the last progress tick (0 when unknown).
  final int keysPerSec;
  final String? lastMessage;
}

/// A parsed offload request the Flipper pushed, waiting for the user to press
/// Start in the Sub-GHz Crypto page. Exactly one of [psa]/[keeloq]/[hitag] is
/// non-null, matching [kind].
class OffloadPendingJob {
  const OffloadPendingJob({
    required this.kind,
    this.psa,
    this.keeloq,
    this.hitag,
  });

  final OffloadJobKind kind;
  final PsaBfRequest? psa;
  final KeeloqBfRequest? keeloq;
  final HitagBfRequest? hitag;
}

/// Listens for compute-offload requests the Flipper pushes over the custom-data
/// channel (fe66), runs the heavy PSA/KeeLoq brute-force natively on the phone,
/// streams progress back, and reports the result — all automatically while a
/// session is connected. Mirrors the arf-android-companion behaviour.
///
/// Lifecycle: create once with a [FlipperClient]; call [start] to begin
/// watching connections and [dispose] to tear down. It attaches to each
/// connected transport that advertises the offload channel and detaches on
/// disconnect.
class OffloadDispatcher {
  OffloadDispatcher(this._client);

  /// Process-wide instance, started from bootstrapAmbientServices() so the
  /// phone answers offload requests automatically whenever a session is up.
  static OffloadDispatcher? _instance;
  static OffloadDispatcher get instance => _instance!;
  static bool get hasInstance => _instance != null;

  /// Idempotently create + start the singleton bound to [client].
  static void ensureStarted(FlipperClient client) {
    _instance ??= OffloadDispatcher(client)..start();
  }

  final FlipperClient _client;

  StreamSubscription<FlipperConnectionState>? _connSub;
  StreamSubscription<Uint8List>? _customSub;
  Transport? _attached;

  final _statusCtrl = StreamController<OffloadStatus>.broadcast();

  /// Live status for a progress UI / notification.
  Stream<OffloadStatus> get status => _statusCtrl.stream;

  final _pendingCtrl = StreamController<OffloadPendingJob>.broadcast();

  /// Emits each time the Flipper pushes a new offload request. The Sub-GHz
  /// Crypto page listens so it can pre-load the data into the right tab.
  Stream<OffloadPendingJob> get pendingJobs => _pendingCtrl.stream;

  OffloadPendingJob? _lastPending;

  /// The most recent pending job, so a page opened slightly after the request
  /// arrived can still read it (the stream is broadcast + non-replaying).
  OffloadPendingJob? get lastPending => _lastPending;

  OffloadJobKind _jobKind = OffloadJobKind.none;
  final Stopwatch _jobClock = Stopwatch();

  // Active job handles (only one at a time; the Flipper drives one BF per user
  // action). A new request or a cancel supersedes the previous.
  PsaOffloadHandle? _psaHandle;
  KeeloqOffloadHandle? _keeloqHandle;
  Hitag2RecoverHandle? _hitagHandle;
  StreamSubscription<PsaOffloadProgress>? _psaProgressSub;
  StreamSubscription<KeeloqOffloadProgress>? _keeloqProgressSub;
  StreamSubscription<Hitag2Progress>? _hitagProgressSub;
  Timer? _progressThrottle;
  int _lastKeys = 0;
  int _lastKeysAt = 0;

  void start() {
    _connSub ??= _client.connectionStream.listen(_onConnection);
    // Attach immediately if already connected.
    _maybeAttach(_client.transport);
  }

  void _onConnection(FlipperConnectionState state) {
    if (state.connected) {
      _maybeAttach(_client.transport);
    } else if (!state.connecting) {
      _detach();
    }
  }

  void _maybeAttach(Transport? transport) {
    if (transport == null || identical(transport, _attached)) return;
    if (!transport.supportsOffload) return;
    _detach();
    _attached = transport;
    _customSub = transport.customDataStream.listen(_onCustomData);
  }

  void _detach() {
    _cancelActiveJob();
    _customSub?.cancel();
    _customSub = null;
    _attached = null;
  }

  void _onCustomData(Uint8List data) {
    if (data.isEmpty) return;
    if (BfProtocol.isPsaCancel(data) ||
        BfProtocol.isKeeloqCancel(data) ||
        BfProtocol.isHitagCancel(data)) {
      _cancelActiveJob();
      _lastPending = null;
      _emit(running: false, message: 'Cancelled by Flipper');
      return;
    }
    if (BfProtocol.isPsa(data)) {
      final req = BfProtocol.parsePsaRequest(data);
      if (req != null) {
        _publishPending(
          OffloadPendingJob(kind: OffloadJobKind.psa, psa: req),
        );
      }
      return;
    }
    if (BfProtocol.isKeeloq(data)) {
      final req = BfProtocol.parseKeeloqRequest(data);
      if (req != null) {
        _publishPending(
          OffloadPendingJob(kind: OffloadJobKind.keeloq, keeloq: req),
        );
      }
      return;
    }
    if (BfProtocol.isHitag(data)) {
      // The firmware now always sends the combo/slice-aware 0x24 request; the
      // legacy 0x20 parser is kept for backward compatibility.
      final req = BfProtocol.isHitagV2(data)
          ? BfProtocol.parseHitagRequestV2(data)
          : BfProtocol.parseHitagRequest(data);
      if (req != null) {
        _publishPending(
          OffloadPendingJob(kind: OffloadJobKind.hitag, hitag: req),
        );
      }
      return;
    }
  }

  /// Tab indices in [SubghzToolsPage] (order: KeeLoq, PSA, Hitag2Hell).
  static const int _tabKeeloq = 0;
  static const int _tabPsa = 1;
  static const int _tabHitag = 2;

  /// Number of live (or in-flight) [SubghzToolsPage] instances. While > 0 a
  /// fresh request updates the open page via [pendingJobs] instead of pushing a
  /// new one. Incremented at push time (before the page mounts) to close the
  /// mount-gap race, and by manually-opened pages in their initState.
  static int _openPages = 0;
  static bool get _pageOpen => _openPages > 0;

  /// Called by a manually-opened [SubghzToolsPage] when it mounts. Pages the
  /// dispatcher pushed are already counted (see [_publishPending]).
  static void notifyPageOpened() => _openPages++;

  /// Called by [SubghzToolsPage] when it unmounts.
  static void notifyPageClosed() {
    if (_openPages > 0) _openPages--;
  }

  /// Stores the new pending job, notifies any open page, and navigates to the
  /// Sub-GHz Crypto page on the correct tab (unless one is already open — then
  /// the [pendingJobs] emit above updates it in place).
  void _publishPending(OffloadPendingJob job) {
    _lastPending = job;
    if (!_pendingCtrl.isClosed) _pendingCtrl.add(job);

    if (_pageOpen) return; // Existing page picks it up via pendingJobs.

    final nav = appNavigatorKey.currentState;
    if (nav == null) return;

    final tab = switch (job.kind) {
      OffloadJobKind.psa => _tabPsa,
      OffloadJobKind.keeloq => _tabKeeloq,
      OffloadJobKind.hitag => _tabHitag,
      OffloadJobKind.none => _tabKeeloq,
    };
    // Count this page now (before it mounts) so a second request arriving in
    // the mount gap updates it via pendingJobs instead of pushing again. The
    // pushed page must NOT call notifyPageOpened() (it is pre-counted).
    _openPages++;
    nav.push(
      MaterialPageRoute<void>(
        builder: (_) => SubghzToolsPage(
          initialTab: tab,
          pending: job,
          dispatcherPushed: true,
        ),
      ),
    );
  }

  // ---- PSA ----
  /// Runs the PSA brute-force for [req]. Called by the Sub-GHz page when the
  /// user presses Start; streams progress + result back to the Flipper exactly
  /// as the old auto-start path did.
  void runPsa(PsaBfRequest req) {
    _cancelActiveJob();
    _jobKind = OffloadJobKind.psa;
    _jobClock
      ..reset()
      ..start();
    _resetProgressRate();
    _emit(running: true, message: 'PSA brute-force…');

    final handle = PsaOffloadRecoverer().start(w0: req.w0, w1: req.w1);
    _psaHandle = handle;

    _psaProgressSub = handle.progress.listen((p) {
      _sendProgress(p.percent, p.keysTested, keeloq: false);
    });

    handle.result.then((res) {
      if (!identical(_psaHandle, handle)) return; // superseded
      final elapsed = _jobClock.elapsedMilliseconds;
      _writeCustom(
        BfProtocol.encodePsaResult(
          found: res.found,
          counter: res.counter,
          decV0: res.decV0,
          decV1: res.decV1,
          elapsedMs: elapsed,
        ),
      );
      _finishJob(
        res.found
            ? 'PSA key found (counter ${res.counter.toRadixString(16)})'
            : (res.cancelled ? 'PSA cancelled' : 'PSA: no key'),
      );
    }).catchError((Object e) {
      if (!identical(_psaHandle, handle)) return;
      _finishJob('PSA error: $e');
    });
  }

  // ---- KeeLoq ----
  /// Runs the KeeLoq brute-force for [req] (user-Start; wiring unchanged).
  void runKeeloq(KeeloqBfRequest req) {
    _cancelActiveJob();
    _jobKind = OffloadJobKind.keeloq;
    _jobClock
      ..reset()
      ..start();
    _resetProgressRate();
    _emit(running: true, message: 'KeeLoq brute-force…');

    // hop2==0 means only one hop was captured; the native side reuses hop1.
    final handle = KeeloqOffloadRecoverer().start(
      learningType: req.learningType,
      serial: req.serial,
      fix: req.fix,
      hop1: req.hop1,
      hop2: req.hop2,
    );
    _keeloqHandle = handle;

    _keeloqProgressSub = handle.progress.listen((p) {
      _sendProgress(p.percent, p.keysTested, keeloq: true);
    });

    handle.result.then((res) {
      if (!identical(_keeloqHandle, handle)) return;
      final elapsed = _jobClock.elapsedMilliseconds;
      // Stream each candidate, then a completion frame.
      for (final c in res.candidates) {
        _writeCustom(
          BfProtocol.encodeKeeloqCandidate(
            mfkey: c.mfkey,
            devkey: c.devkey,
            counter: c.counter,
            learnType: c.learnType,
          ),
        );
      }
      _writeCustom(
        BfProtocol.encodeKeeloqComplete(
          candidateCount: res.candidates.length,
          elapsedMs: elapsed,
        ),
      );
      _finishJob(
        res.candidates.isNotEmpty
            ? 'KeeLoq: ${res.candidates.length} candidate(s)'
            : (res.cancelled ? 'KeeLoq cancelled' : 'KeeLoq: no key'),
      );
    }).catchError((Object e) {
      if (!identical(_keeloqHandle, handle)) return;
      _finishJob('KeeLoq error: $e');
    });
  }

  // ---- Hitag2 / Fiat V1 ----
  /// Runs the Hitag2Hell brute-force for [req] (user-Start; wiring unchanged).
  void runHitag(HitagBfRequest req) {
    _cancelActiveJob();
    if (req.captures.isEmpty) {
      _writeCustom(BfProtocol.encodeHitagResult(found: false, key: const []));
      return;
    }
    _jobKind = OffloadJobKind.hitag;
    _jobClock
      ..reset()
      ..start();
    _resetProgressRate();
    _emit(running: true, message: 'Hitag2Hell brute-force…');

    final captures = [
      for (final c in req.captures)
        Hitag2Capture(
          uid: req.uid,
          button: c.button,
          counter: c.counter,
          hop: c.hop,
          proto: req.proto,
          raw: c.raw,
          payload42: c.payload42,
        ),
    ];

    final handle = NativeHitag2HellRecoverer().start(
      proto: req.proto,
      captures: captures,
      l0Start: req.l0Start,
      l0End: req.l0End,
    );
    _hitagHandle = handle;

    _hitagProgressSub = handle.progress.listen((p) {
      _sendHitagProgress(p.percent, p.slotsDone);
    });

    handle.result.then((res) {
      if (!identical(_hitagHandle, handle)) return;
      _writeCustom(
        BfProtocol.encodeHitagResult(
          found: res.found,
          key: res.key ?? const [],
        ),
      );
      _finishJob(
        res.found
            ? 'Hitag2 key recovered'
            : (res.cancelled ? 'Hitag2 cancelled' : 'Hitag2: no key'),
      );
    }).catchError((Object e) {
      if (!identical(_hitagHandle, handle)) return;
      _finishJob('Hitag2 error: $e');
    });
  }

  void _sendHitagProgress(int percent, int slotsDone) {
    _writeCustom(BfProtocol.encodeHitagProgress(percent, slotsDone));
    // Compute a rough slots/sec for the UI (same model as _sendProgress).
    final now = DateTime.now().millisecondsSinceEpoch;
    final dt = now - _lastKeysAt;
    var kps = 0;
    if (dt > 0) {
      kps = ((slotsDone - _lastKeys) * 1000 ~/ dt);
      if (kps < 0) kps = 0;
    }
    _lastKeys = slotsDone;
    _lastKeysAt = now;
    _emit(running: true, percent: percent, keys: slotsDone, keysPerSec: kps);
  }

  // ---- Progress throttling (~every 500 ms, like the reference) ----
  void _resetProgressRate() {
    _lastKeys = 0;
    _lastKeysAt = DateTime.now().millisecondsSinceEpoch;
  }

  void _sendProgress(int percent, int keysTested, {required bool keeloq}) {
    // Throttle to ~2 Hz and compute keys/sec.
    _progressThrottle ??= Timer(const Duration(milliseconds: 500), () {
      _progressThrottle = null;
    });
    final now = DateTime.now().millisecondsSinceEpoch;
    final dt = now - _lastKeysAt;
    var kps = 0;
    if (dt > 0) {
      kps = ((keysTested - _lastKeys) * 1000 ~/ dt);
      if (kps < 0) kps = 0;
    }
    _lastKeys = keysTested;
    _lastKeysAt = now;

    _writeCustom(
      keeloq
          ? BfProtocol.encodeKeeloqProgress(keysTested, kps)
          : BfProtocol.encodePsaProgress(keysTested, kps),
    );
    _emit(running: true, percent: percent, keys: keysTested, keysPerSec: kps);
  }

  void _writeCustom(Uint8List bytes) {
    final t = _attached;
    if (t == null) return;
    // Fire-and-forget; a failed write just means the link is gone.
    t.writeCustomData(bytes).catchError((_) {});
  }

  void _cancelActiveJob() {
    _psaHandle?.cancel();
    _keeloqHandle?.cancel();
    _hitagHandle?.cancel();
    _psaProgressSub?.cancel();
    _keeloqProgressSub?.cancel();
    _hitagProgressSub?.cancel();
    _psaHandle = null;
    _keeloqHandle = null;
    _hitagHandle = null;
    _psaProgressSub = null;
    _keeloqProgressSub = null;
    _hitagProgressSub = null;
    _jobKind = OffloadJobKind.none;
    _progressThrottle?.cancel();
    _progressThrottle = null;
  }

  void _finishJob(String message) {
    _psaProgressSub?.cancel();
    _keeloqProgressSub?.cancel();
    _hitagProgressSub?.cancel();
    _psaProgressSub = null;
    _keeloqProgressSub = null;
    _hitagProgressSub = null;
    _psaHandle = null;
    _keeloqHandle = null;
    _hitagHandle = null;
    // Emit the completion with the finished kind so per-tab UIs can show the
    // outcome, then clear the kind for the idle state.
    final finishedKind = _jobKind;
    _jobKind = OffloadJobKind.none;
    _jobClock.stop();
    _progressThrottle?.cancel();
    _progressThrottle = null;
    _emit(running: false, message: message, kind: finishedKind);
  }

  void _emit({
    required bool running,
    int percent = 0,
    int keys = 0,
    int keysPerSec = 0,
    String? message,
    OffloadJobKind? kind,
  }) {
    if (_statusCtrl.isClosed) return;
    _statusCtrl.add(
      OffloadStatus(
        kind: kind ?? _jobKind,
        running: running,
        percent: percent,
        keysTested: keys,
        keysPerSec: keysPerSec,
        lastMessage: message,
      ),
    );
  }

  Future<void> dispose() async {
    _cancelActiveJob();
    await _connSub?.cancel();
    await _customSub?.cancel();
    _connSub = null;
    _customSub = null;
    _attached = null;
    if (!_statusCtrl.isClosed) await _statusCtrl.close();
    if (!_pendingCtrl.isClosed) await _pendingCtrl.close();
  }
}
