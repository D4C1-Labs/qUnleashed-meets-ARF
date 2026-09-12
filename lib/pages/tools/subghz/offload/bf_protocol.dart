import 'dart:typed_data';

/// Wire protocol for the ARF compute-offload custom-data channel (fe65/fe66).
///
/// The Flipper firmware offloads its heavy PSA/KeeLoq brute-force to the phone:
/// it NOTIFIES a request on fe66 and the phone WRITES progress/results back on
/// fe65. All frames are raw little-endian binary (NOT protobuf); one BLE packet
/// = one message; byte 0 is the message type. Layouts mirror the firmware
/// (applications/main/subghz/scenes/subghz_scene_psa_decrypt.c and
/// subghz_scene_keeloq_decrypt.c) and the reference companion
/// (arf-android-companion PsaBleProtocol.kt / KeeloqBleProtocol.kt).

// ---- PSA message types ----
const int kPsaMsgBfRequest = 0x01; // Flipper -> phone
const int kPsaMsgBfProgress = 0x02; // phone -> Flipper
const int kPsaMsgBfResult = 0x03; // phone -> Flipper
const int kPsaMsgBfCancel = 0x04; // Flipper -> phone

// ---- KeeLoq message types ----
const int kKlMsgBfRequest = 0x10; // Flipper -> phone
const int kKlMsgBfProgress = 0x11; // phone -> Flipper
const int kKlMsgBfResult = 0x12; // phone -> Flipper
const int kKlMsgBfCancel = 0x13; // Flipper -> phone

// ---- Hitag2 / Fiat V1 (Hitag2Hell) message types ----
const int kHtMsgBfRequest = 0x20; // Flipper -> phone (legacy Fiat V1 only)
const int kHtMsgBfProgress = 0x21; // phone -> Flipper
const int kHtMsgBfResult = 0x22; // phone -> Flipper
const int kHtMsgBfCancel = 0x23; // Flipper -> phone
// Combo/slice-aware request (proto: 0=Fiat V1, 1=Fiat V2, 2=Renault V1). The
// firmware now always sends this opcode instead of 0x20.
const int kHtMsgBfRequestV2 = 0x24; // Flipper -> phone

// ---- Hitag2 offload protocol ids (wire `proto` byte + native `proto` arg) ----
const int kHitagProtoFiatV1 = 0;
const int kHitagProtoFiatV2 = 1;
const int kHitagProtoRenaultV1 = 2;

/// On-wire capture size (bytes) for each proto in the 0x24 layout.
const int kHitagCaptureBytesFiatV1 = 7; // btn(1)+cnt(2 LE)+hop(4 LE)
const int kHitagCaptureBytesFiatV2 = 14; // raw[14] verbatim frame
const int kHitagCaptureBytesRenaultV1 = 8; // payload42(6 LE)+button(1)+counter(1)

/// Per-proto capture caps enforced on the wire.
const int kHitagMaxCapturesFiatV1 = 7;
const int kHitagMaxCapturesFiatV2 = 3;
const int kHitagMaxCapturesRenaultV1 = 6;

/// A PSA brute-force request from the Flipper: `[0x01][bf_type][w0:4][w1:4]`.
class PsaBfRequest {
  const PsaBfRequest({required this.bfType, required this.w0, required this.w1});

  /// 1 = BF1, 2 = BF2, 0 = try both (the firmware sends 0).
  final int bfType;
  final int w0;
  final int w1;
}

/// A KeeLoq brute-force request:
/// `[0x10][learn_type][fix:4][hop1:4][hop2:4][serial:4]`.
class KeeloqBfRequest {
  const KeeloqBfRequest({
    required this.learningType,
    required this.fix,
    required this.hop1,
    required this.hop2,
    required this.serial,
  });

  /// 0 = auto (try 6, 7, 8); else the specific learning type.
  final int learningType;
  final int fix;
  final int hop1;
  final int hop2;
  final int serial;
}

/// One captured Hitag2 frame. The active fields depend on the request `proto`:
///   * Fiat V1    : `button`, `counter` (16-bit), `hop`.
///   * Fiat V2    : `raw` (14-byte verbatim frame); uid/hop/counter/IV are
///                  re-derived natively from `raw`.
///   * Renault V1 : `payload42` (low 42 bits), `button`, `counter` (8-bit).
class HitagCapture {
  const HitagCapture({
    this.button = 0,
    this.counter = 0,
    this.hop = 0,
    this.raw,
    this.payload42,
  });
  final int button;
  final int counter;
  final int hop;

  /// Fiat V2: the 14-byte verbatim frame (bytes 0..13). Null otherwise.
  final Uint8List? raw;

  /// Renault V1: the low 42 bits of the payload. Null otherwise.
  final int? payload42;
}

/// A Hitag2Hell brute-force request. Legacy (0x20) requests are Fiat V1 only;
/// the combo/slice-aware (0x24) request carries an explicit [proto].
/// uid is shared by all captures; l0_start/l0_end 0 => full 2^20 sweep.
class HitagBfRequest {
  const HitagBfRequest({
    required this.uid,
    required this.l0Start,
    required this.l0End,
    required this.captures,
    this.proto = kHitagProtoFiatV1,
  });

  final int uid;
  final int l0Start;
  final int l0End;
  final List<HitagCapture> captures;

  /// 0=Fiat V1, 1=Fiat V2, 2=Renault V1.
  final int proto;
}

/// Parses/encodes the offload binary protocol. All multi-byte fields are
/// little-endian.
class BfProtocol {
  /// True if [data] is a PSA offload message (type 0x01..0x04).
  static bool isPsa(Uint8List data) =>
      data.isNotEmpty && data[0] >= kPsaMsgBfRequest && data[0] <= kPsaMsgBfCancel;

  /// True if [data] is a KeeLoq offload message (type 0x10..0x13).
  static bool isKeeloq(Uint8List data) =>
      data.isNotEmpty && data[0] >= kKlMsgBfRequest && data[0] <= kKlMsgBfCancel;

  static bool isPsaCancel(Uint8List data) =>
      data.isNotEmpty && data[0] == kPsaMsgBfCancel;

  static bool isKeeloqCancel(Uint8List data) =>
      data.isNotEmpty && data[0] == kKlMsgBfCancel;

  /// Parses `[0x01][bf_type][w0:4][w1:4]` (10 bytes). Returns null if malformed.
  static PsaBfRequest? parsePsaRequest(Uint8List data) {
    if (data.length < 10 || data[0] != kPsaMsgBfRequest) return null;
    final v = ByteData.sublistView(data);
    final bfType = data[1];
    final w0 = v.getUint32(2, Endian.little);
    final w1 = v.getUint32(6, Endian.little);
    return PsaBfRequest(bfType: bfType, w0: w0, w1: w1);
  }

  /// `[0x02][keys_tested:4][keys_per_sec:4]` (9 bytes).
  static Uint8List encodePsaProgress(int keysTested, int keysPerSec) {
    final b = ByteData(9);
    b.setUint8(0, kPsaMsgBfProgress);
    b.setUint32(1, keysTested & 0xFFFFFFFF, Endian.little);
    b.setUint32(5, keysPerSec & 0xFFFFFFFF, Endian.little);
    return b.buffer.asUint8List();
  }

  /// `[0x03][success:1][counter:4][dec_v0:4][dec_v1:4][elapsed_ms:4]` (18 bytes).
  static Uint8List encodePsaResult({
    required bool found,
    required int counter,
    required int decV0,
    required int decV1,
    required int elapsedMs,
  }) {
    final b = ByteData(18);
    b.setUint8(0, kPsaMsgBfResult);
    b.setUint8(1, found ? 1 : 0);
    b.setUint32(2, counter & 0xFFFFFFFF, Endian.little);
    b.setUint32(6, decV0 & 0xFFFFFFFF, Endian.little);
    b.setUint32(10, decV1 & 0xFFFFFFFF, Endian.little);
    b.setUint32(14, elapsedMs & 0xFFFFFFFF, Endian.little);
    return b.buffer.asUint8List();
  }

  /// Parses `[0x10][learn_type][fix:4][hop1:4][hop2:4][serial:4]` (18 bytes).
  static KeeloqBfRequest? parseKeeloqRequest(Uint8List data) {
    if (data.length < 18 || data[0] != kKlMsgBfRequest) return null;
    final v = ByteData.sublistView(data);
    final learningType = data[1];
    final fix = v.getUint32(2, Endian.little);
    final hop1 = v.getUint32(6, Endian.little);
    final hop2 = v.getUint32(10, Endian.little);
    final serial = v.getUint32(14, Endian.little);
    return KeeloqBfRequest(
      learningType: learningType,
      fix: fix,
      hop1: hop1,
      hop2: hop2,
      serial: serial,
    );
  }

  /// `[0x11][phase:1][keys_tested:4][keys_per_sec:4]` (10 bytes).
  static Uint8List encodeKeeloqProgress(
    int keysTested,
    int keysPerSec, {
    int phase = 0,
  }) {
    final b = ByteData(10);
    b.setUint8(0, kKlMsgBfProgress);
    b.setUint8(1, phase & 0xFF);
    b.setUint32(2, keysTested & 0xFFFFFFFF, Endian.little);
    b.setUint32(6, keysPerSec & 0xFFFFFFFF, Endian.little);
    return b.buffer.asUint8List();
  }

  /// KeeLoq result, 27 bytes. `kind`: 1 = candidate, 2 = complete, 0 = notfound.
  ///   `[0x12][kind:1][mfkey:8][devkey:8][cnt:4][elapsed_ms:4][learn_type:1]`
  static Uint8List _encodeKeeloqResult({
    required int kind,
    int mfkey = 0,
    int devkey = 0,
    int cntOrCount = 0,
    int elapsedMs = 0,
    int learnType = 0,
  }) {
    final b = ByteData(27);
    b.setUint8(0, kKlMsgBfResult);
    b.setUint8(1, kind & 0xFF);
    b.setUint64(2, mfkey, Endian.little);
    b.setUint64(10, devkey, Endian.little);
    b.setUint32(18, cntOrCount & 0xFFFFFFFF, Endian.little);
    b.setUint32(22, elapsedMs & 0xFFFFFFFF, Endian.little);
    b.setUint8(26, learnType & 0xFF);
    return b.buffer.asUint8List();
  }

  /// A recovered candidate (kind = 1).
  static Uint8List encodeKeeloqCandidate({
    required int mfkey,
    required int devkey,
    required int counter,
    required int learnType,
  }) => _encodeKeeloqResult(
    kind: 1,
    mfkey: mfkey,
    devkey: devkey,
    cntOrCount: counter,
    learnType: learnType,
  );

  /// Brute-force complete (kind = 2); carries the candidate count + elapsed.
  static Uint8List encodeKeeloqComplete({
    required int candidateCount,
    required int elapsedMs,
  }) => _encodeKeeloqResult(
    kind: 2,
    cntOrCount: candidateCount,
    elapsedMs: elapsedMs,
  );

  /// Not found (kind = 0).
  static Uint8List encodeKeeloqNotFound({required int elapsedMs}) =>
      _encodeKeeloqResult(kind: 0, elapsedMs: elapsedMs);

  // ---- Hitag2 / Fiat V1 ----

  /// True if [data] is a Hitag2 offload message (type 0x20..0x24).
  static bool isHitag(Uint8List data) =>
      data.isNotEmpty &&
      data[0] >= kHtMsgBfRequest &&
      data[0] <= kHtMsgBfRequestV2;

  static bool isHitagCancel(Uint8List data) =>
      data.isNotEmpty && data[0] == kHtMsgBfCancel;

  /// True if [data] is the combo/slice-aware Hitag2 request (0x24).
  static bool isHitagV2(Uint8List data) =>
      data.isNotEmpty && data[0] == kHtMsgBfRequestV2;

  /// Parses the Hitag2 request (variable length, up to 7 captures). Header is
  /// 14 bytes; each capture adds 7. Returns null if malformed.
  static HitagBfRequest? parseHitagRequest(Uint8List data) {
    if (data.length < 14 || data[0] != kHtMsgBfRequest) return null;
    final v = ByteData.sublistView(data);
    final uid = v.getUint32(1, Endian.little);
    final l0Start = v.getUint32(5, Endian.little);
    final l0End = v.getUint32(9, Endian.little);
    final count = data[13];
    if (data.length < 14 + count * 7) return null;
    final caps = <HitagCapture>[];
    var off = 14;
    for (var i = 0; i < count; i++) {
      final btn = data[off];
      final cnt = v.getUint16(off + 1, Endian.little);
      final hop = v.getUint32(off + 3, Endian.little);
      caps.add(HitagCapture(button: btn, counter: cnt, hop: hop));
      off += 7;
    }
    return HitagBfRequest(
      uid: uid,
      l0Start: l0Start,
      l0End: l0End,
      captures: caps,
    );
  }

  /// Parses the combo/slice-aware Hitag2 request (0x24):
  ///   `[0x24][proto:1][uid:4][l0_start:4][l0_end:4][count:1][captures...]`
  /// Header is 15 bytes; each capture's size depends on `proto`:
  ///   proto 0 (Fiat V1)    : btn(1) + cnt(2 LE) + hop(4 LE)               = 7
  ///   proto 1 (Fiat V2)    : raw[14]                                       = 14
  ///   proto 2 (Renault V1) : payload42(6 LE) + button(1) + counter(1)      = 8
  /// Returns null if malformed (bad opcode, unknown proto, over-cap, or short).
  static HitagBfRequest? parseHitagRequestV2(Uint8List data) {
    if (data.length < 15 || data[0] != kHtMsgBfRequestV2) return null;
    final proto = data[1];
    final int capBytes;
    final int maxCaps;
    switch (proto) {
      case kHitagProtoFiatV1:
        capBytes = kHitagCaptureBytesFiatV1;
        maxCaps = kHitagMaxCapturesFiatV1;
        break;
      case kHitagProtoFiatV2:
        capBytes = kHitagCaptureBytesFiatV2;
        maxCaps = kHitagMaxCapturesFiatV2;
        break;
      case kHitagProtoRenaultV1:
        capBytes = kHitagCaptureBytesRenaultV1;
        maxCaps = kHitagMaxCapturesRenaultV1;
        break;
      default:
        return null;
    }
    final v = ByteData.sublistView(data);
    final uid = v.getUint32(2, Endian.little);
    final l0Start = v.getUint32(6, Endian.little);
    final l0End = v.getUint32(10, Endian.little);
    final count = data[14];
    if (count > maxCaps) return null;
    if (data.length < 15 + count * capBytes) return null;

    final caps = <HitagCapture>[];
    var off = 15;
    for (var i = 0; i < count; i++) {
      switch (proto) {
        case kHitagProtoFiatV1:
          final btn = data[off];
          final cnt = v.getUint16(off + 1, Endian.little);
          final hop = v.getUint32(off + 3, Endian.little);
          caps.add(HitagCapture(button: btn, counter: cnt, hop: hop));
          break;
        case kHitagProtoFiatV2:
          final raw = Uint8List.fromList(
            data.sublist(off, off + kHitagCaptureBytesFiatV2),
          );
          caps.add(HitagCapture(raw: raw));
          break;
        case kHitagProtoRenaultV1:
          // payload42 = low 42 bits, 6 bytes little-endian:
          //   byte[b] = (payload42 >> (8*b)) & 0xFF; top 6 bits of byte[5] = 0.
          var payload42 = 0;
          for (var b = 0; b < 6; b++) {
            payload42 |= data[off + b] << (8 * b);
          }
          payload42 &= 0x3FFFFFFFFFF; // mask to 42 bits (defensive)
          final button = data[off + 6];
          final counter = data[off + 7];
          caps.add(
            HitagCapture(
              button: button,
              counter: counter,
              payload42: payload42,
            ),
          );
          break;
      }
      off += capBytes;
    }
    return HitagBfRequest(
      uid: uid,
      l0Start: l0Start,
      l0End: l0End,
      captures: caps,
      proto: proto,
    );
  }

  /// `[0x21][pct:1][slots_done:8]` (10 bytes).
  static Uint8List encodeHitagProgress(int percent, int slotsDone) {
    final b = ByteData(10);
    b.setUint8(0, kHtMsgBfProgress);
    b.setUint8(1, percent.clamp(0, 100));
    b.setUint64(2, slotsDone, Endian.little);
    return b.buffer.asUint8List();
  }

  /// `[0x22][found:1][key:6][epoch:4]` (12 bytes). key is the 6-byte Hitag2 key
  /// (as stored in the .sub); epoch is 0 for Fiat V1.
  static Uint8List encodeHitagResult({
    required bool found,
    required List<int> key,
    int epoch = 0,
  }) {
    final b = ByteData(12);
    b.setUint8(0, kHtMsgBfResult);
    b.setUint8(1, found ? 1 : 0);
    final out = b.buffer.asUint8List();
    for (var i = 0; i < 6; i++) {
      out[2 + i] = (found && i < key.length) ? (key[i] & 0xFF) : 0;
    }
    b.setUint32(8, epoch & 0xFFFFFFFF, Endian.little);
    return out;
  }
}
