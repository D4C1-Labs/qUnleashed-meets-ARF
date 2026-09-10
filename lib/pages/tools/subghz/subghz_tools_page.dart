import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'hitag2hell_recoverer.dart';
import 'keeloq_recoverer.dart';
import 'psa_recoverer.dart';

/// A minimal tools page exercising the three `qunleashed_subghz` recoverers:
/// KeeLoq decrypt (single-shot), the PSA TEA bruteforce (progress + cancel),
/// and the Hitag2Hell Fiat V1 attack (progress + cancel + ETA).
///
/// It deliberately uses plain Material widgets rather than the app's themed
/// components so it stays self-contained; wire it into the tools router the
/// same way the MIFARE `RecoverPage` is (push it as a route).
class SubghzToolsPage extends StatelessWidget {
  const SubghzToolsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Sub-GHz Tools'),
          bottom: const TabBar(
            tabs: [
              Tab(text: 'KeeLoq'),
              Tab(text: 'PSA'),
              Tab(text: 'Hitag2Hell'),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            _KeeloqTab(),
            _PsaTab(),
            _Hitag2Tab(),
          ],
        ),
      ),
    );
  }
}

// Parses a hex string (optional 0x prefix, spaces ignored) to an int, or null.
int? _parseHex(String s) {
  final cleaned = s.trim().replaceAll(' ', '').replaceAll('0x', '');
  if (cleaned.isEmpty) return null;
  return int.tryParse(cleaned, radix: 16);
}

// Parses exactly [n] bytes from a hex string.
List<int>? _parseHexBytes(String s, int n) {
  final cleaned = s.trim().replaceAll(' ', '').replaceAll('0x', '');
  if (cleaned.length != n * 2) return null;
  final out = <int>[];
  for (var i = 0; i < cleaned.length; i += 2) {
    final b = int.tryParse(cleaned.substring(i, i + 2), radix: 16);
    if (b == null) return null;
    out.add(b);
  }
  return out;
}

String _hex(int v, int width) =>
    v.toRadixString(16).toUpperCase().padLeft(width, '0');

// ---------------------------------------------------------------------------
// KeeLoq
// ---------------------------------------------------------------------------
class _KeeloqTab extends StatefulWidget {
  const _KeeloqTab();

  @override
  State<_KeeloqTab> createState() => _KeeloqTabState();
}

class _KeeloqTabState extends State<_KeeloqTab> {
  final _hop = TextEditingController();
  final _key = TextEditingController();
  String _output = '';

  @override
  void dispose() {
    _hop.dispose();
    _key.dispose();
    super.dispose();
  }

  void _run() {
    final hop = _parseHex(_hop.text);
    final key = _parseHex(_key.text);
    if (hop == null || key == null) {
      setState(() => _output = 'Invalid hex for hop or key.');
      return;
    }
    try {
      final plain = KeeloqRecoverer.decrypt(hop, key);
      setState(() => _output = 'decrypt = 0x${_hex(plain, 8)}');
    } catch (e) {
      setState(() => _output = 'Native error: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _hop,
            decoration: const InputDecoration(
              labelText: 'Hop (hex, 32-bit)',
              hintText: 'e.g. 1A2B3C4D',
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _key,
            decoration: const InputDecoration(
              labelText: 'Key (hex, 64-bit)',
              hintText: 'e.g. 0123456789ABCDEF',
            ),
          ),
          const SizedBox(height: 12),
          ElevatedButton(onPressed: _run, child: const Text('Decrypt')),
          const SizedBox(height: 16),
          SelectableText(_output),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// PSA
// ---------------------------------------------------------------------------
class _PsaTab extends StatefulWidget {
  const _PsaTab();

  @override
  State<_PsaTab> createState() => _PsaTabState();
}

class _PsaTabState extends State<_PsaTab> {
  final _key1 = TextEditingController();
  final _key2 = TextEditingController();
  final _recoverer = NativePsaRecoverer();

  PsaBruteforceHandle? _handle;
  double _progress = 0;
  int _keysTested = 0;
  bool _running = false;
  String _output = '';

  @override
  void dispose() {
    _key1.dispose();
    _key2.dispose();
    super.dispose();
  }

  Future<void> _run() async {
    final k1 = _parseHexBytes(_key1.text, 8);
    final k2 = _parseHexBytes(_key2.text, 8);
    if (k1 == null || k2 == null) {
      setState(() => _output = 'Each key must be exactly 8 bytes of hex.');
      return;
    }

    setState(() {
      _running = true;
      _progress = 0;
      _keysTested = 0;
      _output = 'Running…';
    });

    try {
      final handle = _recoverer.start(key1: k1, key2: k2);
      _handle = handle;
      handle.progress.listen((p) {
        if (!mounted) return;
        setState(() {
          _progress = p.percent / 100.0;
          _keysTested = p.keysTested;
        });
      });
      final res = await handle.result;
      if (!mounted) return;
      setState(() {
        _running = false;
        _handle = null;
        if (res.found) {
          _output =
              'FOUND\nserial=0x${_hex(res.serial, 16)}\n'
              'cnt=${res.counter} btn=${res.button} type=${res.type}';
        } else if (res.cancelled) {
          _output = 'Cancelled.';
        } else {
          _output = 'No key found.';
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _running = false;
        _handle = null;
        _output = 'Error: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _key1,
            decoration: const InputDecoration(
              labelText: 'Key1 (hex, 8 bytes)',
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _key2,
            decoration: const InputDecoration(
              labelText: 'Key2 (hex, 8 bytes)',
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton(
                  onPressed: _running ? null : _run,
                  child: const Text('Bruteforce'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: OutlinedButton(
                  onPressed: _running ? () => _handle?.cancel() : null,
                  child: const Text('Cancel'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (_running) ...[
            LinearProgressIndicator(value: _progress == 0 ? null : _progress),
            const SizedBox(height: 8),
            Text(
              '${(_progress * 100).toStringAsFixed(1)}%  '
              'keys=$_keysTested',
            ),
          ],
          const SizedBox(height: 16),
          SelectableText(_output),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Hitag2Hell
// ---------------------------------------------------------------------------
class _Hitag2Tab extends StatefulWidget {
  const _Hitag2Tab();

  @override
  State<_Hitag2Tab> createState() => _Hitag2TabState();
}

class _Hitag2TabState extends State<_Hitag2Tab> {
  // One capture row of manual inputs.
  final _uid = TextEditingController();
  final _btn = TextEditingController();
  final _cnt = TextEditingController();
  final _hop = TextEditingController();
  final _recoverer = NativeHitag2HellRecoverer();

  final _captures = <Hitag2Capture>[];
  Hitag2RecoverHandle? _handle;
  double _progress = 0;
  int _slots = 0;
  DateTime? _startedAt;
  bool _running = false;
  String _output = '';

  @override
  void dispose() {
    _uid.dispose();
    _btn.dispose();
    _cnt.dispose();
    _hop.dispose();
    super.dispose();
  }

  void _addCapture() {
    final uid = _parseHex(_uid.text);
    final btn = int.tryParse(_btn.text.trim());
    final cnt = int.tryParse(_cnt.text.trim());
    final hop = _parseHex(_hop.text);
    if (uid == null || btn == null || cnt == null || hop == null) {
      setState(() => _output = 'Invalid capture (uid/hop hex, btn/cnt decimal).');
      return;
    }
    setState(() {
      _captures.add(
        Hitag2Capture(uid: uid, button: btn, counter: cnt, hop: hop),
      );
      _output = '${_captures.length} capture(s) queued.';
    });
  }

  String _eta() {
    if (_startedAt == null || _progress <= 0) return '—';
    final elapsed = DateTime.now().difference(_startedAt!);
    final total = elapsed.inMilliseconds / _progress;
    final remaining = Duration(
      milliseconds: (total - elapsed.inMilliseconds).round(),
    );
    return '${remaining.inMinutes}m ${remaining.inSeconds % 60}s';
  }

  Future<void> _run() async {
    if (_captures.isEmpty) {
      setState(() => _output = 'Add at least one capture first.');
      return;
    }
    setState(() {
      _running = true;
      _progress = 0;
      _slots = 0;
      _startedAt = DateTime.now();
      _output = 'Running full 2^20 sweep…';
    });
    try {
      final handle = _recoverer.start(captures: List.of(_captures));
      _handle = handle;
      handle.progress.listen((p) {
        if (!mounted) return;
        setState(() {
          _progress = p.percent / 100.0;
          _slots = p.slotsDone;
        });
      });
      final res = await handle.result;
      if (!mounted) return;
      setState(() {
        _running = false;
        _handle = null;
        if (res.found) {
          _output = 'FOUND key = ${_bytesHex(res.key!)}';
        } else if (res.cancelled) {
          _output = 'Cancelled.';
        } else {
          _output = 'No key found.';
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _running = false;
        _handle = null;
        _output = 'Error: $e';
      });
    }
  }

  static String _bytesHex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).toUpperCase().padLeft(2, '0')).join('');

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: _uid,
            decoration: const InputDecoration(labelText: 'UID (hex, 32-bit)'),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _btn,
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: const InputDecoration(labelText: 'Btn'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _cnt,
                  keyboardType: TextInputType.number,
                  inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  decoration: const InputDecoration(labelText: 'Cnt'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _hop,
            decoration: const InputDecoration(labelText: 'Hop (hex, 32-bit)'),
          ),
          const SizedBox(height: 12),
          OutlinedButton(
            onPressed: _running ? null : _addCapture,
            child: const Text('Add capture'),
          ),
          const SizedBox(height: 8),
          Text('${_captures.length} capture(s) queued'),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton(
                  onPressed: _running ? null : _run,
                  child: const Text('Recover'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: OutlinedButton(
                  onPressed: _running ? () => _handle?.cancel() : null,
                  child: const Text('Cancel'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (_running) ...[
            LinearProgressIndicator(value: _progress == 0 ? null : _progress),
            const SizedBox(height: 8),
            Text(
              '${(_progress * 100).toStringAsFixed(2)}%  '
              'slots=$_slots  ETA ${_eta()}',
            ),
          ],
          const SizedBox(height: 16),
          SelectableText(_output),
        ],
      ),
    );
  }
}
