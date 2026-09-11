import 'dart:async';

import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import '../../../../services/notifications/notification_center.dart';
import 'offload_dispatcher.dart';

/// Shows a background notification while the phone is running an offloaded
/// PSA/KeeLoq brute-force for the Flipper, with a live progress bar. Bound to
/// [OffloadDispatcher.status]. Best-effort: any platform/plugin failure is
/// swallowed so it can never affect the compute path.
class OffloadNotificationService {
  static final OffloadNotificationService instance =
      OffloadNotificationService._();
  OffloadNotificationService._();

  static const int _notificationId = 2100;
  static const String _channelId = 'compute_offload';
  static const String _channelName = 'Compute offload';
  static const String _channelDesc =
      'Progress while the phone runs a brute-force for the Flipper';

  StreamSubscription<OffloadStatus>? _sub;
  bool _started = false;

  FlutterLocalNotificationsPlugin get _plugin =>
      NotificationCenter.instance.plugin;

  void start(OffloadDispatcher dispatcher) {
    if (_started) return;
    _started = true;
    _sub = dispatcher.status.listen(_onStatus, onError: (_) {});
  }

  Future<void> _onStatus(OffloadStatus s) async {
    try {
      if (s.running) {
        await _showProgress(s);
      } else {
        // Job ended: show a short completion note, then clear.
        if (s.lastMessage != null) {
          await _showDone(s.lastMessage!);
        } else {
          await _cancel();
        }
      }
    } catch (_) {
      // Notifications are cosmetic; never let them break offload.
    }
  }

  Future<void> _showProgress(OffloadStatus s) async {
    final title = switch (s.kind) {
      OffloadJobKind.psa => 'PSA brute-force (offloaded)',
      OffloadJobKind.keeloq => 'KeeLoq brute-force (offloaded)',
      OffloadJobKind.hitag => 'Hitag2Hell brute-force (offloaded)',
      OffloadJobKind.none => 'Brute-force (offloaded)',
    };
    final body = s.keysTested > 0
        ? '${s.percent}% — ${s.keysTested} keys tested'
        : 'Starting…';

    final android = AndroidNotificationDetails(
      _channelId,
      _channelName,
      channelDescription: _channelDesc,
      importance: Importance.low,
      priority: Priority.low,
      onlyAlertOnce: true,
      showProgress: true,
      maxProgress: 100,
      progress: s.percent.clamp(0, 100),
      ongoing: true,
      autoCancel: false,
    );

    await _plugin.show(
      id: _notificationId,
      title: title,
      body: body,
      notificationDetails: NotificationDetails(
        android: android,
        iOS: const DarwinNotificationDetails(presentAlert: false),
        macOS: const DarwinNotificationDetails(presentAlert: false),
      ),
    );
  }

  Future<void> _showDone(String message) async {
    const android = AndroidNotificationDetails(
      _channelId,
      _channelName,
      channelDescription: _channelDesc,
      importance: Importance.defaultImportance,
      priority: Priority.defaultPriority,
      onlyAlertOnce: true,
      ongoing: false,
      autoCancel: true,
    );
    await _plugin.show(
      id: _notificationId,
      title: 'Offload finished',
      body: message,
      notificationDetails: const NotificationDetails(
        android: android,
        iOS: DarwinNotificationDetails(presentAlert: true),
        macOS: DarwinNotificationDetails(presentAlert: true),
      ),
    );
  }

  Future<void> _cancel() async {
    await _plugin.cancel(id: _notificationId);
  }

  Future<void> dispose() async {
    await _sub?.cancel();
    _sub = null;
    _started = false;
  }
}
