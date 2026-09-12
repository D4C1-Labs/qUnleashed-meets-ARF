import 'package:flutter/widgets.dart';

/// Process-wide navigator key so headless services (with no [BuildContext] of
/// their own) can drive navigation — e.g. the compute-offload dispatcher pushing
/// the Sub-GHz Crypto page when the Flipper sends an offload request.
final GlobalKey<NavigatorState> appNavigatorKey = GlobalKey<NavigatorState>();
