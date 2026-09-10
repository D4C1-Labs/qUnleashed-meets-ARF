// Deploys the SDK and toolchain into ~/.ufbt, then builds every app declared by
// the application.fam of the directory passed as the first argument.
//
//   dart run example/dartufbt_example.dart my_app

import 'dart:io';

import 'package:dartufbt/dartufbt.dart';

Future<void> main(List<String> args) async {
  final appDir = Directory(args.isEmpty ? '.' : args.first);

  final logger = UfbtLogger(sink: UfbtConsoleSink().call);
  final ufbt = UfbtInstaller(logger: logger);

  await ufbt.install(SdkDeployTask.channel(channel: UfbtUpdateChannel.release));

  final status = ufbt.status();
  stdout.writeln('SDK: ${status.version} (${status.target}, ${status.mode})');

  final result = await FapBuilder(
    logger: logger,
    paths: ufbt.paths,
  ).build(appDir: appDir);

  if (!result.success) {
    stderr.writeln(result.error);
    exitCode = 1;
    return;
  }

  stdout.writeln(result.fap!.path);
}
