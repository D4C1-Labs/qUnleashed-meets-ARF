#
# Dart FFI pod for the host-side Sub-GHz crypto (PSA TEA bruteforce, KeeLoq,
# Hitag2Hell Fiat V1). Compiles the unity forwarder (which #includes the shared
# C sources one level up). Referenced as a development pod from ios/Podfile and
# macos/Podfile.
#
Pod::Spec.new do |s|
  s.name             = 'qunleashed_subghz'
  s.version          = '0.0.1'
  s.summary          = 'Host-side Sub-GHz key recovery: PSA, KeeLoq, Hitag2Hell (FFI).'
  s.description      = <<-DESC
PSA TEA bruteforce, KeeLoq block cipher, and the Hitag2Hell Fiat V1
guess-and-determine attack, built as a Dart FFI library. Crypto ported from the
Flipper-ARF firmware and a verified Hitag2Hell core.
                       DESC
  s.homepage         = 'https://github.com/mishamyte/qUnleashed'
  s.license          = { :type => 'GPLv3' }
  s.author           = { 'qUnleashed' => 'noreply@localhost' }

  s.source           = { :path => '.' }
  s.source_files     = 'qunleashed_subghz_unity.c'
  s.requires_arc     = false

  s.ios.dependency 'Flutter'
  s.ios.deployment_target = '12.0'
  s.osx.dependency 'FlutterMacOS'
  s.osx.deployment_target = '10.15'

  # HEADER_SEARCH_PATHS lets the #included sources find their headers (the
  # hitag2/ subdir + the module root).
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'GCC_C_LANGUAGE_STANDARD' => 'gnu11',
    'GCC_TREAT_WARNINGS_AS_ERRORS' => 'NO',
    'HEADER_SEARCH_PATHS' => '"$(PODS_TARGET_SRCROOT)/.." "$(PODS_TARGET_SRCROOT)/../hitag2"',
    'OTHER_CFLAGS' => '-O3',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
  }
end
