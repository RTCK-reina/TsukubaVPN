#!/bin/zsh
# ルート権限なしで到達できる限界までの統合テスト（実サーバーに接続する）
set -e
ROOT="${0:A:h}"; cd "$ROOT"
mkdir -p /tmp/tvpn
SDK="$(xcrun --show-sdk-path)"
swiftc -target arm64-apple-macos14.0 -sdk "$SDK" -o /tmp/tvpn/livetest \
  Sources/Models.swift Sources/VPNGateAPI.swift Sources/Scripts.swift \
  Sources/VPNController.swift Test/Live/main.swift
exec /tmp/tvpn/livetest "$@"
