#!/bin/zsh
# 動作検証（管理者権限なしで通せる範囲をすべて確認する）
set -e
ROOT="${0:A:h}"; cd "$ROOT"
mkdir -p /tmp/tvpn
SDK="$(xcrun --show-sdk-path)"
swiftc -target arm64-apple-macos14.0 -sdk "$SDK" -o /tmp/tvpn/verify \
  Sources/Models.swift Sources/VPNGateAPI.swift Sources/Scripts.swift \
  Sources/VPNController.swift Test/main.swift
exec /tmp/tvpn/verify "$@"
