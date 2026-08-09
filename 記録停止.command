#!/bin/bash
cd "$(dirname "$0")"
clear
echo "==============================================="
echo "  記録を停止してレポートを作ります"
echo "==============================================="
echo
./record.sh stop
echo
echo "Finder で report.md を開いた状態にしました。"
echo "Claude に「ログ見て」と言えば内容を読み取ります。"
