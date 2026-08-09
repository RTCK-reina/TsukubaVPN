import Foundation

enum Scripts {

    /// openvpn を常駐起動する。root で実行されるのは**このスクリプトだけ**で、しかも1回きり。
    ///
    /// 起動したあとの「どのサーバーにつなぐか」「別のサーバーに乗り換える」「切る」は
    /// すべて管理インターフェース（127.0.0.1、パスワード付き）越しに一般ユーザー権限で行う。
    /// --management-query-remote があるので、接続先は起動時に決めなくてよい。
    static let daemon = """
    #!/bin/sh
    D='__DIR__'
    OV='__OV__'
    PORT=__PORT__
    # すでに常駐していれば何もしない
    P=$(cat "$D/openvpn.pid" 2>/dev/null)
    if [ -n "$P" ] && kill -0 "$P" 2>/dev/null; then
      echo "DAEMON_OK" > "$D/result.txt"
      chmod 644 "$D/result.txt" 2>/dev/null
      exit 0
    fi
    rm -f "$D/openvpn.pid" "$D/result.txt" "$D/dns-status.txt"
    : > "$D/openvpn.log"
    chmod 644 "$D/openvpn.log" 2>/dev/null
    CFG="$D/shared.ovpn"
    SZ=$(wc -c < "$CFG" 2>/dev/null | tr -d ' ')
    if [ -z "$SZ" ] || [ "$SZ" -lt 1000 ] || ! grep -q "<ca>" "$CFG"; then
      echo "BAD_PROFILE" > "$D/result.txt"
      chmod 644 "$D/result.txt" 2>/dev/null
      exit 2
    fi
    "$OV" --config "$CFG" --cd "$D" \\
      --log-append "$D/openvpn.log" --verb 3 --mute-replay-warnings \\
      --management 127.0.0.1 "$PORT" "$D/mgmt.pass" \\
      --management-query-remote --management-hold \\
      --writepid "$D/openvpn.pid" \\
      --script-security 2 --up "$D/up.sh" --down "$D/down.sh" --down-pre --up-restart \\
      --daemon >> "$D/openvpn.log" 2>&1
    n=0
    while [ "$n" -lt 40 ]; do
      if [ -s "$D/openvpn.pid" ]; then break; fi
      sleep 0.25
      n=$((n+1))
    done
    chmod 644 "$D/openvpn.pid" 2>/dev/null
    if [ ! -s "$D/openvpn.pid" ]; then
      echo "DAEMON_FAILED" > "$D/result.txt"
      chmod 644 "$D/result.txt" 2>/dev/null
      exit 1
    fi
    echo "$PORT" > "$D/mgmt.port"
    chmod 644 "$D/mgmt.port" 2>/dev/null
    echo "DAEMON_OK" > "$D/result.txt"
    chmod 644 "$D/result.txt" 2>/dev/null
    exit 0
    """

    /// 非常用の強制停止。管理ソケットが使えないときだけ使う（root が要る）。
    static let stop = """
    #!/bin/sh
    D='__DIR__'
    P=$(cat "$D/openvpn.pid" 2>/dev/null)
    if [ -n "$P" ]; then
      kill "$P" 2>/dev/null
      sleep 1
      kill -9 "$P" 2>/dev/null
    fi
    pkill -f "$D/shared.ovpn" 2>/dev/null
    pkill -f "$D/cand" 2>/dev/null
    sleep 1
    /bin/sh "$D/down.sh" >/dev/null 2>&1
    rm -f "$D/openvpn.pid" "$D/run.lock"
    exit 0
    """

    /// 接続確立時に DNS をトンネル側へ切り替える。openvpn が root で実行する。
    static let up = """
    #!/bin/bash
    # DNS の切り替えに失敗しても VPN 接続そのものは落とさない。
    # openvpn は --up が非ゼロ終了すると接続ごと中断するため、ここは必ず 0 で終わり、
    # 結果を dns-status.txt に残してアプリ側に警告させる。
    D="$(cd "$(dirname "$0")" && pwd)"
    BK="$D/dns-backup.txt"
    ST="$D/dns-status.txt"
    NS=/usr/sbin/networksetup
    fail() {
      echo "failed:$1" > "$ST"
      chmod 644 "$ST" 2>/dev/null
      exit 0
    }
    SERVICES=$("$NS" -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\\*//')
    [ -n "$SERVICES" ] || fail "ネットワークサービスの一覧を取得できませんでした"
    if [ ! -f "$BK" ]; then
      : > "$BK"
      while IFS= read -r svc; do
        [ -z "$svc" ] && continue
        cur=$("$NS" -getdnsservers "$svc" 2>/dev/null | tr '\\n' ' ')
        [ -n "$cur" ] || { rm -f "$BK"; fail "今のDNS設定を読み取れませんでした（$svc）"; }
        printf '%s\\t%s\\n' "$svc" "$cur" >> "$BK" || { rm -f "$BK"; fail "DNS設定を控えられませんでした"; }
      done <<< "$SERVICES"
      [ -s "$BK" ] || { rm -f "$BK"; fail "DNS設定を控えられませんでした"; }
      chmod 644 "$BK" 2>/dev/null
    fi
    DNS=""
    i=1
    while [ "$i" -le 40 ]; do
      eval v="\\$foreign_option_$i"
      [ -z "$v" ] && break
      case "$v" in
        "dhcp-option DNS "*) DNS="$DNS ${v##* }" ;;
      esac
      i=$((i+1))
    done
    if [ -z "$DNS" ]; then DNS="1.1.1.1 8.8.8.8"; fi
    NGSVC=""
    while IFS= read -r svc; do
      [ -z "$svc" ] && continue
      "$NS" -setdnsservers "$svc" $DNS >/dev/null 2>&1 || NGSVC="$NGSVC $svc"
    done <<< "$SERVICES"
    /usr/bin/dscacheutil -flushcache 2>/dev/null
    /usr/bin/killall -HUP mDNSResponder 2>/dev/null
    [ -z "$NGSVC" ] || fail "DNSを切り替えられませんでした（$NGSVC ）"
    echo "ok" > "$ST"
    chmod 644 "$ST" 2>/dev/null
    exit 0
    """

    /// 切断時に DNS を元に戻す。root で実行される。
    static let down = """
    #!/bin/bash
    # 復元に失敗してもここでは 0 で終える（openvpn の経路後始末を巻き添えにしないため）。
    # バックアップは消さずに残し、アプリの「元に戻す」から再試行できるようにする。
    D="$(cd "$(dirname "$0")" && pwd)"
    BK="$D/dns-backup.txt"
    ST="$D/dns-status.txt"
    NS=/usr/sbin/networksetup
    if [ -f "$BK" ]; then
      NGSVC=""
      while IFS=$'\\t' read -r svc cur; do
        [ -z "$svc" ] && continue
        case "$cur" in
          *"any DNS Servers"*|"" ) "$NS" -setdnsservers "$svc" "Empty" >/dev/null 2>&1 || NGSVC="$NGSVC $svc" ;;
          * ) "$NS" -setdnsservers "$svc" $cur >/dev/null 2>&1 || NGSVC="$NGSVC $svc" ;;
        esac
      done < "$BK"
      /usr/bin/dscacheutil -flushcache 2>/dev/null
      /usr/bin/killall -HUP mDNSResponder 2>/dev/null
      if [ -n "$NGSVC" ]; then
        echo "failed:DNS設定を元に戻せませんでした（$NGSVC ）" > "$ST"
        chmod 644 "$ST" 2>/dev/null
        exit 0
      fi
      rm -f "$BK"
    fi
    rm -f "$ST"
    /usr/bin/dscacheutil -flushcache 2>/dev/null
    /usr/bin/killall -HUP mDNSResponder 2>/dev/null
    exit 0
    """

    /// セーフモード接続テスト。root で実行される。
    /// --route-nopull により「経路とDNSは一切変更せず」トンネルだけを張って確認し、すぐ畳む。
    /// 現在の通信経路に影響しないので、リモート接続中でも安全に実行できる。
    static let selftest = """
    #!/bin/sh
    D='__DIR__'
    OV='__OV__'
    N=__N__
    R="$D/selftest.result"
    L="$D/selftest.log"
    rm -f "$R" "$L" "$D/selftest.pid"
    DEF1=$(/usr/sbin/netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print $2" via "$NF; exit}')
    UT1=$(/sbin/ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -c '^utun')
    PORT=__PORT__
    OKF=0
    IDX=0
    VALID=0
    DEV=""
    TUNIP=""
    DEF2="$DEF1"
    UT2="$UT1"
    i=1
    while [ "$i" -le "$N" ]; do
      CFG="$D/selftest$i.ovpn"
      SZ=$(wc -c < "$CFG" 2>/dev/null | tr -d ' ')
      if [ -z "$SZ" ] || [ "$SZ" -lt 1000 ] || ! grep -q "<ca>" "$CFG"; then
        i=$((i+1))
        continue
      fi
      VALID=$((VALID+1))
      : > "$L"
      chmod 644 "$L" 2>/dev/null
      rm -f "$D/selftest.pid"
      pj=0
      while [ "$pj" -lt 8 ]; do
        "$OV" --config "$CFG" --cd "$D" --log-append "$L" --verb 3 --route-nopull --mute-replay-warnings --management 127.0.0.1 "$PORT" "$D/mgmt.pass" --writepid "$D/selftest.pid" --connect-retry-max 1 --connect-timeout 12 --resolv-retry 4 --daemon >> "$L" 2>&1
        sleep 0.4
        if grep -q "Socket bind failed" "$L" 2>/dev/null; then
          PORT=$((PORT+1)); pj=$((pj+1)); : > "$L"; continue
        fi
        break
      done
      n=0
      while [ "$n" -lt 44 ]; do
        if grep -q "Initialization Sequence Completed" "$L" 2>/dev/null; then OKF=1; IDX=$i; break; fi
        if grep -q -E "Exiting due to fatal error|Options error|Cannot allocate TUN|AUTH_FAILED" "$L" 2>/dev/null; then break; fi
        P=$(cat "$D/selftest.pid" 2>/dev/null)
        if [ -n "$P" ]; then
          if ! kill -0 "$P" 2>/dev/null; then break; fi
        fi
        sleep 0.5
        n=$((n+1))
      done
      if [ "$OKF" = "1" ]; then
        DEV=$(grep -o 'utun[0-9][0-9]*' "$L" 2>/dev/null | tail -1)
        TUNIP=$(/sbin/ifconfig "$DEV" 2>/dev/null | awk '/inet /{print $2; exit}')
        DEF2=$(/usr/sbin/netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print $2" via "$NF; exit}')
        UT2=$(/sbin/ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -c '^utun')
      fi
      P=$(cat "$D/selftest.pid" 2>/dev/null)
      if [ -n "$P" ]; then kill "$P" 2>/dev/null; sleep 2; kill -9 "$P" 2>/dev/null; fi
      [ "$OKF" = "1" ] && break
      i=$((i+1))
    done
    sleep 1
    DEF3=$(/usr/sbin/netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print $2" via "$NF; exit}')
    UT3=$(/sbin/ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -c '^utun')
    {
      if [ "$OKF" = "1" ]; then echo "result=OK"; else echo "result=NG"; fi
      if [ "$VALID" = "0" ]; then echo "reason=broken_config"; elif [ "$OKF" != "1" ]; then echo "reason=all_failed"; fi
      echo "index=$IDX"
      echo "dev=$DEV"
      echo "tunip=$TUNIP"
      echo "utun_before=$UT1"
      echo "utun_during=$UT2"
      echo "utun_after=$UT3"
      echo "default_before=$DEF1"
      echo "default_during=$DEF2"
      echo "default_after=$DEF3"
    } > "$R"
    rm -f "$D/selftest.pid"
    chmod 644 "$R" 2>/dev/null
    exit 0
    """
}
