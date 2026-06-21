#!/bin/bash

set +e
[[ -t 1 ]] && for run in {1..199}; do echo ""; done
SUDO_OK=0
sudo -n true >/dev/null 2>&1 && SUDO_OK=1 || SUDO_OK=0
BGPASN="N/A"
SERIAL="N/A"
if (( SUDO_OK )); then
  BGPASN=$(sudo -n awk '/^router bgp /{print $3; exit}' /etc/frr/frr.conf 2>/dev/null || echo "N/A")
  SERIAL=$(sudo dmidecode -s system-serial-number 2>/dev/null || echo "N/A")
fi

BGP_SUMMARY=""
if (( SUDO_OK )) && command -v vtysh >/dev/null 2>&1; then
  BGP_SUMMARY=$(sudo -n vtysh -c 'show bgp summary' 2>/dev/null || true)
fi
DATESTR=$(date '+%Y-%m-%d %H:%M %Z')
if [[ -n "$BGP_SUMMARY" ]]; then
BGP_UP_TOTAL=$(
  awk '
    BEGIN {mode=""; intable=0; up4=0; upe=0; t4=""; te=""}
    /^IPv4 Unicast Summary:/ {mode="v4"; next}
    /^L2VPN EVPN Summary:/   {mode="evpn"; next}
    /^Neighbor[[:space:]]/ {intable=1; next}
    /^Total number of neighbors/ {
      if (mode=="v4"  && t4=="") t4=$5;
      if (mode=="evpn" && te=="") te=$5;
      intable=0;
      next
    }
    intable==1 && $1!="" {
      # Established ise "State/PfxRcd" kolonu sayıdır (10. kolon)
      if (mode=="v4"  && $10 ~ /^[0-9]+$/) up4++
      if (mode=="evpn" && $10 ~ /^[0-9]+$/) upe++
    }
    END {
      if (t4=="") t4="0";
      if (te=="") te="0";
      printf "IPv4 %d/%s  EVPN %d/%s", up4, t4, upe, te
    }
  ' <<<"$BGP_SUMMARY")
else
 BGP_UP_TOTAL="N/A"
fi
IPv4_mgmt=$(ip address show eth0 | grep global | awk '{print $2}')
IPv4_lo0=$(ip address show lo | grep global | awk '{print $2}' | head -n 1)
UP=$(uptime -p | awk '{for(i=2;i<=NF;i++){printf "%s ", $i}}')
KERNEL=$(uname -r)
ME=$(whoami)
OWN_TTY=$(tty | cut -d "/" -f3-4)
ME_LABEL="[\033[0;32m$ME\033[0m] \033[1;33m--> \033[1;32m$OWN_TTY\033[0m"
OTHERS_COUNT=$(w -h | awk -v t="$OWN_TTY" '$2!=t{n++} END{print n+0}')
if [ "$OTHERS_COUNT" -gt 0 ]; then
  WHO="$ME_LABEL  \033[1;33m+$OTHERS_COUNT More...\033[0m"
else
  WHO="$ME_LABEL"
fi
OS=$(grep -E '^VERSION=' /etc/os-release | cut -d "\"" -f 2)
MODEL=$(/usr/bin/platform-detect | awk -F, '{print $2}' | tr '[:lower:]' '[:upper:]')
LCTN="LLDPq"
echo -e "
\e[1;32m╔════════════════════════════════════════════════════╗ --------------------------------------------------------------\e[0m
\e[1;32m║....................................................║\e[0m \e[0;33mWelcome to\e[0m \e[1;35m$(hostname)\e[0m \e[0;33m\uE0B6\e[0;30;43m $OS \e[0m\e[0;33m\uE0B4\e[0m
\e[1;32m║...##..##..##..##..######..#####...######...####....║ --------------------------------------------------------------\e[0m
\e[1;32m║...###.##..##..##....##....##..##....##....##..##...║\e[0m \e[0;33mUptime: \e[0;32m"$UP" \e[0m
\e[1;32m║...##.###..##..##....##....##..##....##....######...║ --------------------------------------------------------------\e[0m
\e[1;32m║...##..##...####.....##....##..##....##....##..##...║\e[0m \e[0;33mLoopback: \e[0;31m\uE0B6\e[0;41m\e[1;37m$IPv4_lo0\e[0;31m\uE0B4 \e[0m \e[0;33mMGMT:\e[0m \e[0;31m\uE0B6\e[0;41m\e[1;37m$IPv4_mgmt\e[0;31m\uE0B4 \e[0m
\e[1;32m║...##..##....##....######..#####...######..##..##...║ --------------------------------------------------------------\e[0m
\e[1;32m║....................................................║\e[0m \e[0;33mKernel:\e[0m\e[0;32m $KERNEL\e[0m \e[0;33mDate:\e[0m\e[0;32m $DATESTR\e[0m
\e[1;32m║.######...####....#####...#####....######....#####..║ --------------------------------------------------------------\e[0m
\e[1;32m║.##......##..##...##..##..##..##.....##.....##...##.║\e[0m \e[0;33mLogged-in: \e[0m$WHO \e[0m \e[0;31m\uE0B6\e[0;41m\e[1;33m$SERIAL\e[0;31m\uE0B4\e[0m
\e[1;32m║.####....######...#####...#####......##.....##......║ --------------------------------------------------------------\e[0m
\e[1;32m║.##......##..##...##..##..##..##.....##.....##...##.║\e[0m \e[0;33mBGP-Status: \e[0m\e[0;31m\uE0B6\e[0;41m\e[1;37m$BGP_UP_TOTAL\e[0;31m\uE0B4\e[0m \e[0;33mMODEL: \e[1;32m\uE0B6\e[0;30;42m $MODEL \e[0m\e[1;32m\uE0B4\e[0m
\e[1;32m║.##......##..##...#####...##..##...######....#####..║ --------------------------------------------------------------\e[0m
\e[1;32m║....................................................║\e[0m \e[0;33mLocation:\e[0m \e[0;31m\uE0B6\e[0;41m\e[1;33m$LCTN\e[0;31m\uE0B4 \e[0;33mBGP-ASN:\e[0m \e[0;31m\uE0B6\e[0;41m\e[1;33m$BGPASN\e[0;31m\uE0B4\e[0m
\e[1;32m╚════════════════════════════════════════════════════╝ --------------------------------------------------------------\e[0m
"
