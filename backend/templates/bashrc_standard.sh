#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
#  .bashrc standardise - Deploiement infrastructure RootWarden
#  Version   : 3.0
#  Maintenu  : Equipe Admin.Sys
#  Modifie   : 2026-04-20
#
#  Dependances optionnelles : figlet | toilet (banniere ASCII)
#  Fichiers externes        : /etc/external_ip (IP publique, une ligne)
#  Personnalisation locale  : ~/.bashrc.local (source en fin de fichier)
# ══════════════════════════════════════════════════════════════════════════════

# Quitter si non interactif
case $- in *i*) ;; *) return;; esac

# ══════════════════════════════════════════════════════════════════════════════
#  1. PALETTE DE COULEURS
# ══════════════════════════════════════════════════════════════════════════════

RST='\033[0m'
CYN='\033[0;36m'    WHT='\033[0;37m'
BCYN='\033[1;36m'   BWHT='\033[1;37m'   BYLW='\033[1;33m'
BGRN='\033[1;32m'   BRED='\033[1;31m'   BBLU='\033[1;34m'
DWHT='\033[2;37m'

# Couleurs du tableau sysinfo
_C_IP_INT='\033[0;31m'
_C_HOST='\033[38;5;208m'
_C_IP_EXT='\033[0;34m'
_C_UPTIME='\033[0;32m'

# ══════════════════════════════════════════════════════════════════════════════
#  2. FONCTIONS INTERNES
# ══════════════════════════════════════════════════════════════════════════════

__ccol() {
    local raw="$1" clr="$2" lbl val
    lbl="${raw%%[! ]*}${raw#${raw%%[! ]*}}"
    lbl="${raw%%[! ]*}"
    local tmp="${raw#$lbl}"
    lbl+="${tmp%%[ ]*}"
    val="${raw#*${tmp%%[ ]*}}"
    printf '%b%s%b%b%s%b' "$CYN" "$lbl" "$RST" "$clr" "$val" "$RST"
}

__fmt_uptime() {
    local s="${1:-0}" d h m
    d=$((s/86400))  h=$(((s%86400)/3600))  m=$(((s%3600)/60))
    if   ((d>0)); then echo "${d}j ${h}h ${m}m"
    elif ((h>0)); then echo "${h}h ${m}m"
    else               echo "${m}m"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  3. BANNIERE D'ACCUEIL
# ══════════════════════════════════════════════════════════════════════════════

__banner() {
    local name sep art=""
    name=$(hostname -s | tr '[:lower:]' '[:upper:]')
    sep="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo -e "${BCYN}${sep}${RST}"

    command -v figlet &>/dev/null && art=$(figlet -f slant -w 80 "$name" 2>/dev/null)
    [[ -z "$art" ]] && command -v toilet &>/dev/null && art=$(toilet -f future "$name" 2>/dev/null)

    if [[ -n "$art" ]]; then
        local tw=70
        while IFS= read -r line; do
            local stripped
            stripped=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
            local pad=$(( (tw - ${#stripped}) / 2 ))
            ((pad<0)) && pad=0
            printf "%*s%b%s%b\n" "$pad" "" "$BWHT" "$line" "$RST"
        done <<< "$art"
    else
        local text="Bienvenue sur ${name}"
        local p=4 inner=$(( ${#text} + p*2 ))
        local bar=$(printf '═%.0s' $(seq 1 "$inner"))
        local sp=$(printf ' %.0s' $(seq 1 "$p"))
        echo ""
        echo -e "   ${BCYN}╔${bar}╗${RST}"
        echo -e "   ${BCYN}║${RST}${sp}${BYLW}${text}${RST}${sp}${BCYN}║${RST}"
        echo -e "   ${BCYN}╚${bar}╝${RST}"
        echo ""
    fi

    echo -e "${BCYN}${sep}${RST}"
}

# ══════════════════════════════════════════════════════════════════════════════
#  4. TABLEAU SYSTEME + ALERTES
# ══════════════════════════════════════════════════════════════════════════════

__sysinfo() {
    local os ip_int ip_ext mem disk host up_raw up_fmt
    os=$(. /etc/os-release 2>/dev/null && echo "${NAME} ${VERSION_ID}" || uname -o)
    ip_int=$(ip -4 -o addr show 2>/dev/null | awk '!/127\.0\.0\.1/{print $4;exit}')
    : "${ip_int:=N/A}"

    ip_ext=""
    if command -v dig &>/dev/null; then
        ip_ext=$(dig +short +timeout=2 +tries=1 myip.opendns.com @resolver1.opendns.com 2>/dev/null)
    fi
    if [[ -z "$ip_ext" ]] && command -v curl &>/dev/null; then
        ip_ext=$(curl -4 -s --connect-timeout 2 --max-time 3 ifconfig.me 2>/dev/null)
    fi
    if [[ -z "$ip_ext" ]] && command -v wget &>/dev/null; then
        ip_ext=$(wget -4 -qO- --timeout=3 ifconfig.me 2>/dev/null)
    fi
    if [[ -z "$ip_ext" ]] && [[ -f /etc/external_ip ]]; then
        ip_ext=$(head -1 /etc/external_ip 2>/dev/null | tr -d '[:space:]')
    fi
    : "${ip_ext:=N/A}"

    mem=$(free -h 2>/dev/null | awk '/^Mem:/{printf "%s/%s",$3,$2}')
    : "${mem:=N/A}"
    disk=$(df -h / 2>/dev/null | awk 'NR==2{printf "%s/%s (%s)",$3,$2,$5}')
    host=$(hostname -f 2>/dev/null || hostname)
    up_raw=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
    up_fmt=$(__fmt_uptime "$up_raw")

    local ka_has=0 ka_role="" ka_vip="" ka_ip_ha="" ka_status="" ka_status_color=""
    if systemctl is-active keepalived &>/dev/null; then
        ka_has=1
        local ka_conf="/etc/keepalived/keepalived.conf"

        if [[ -r "$ka_conf" ]]; then
            ka_role=$(awk '/^\s*state\s/{print toupper($2);exit}' "$ka_conf" 2>/dev/null)
            ka_vip=$(awk '/virtual_ipaddress/,/}/' "$ka_conf" 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | head -1)
        fi

        if [[ -z "$ka_vip" ]]; then
            ka_vip=$(ip -4 addr show 2>/dev/null \
                | awk '/inet .* secondary/{print $2; exit}')
        fi

        ka_ip_ha="${ka_vip:-N/A}"

        if [[ -z "$ka_role" ]]; then
            [[ -n "$ka_vip" ]] && ka_role="MASTER" || ka_role="BACKUP"
        fi

        if [[ -n "$ka_vip" ]]; then
            local ka_vip_bare="${ka_vip%%/*}"
            if ip -4 addr show 2>/dev/null | grep -q "${ka_vip_bare}"; then
                ka_status="UP"
                ka_status_color="${BGRN}"
            else
                ka_status="DOWN"
                ka_status_color="${BRED}"
            fi
        else
            ka_status="DOWN"
            ka_status_color="${BRED}"
        fi
    fi

    local uc="${BGRN}"; ((EUID==0)) && uc="${BRED}"

    local W=30 V=22
    local r1c1 r1c2 r1c3 r2c1 r2c2 r2c3 r3c1 r3c2 r3c3

    if ((ka_has)); then
        printf -v r1c1 "  %-8s%-${V}s" "OS"      "$os"
        printf -v r1c2 "%-8s%-${V}s"   "IP.Int"  "$ip_int"
        printf -v r1c3 "%-8s%s"        "RAM"     "$mem"

        printf -v r2c1 "  %-8s%-${V}s" "Host"    "$host"
        printf -v r2c2 "%-8s%-${V}s"   "IP.Ext"  "$ip_ext"
        printf -v r2c3 "%-8s%s"        "Disk"    "$disk"

        local r4c1 r4c2 r4c3
        printf -v r4c1 "  %-8s%-${V}s" "HA.Role" "$ka_role"
        printf -v r4c2 "%-8s%-${V}s"   "IP.HA"   "$ka_ip_ha"
        printf -v r4c3 "%-8s%s"        "HA"      "$ka_status"

        printf -v r3c1 "  %-8s%-${V}s" "User"    "$(whoami)"
        printf -v r3c2 "%-8s%-${V}s"   "Uptime"  "$up_fmt"
        r3c3=$(date '+%d/%m/%Y %H:%M')

        echo ""
        echo -e "$(__ccol "$r1c1" "$WHT")${DWHT}│${RST}$(__ccol "$r1c2" "$_C_IP_INT")${DWHT}│${RST}$(__ccol " $r1c3" "$WHT")"
        echo -e "$(__ccol "$r2c1" "$_C_HOST")${DWHT}│${RST}$(__ccol "$r2c2" "$_C_IP_EXT")${DWHT}│${RST}$(__ccol " $r2c3" "$WHT")"
        echo -e "$(__ccol "$r4c1" "$BYLW")${DWHT}│${RST}$(__ccol "$r4c2" "$BYLW")${DWHT}│${RST}$(__ccol " $r4c3" "$ka_status_color")"
        echo -e "$(__ccol "$r3c1" "$uc")${DWHT}│${RST}$(__ccol "$r3c2" "$_C_UPTIME")${DWHT}│${RST} ${WHT}${r3c3}${RST}"
    else
        printf -v r1c1 "  %-8s%-${V}s" "OS"     "$os"
        printf -v r1c2 "%-8s%-${V}s"   "IP.Int" "$ip_int"
        printf -v r1c3 "%-8s%s"        "RAM"    "$mem"

        printf -v r2c1 "  %-8s%-${V}s" "Host"   "$host"
        printf -v r2c2 "%-8s%-${V}s"   "IP.Ext" "$ip_ext"
        printf -v r2c3 "%-8s%s"        "Disk"   "$disk"

        printf -v r3c1 "  %-8s%-${V}s" "User"   "$(whoami)"
        printf -v r3c2 "%-8s%-${V}s"   "Uptime" "$up_fmt"
        r3c3=$(date '+%d/%m/%Y %H:%M')

        echo ""
        echo -e "$(__ccol "$r1c1" "$WHT")${DWHT}│${RST}$(__ccol "$r1c2" "$_C_IP_INT")${DWHT}│${RST}$(__ccol " $r1c3" "$WHT")"
        echo -e "$(__ccol "$r2c1" "$_C_HOST")${DWHT}│${RST}$(__ccol "$r2c2" "$_C_IP_EXT")${DWHT}│${RST}$(__ccol " $r2c3" "$WHT")"
        echo -e "$(__ccol "$r3c1" "$uc")${DWHT}│${RST}$(__ccol "$r3c2" "$_C_UPTIME")${DWHT}│${RST} ${WHT}${r3c3}${RST}"
    fi

    echo ""

    # Alertes
    local a=0

    ((EUID==0)) \
        && echo -e "  ${BRED}⚠  SESSION ROOT - Toute action est journalisee.${RST}" && a=1

    local cores=$(nproc 2>/dev/null || echo 1)
    awk -v l="$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)" -v c="$cores" \
        'BEGIN{exit !(l+0>c+0)}' 2>/dev/null \
        && echo -e "  ${BYLW}⚠  Charge systeme elevee (load > ${cores} coeurs)${RST}" && a=1

    local dpct
    dpct=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print int($5)}')
    [[ "$dpct" =~ ^[0-9]+$ ]] && ((dpct>90)) \
        && echo -e "  ${BRED}⚠  Espace disque critique : ${dpct}% utilise sur /${RST}" && a=1

    local mpct
    mpct=$(free 2>/dev/null | awk '/^Mem:/{if($2>0) printf "%.0f",($2-$7)/$2*100}')
    [[ "$mpct" =~ ^[0-9]+$ ]] && ((mpct>90)) \
        && echo -e "  ${BRED}⚠  Memoire critique : ${mpct}% de la RAM utilisee${RST}" && a=1

    local swp
    swp=$(free 2>/dev/null | awk '/^Swap:/{print $3}')
    [[ "$swp" =~ ^[0-9]+$ ]] && ((swp>0)) \
        && echo -e "  ${BYLW}⚠  Swap actif : $(free -h 2>/dev/null | awk '/^Swap:/{print $3}') utilise${RST}" && a=1

    if [[ -x /usr/lib/update-notifier/apt-check ]]; then
        local sec
        sec=$(/usr/lib/update-notifier/apt-check 2>&1 | cut -d';' -f2)
        [[ "$sec" =~ ^[0-9]+$ ]] && ((sec>0)) \
            && echo -e "  ${BRED}⚠  ${sec} mise(s) a jour de securite en attente${RST}" && a=1
    fi

    [[ -f /var/run/reboot-required ]] \
        && echo -e "  ${BRED}⚠  Redemarrage requis${RST}" && a=1

    if command -v systemctl &>/dev/null; then
        local fc
        fc=$(systemctl --failed --no-legend 2>/dev/null | wc -l)
        ((fc>0)) \
            && echo -e "  ${BRED}⚠  ${fc} service(s) en echec (systemctl --failed)${RST}" && a=1
    fi

    local zb
    zb=$(ps -eo stat= 2>/dev/null | grep -c '^Z')
    ((zb>0)) \
        && echo -e "  ${BYLW}⚠  ${zb} processus zombie(s) detecte(s)${RST}" && a=1

    if [[ -r /var/log/auth.log ]]; then
        local sf
        sf=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0)
        ((sf>50)) \
            && echo -e "  ${BYLW}⚠  ${sf} tentatives SSH echouees dans auth.log${RST}" && a=1
    fi

    ((up_raw<600)) \
        && echo -e "  ${BYLW}⚠  Serveur redemarre il y a moins de 10 minutes${RST}" && a=1

    ((a)) && echo ""
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
#  5. AFFICHAGE AU LOGIN + CLEAR
# ══════════════════════════════════════════════════════════════════════════════

__banner
__sysinfo

clear() { command clear; __banner; __sysinfo; }

# ══════════════════════════════════════════════════════════════════════════════
#  6. PROMPT (PS1)
# ══════════════════════════════════════════════════════════════════════════════

__prompt() {
    local ec=$?
    local r='\[\033[0m\]' d='\[\033[2;37m\]'
    local g='\[\033[1;32m\]' rd='\[\033[1;31m\]'
    local c='\[\033[1;36m\]' b='\[\033[1;34m\]'
    local p='\[\033[1;35m\]' y='\[\033[1;33m\]'

    local st="${g}✔${r}"
    ((ec)) && st="${rd}✘ ${ec}${r}"

    local uc="$g" pc="\$"
    ((EUID==0)) && uc="$rd" && pc="#"

    local gb=""
    if command -v git &>/dev/null; then
        local br
        br=$(git symbolic-ref --short HEAD 2>/dev/null || git describe --tags --exact-match 2>/dev/null)
        if [[ -n "$br" ]]; then
            local dirty=""
            [[ -n $(git status --porcelain 2>/dev/null) ]] && dirty="${y}*"
            gb=" ${d}on${r} ${p} ${br}${dirty}${r}"
        fi
    fi

    PS1="\n${d}┌─[${r}${st}${d}]${r} ${uc}\u${r}${d}@${r}${c}\h${r}${d}:${r}${b}\w${r}${gb}\n${d}└─▶${r} ${uc}${pc}${r} "
}

PROMPT_COMMAND='__prompt'

# ══════════════════════════════════════════════════════════════════════════════
#  7. HISTORIQUE
# ══════════════════════════════════════════════════════════════════════════════

HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
HISTCONTROL=ignoreboth:erasedups
HISTIGNORE="passwd*:secret*:token*:key=*:export *KEY*:export *SECRET*:export *PASS*"
shopt -s histappend
PROMPT_COMMAND+="${PROMPT_COMMAND:+;}history -a"

# ══════════════════════════════════════════════════════════════════════════════
#  8. OPTIONS SHELL
# ══════════════════════════════════════════════════════════════════════════════

shopt -s checkwinsize cdspell dirspell globstar nocaseglob
stty -ixon 2>/dev/null

# ══════════════════════════════════════════════════════════════════════════════
#  9. ALIASES
# ══════════════════════════════════════════════════════════════════════════════

alias ..='cd ..'  ...='cd ../..'  ....='cd ../../..'

alias ls='ls --color=auto --group-directories-first'
alias ll='ls -lAhF --color=auto --group-directories-first --time-style=long-iso'
alias la='ls -A --color=auto'
alias lt='ls -lAhFtr --color=auto --time-style=long-iso'
alias lsize='ls -lAhFS --color=auto'

alias rm='rm -I --preserve-root'
alias mv='mv -i'  cp='cp -i'  ln='ln -i'
alias chown='chown --preserve-root'
alias chmod='chmod --preserve-root'
alias chgrp='chgrp --preserve-root'

alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

alias ports='ss -tulnp'
alias listen='ss -tlnp'
alias ping='ping -c 5'

alias df='df -hT'
alias du='du -h --max-depth=1 | sort -rh'
alias free='free -h'
alias psmem='ps auxf --sort=-%mem | head -20'
alias pscpu='ps auxf --sort=-%cpu | head -20'
alias topmem='ps aux --sort=-%mem | head -11'
alias topcpu='ps aux --sort=-%cpu | head -11'

alias jlog='journalctl -xe --no-pager -n 50'
alias jfollow='journalctl -f'
alias syslog='tail -f /var/log/syslog 2>/dev/null || journalctl -f'

alias sctl='systemctl'
alias sreload='sudo systemctl daemon-reload'
alias sstatus='systemctl status'
alias sstart='sudo systemctl start'
alias sstop='sudo systemctl stop'
alias srestart='sudo systemctl restart'
alias sfailed='systemctl --failed'

if command -v docker &>/dev/null; then
    alias dk='docker'
    alias dkps='docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"'
    alias dkpsa='docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"'
    alias dklogs='docker logs -f'
    alias dkprune='docker system prune -af --volumes'
    alias dkc='docker compose'
fi

# ══════════════════════════════════════════════════════════════════════════════
#  10. FONCTIONS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

extract() {
    [[ ! -f "$1" ]] && echo "Erreur : '$1' n'est pas un fichier." && return 1
    case "$1" in
        *.tar.bz2|*.tbz2) tar xjf "$1" ;;
        *.tar.gz|*.tgz)   tar xzf "$1" ;;
        *.tar.xz)         tar xJf "$1" ;;
        *.tar)            tar xf  "$1" ;;
        *.bz2)   bunzip2    "$1" ;;  *.gz)  gunzip      "$1" ;;
        *.xz)    xz -d      "$1" ;;  *.zst) zstd -d     "$1" ;;
        *.rar)   unrar x    "$1" ;;  *.zip) unzip       "$1" ;;
        *.7z)    7z x       "$1" ;;  *.Z)   uncompress  "$1" ;;
        *) echo "Format non reconnu : '$1'" ;;
    esac
}

mkcd()     { mkdir -p "$1" && cd "$1" || return 1; }
ff()       { find . -type f -iname "*${1}*" 2>/dev/null; }
fd()       { find . -type d -iname "*${1}*" 2>/dev/null; }
whoisport(){ [[ -z "$1" ]] && echo "Usage : whoisport <port>" && return 1; ss -tulnp | grep ":$1 " || echo "Aucun service sur le port $1"; }
dirtop()   { du -h --max-depth="${1:-1}" 2>/dev/null | sort -rh | head -20; }
bak()      { [[ -z "$1" ]] && echo "Usage : bak <fichier>" && return 1; cp -v "$1" "${1}.bak.$(date +%Y%m%d_%H%M%S)"; }

sysinfo() {
    echo -e "\n${BCYN}═══ Resume systeme ═══${RST}\n"
    echo -e "${CYN}Hostname  :${RST} $(hostname -f 2>/dev/null || hostname)"
    echo -e "${CYN}OS        :${RST} $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
    echo -e "${CYN}Kernel    :${RST} $(uname -r)"
    echo -e "${CYN}Uptime    :${RST} $(uptime -p 2>/dev/null || uptime)"
    echo -e "${CYN}CPU       :${RST} $(nproc) coeurs - $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs)"
    echo -e "${CYN}RAM       :${RST} $(free -h | awk '/^Mem:/{printf "%s / %s",$3,$2}')"
    echo -e "${CYN}Disque /  :${RST} $(df -h / | awk 'NR==2{printf "%s / %s (%s)",$3,$2,$5}')"
    echo -e "${CYN}IP privee :${RST} $(ip -4 -o addr show 2>/dev/null | awk '!/127\.0\.0\.1/{print $4;exit}')"
    echo -e "${CYN}IP pub.   :${RST} $(head -1 /etc/external_ip 2>/dev/null || echo 'N/A')"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
#  11. AUTOCOMPLETION
# ══════════════════════════════════════════════════════════════════════════════

if ! shopt -oq posix; then
    [[ -f /usr/share/bash-completion/bash_completion ]] && . /usr/share/bash-completion/bash_completion \
        || { [[ -f /etc/bash_completion ]] && . /etc/bash_completion; }
fi

if command -v kubectl &>/dev/null; then
    source <(kubectl completion bash 2>/dev/null)
    alias k='kubectl'
    complete -F __start_kubectl k 2>/dev/null
fi

# ══════════════════════════════════════════════════════════════════════════════
#  12. PATH
# ══════════════════════════════════════════════════════════════════════════════

__path_add() { case ":${PATH}:" in *:"$1":*) ;; *) PATH="$1:${PATH}" ;; esac; }
[[ -d "$HOME/.local/bin" ]] && __path_add "$HOME/.local/bin"
[[ -d "$HOME/bin" ]]        && __path_add "$HOME/bin"
[[ -d "/usr/local/sbin" ]]  && __path_add "/usr/local/sbin"
export PATH

# ══════════════════════════════════════════════════════════════════════════════
#  13. PERSONNALISATION LOCALE
# ══════════════════════════════════════════════════════════════════════════════

[[ -f "$HOME/.bashrc.local" ]] && . "$HOME/.bashrc.local"

true
