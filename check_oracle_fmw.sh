#!/bin/bash
# =============================================================================
# check_oracle_fmw.sh  -  v1.0  (26/11/2026)
#
# Releve en LECTURE SEULE des composants Oracle Fusion Middleware (ODI,
# WebLogic, OPSS, OAM, OBIEE...) et des bases Oracle d'un serveur Linux.
# Contexte : CSPU Oracle de novembre 2026
#   CVE-2026-91569  WebLogic Server (TopLink Integration)
#   CVE-2026-114824 Oracle Platform Security for Java (Centralized Thirdparty Jars)
#   CVE-2026-114835 / -91500 / -91510  Oracle Access Manager
#   CVE-2026-114784 Oracle Business Intelligence Enterprise Edition
#   CVE-2026-91558  Service Delivery Platform
# Cibles SIDV : Demeter-W2 (prod, agent ODI), Anteros-W2 (recette).
#
# Usage : sudo ./check_oracle_fmw.sh [-p "<patch> <patch> ..."] [-o <dossier>] [-n]
#   -p  numeros de patch attendus (Patch Availability Document MOS du CSPU),
#       compares a la liste des patchs de chaque Oracle Home
#   -o  dossier du rapport (defaut : dossier courant)
#   -n  ne pas lancer OPatch (lecture des fichiers d'inventaire uniquement)
#
# Sortie : oraclefmw_<HOST>_<AAAAMMJJ_HHMM>.txt
#
# Le script ne modifie rien. Seule exception : OPatch ecrit ses propres logs
# dans <ORACLE_HOME>/cfgtoollogs/opatch (option -n pour l'eviter).
# Les valeurs qui ressemblent a des mots de passe sont masquees.
# A lancer en root (sudo) : OPatch est alors execute sous le compte
# proprietaire de chaque Oracle Home.
# =============================================================================

set -u
export LC_ALL=C

SCRIPT_VERSION="1.0"
EXPECTED=""
OUTDIR="$(pwd)"
RUN_OPATCH=1
OPATCH_TIMEOUT=300
# Motif des process java a detailler (ODI, WebLogic, FMW)
FLAG_RE='oracle\.odi|/odi/|odi[-_.][a-z]|weblogic|wlserver|NodeManager|oracle_common|Oracle_Home|DOMAIN_HOME|oam_server|oam-server|bi_server|obis'

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while getopts "p:o:nh" opt; do
  case "$opt" in
    p) EXPECTED="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    n) RUN_OPATCH=0 ;;
    *) usage ;;
  esac
done

EXPECTED="$(printf '%s' "$EXPECTED" | tr ',;' '  ')"
HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +%Y%m%d_%H%M)"
REPORT="${OUTDIR%/}/oraclefmw_${HOST}_${STAMP}.txt"
TMPF="$(mktemp /tmp/oraclefmw.XXXXXX)" || { echo "mktemp impossible"; exit 1; }
trap 'rm -f "$TMPF" "$TMPF".*' EXIT

# ----------------------------------------------------------------------------
# Etat global
# ----------------------------------------------------------------------------
declare -a OHS=() DOMS=() INVS=() LISTEN_FLAG=()
declare -A SEEN_OH=() SEEN_DOM=() SEEN_INV=() FLAG_PID=() PID_ARGS=() PID_USER=() PID_EXE=() PID_JH=()
DEFAULT_JH=""
WLS_RUNNING=0; NM_RUNNING=0; ODI_RUNNING=0
WLS_BIN=0; OPSS_FOUND=0; ODI_FOUND=0; OAM_HINT=0; BI_HINT=0; SDP_HINT=0; DB_FOUND=0
OPSS_HOMES=""; WLS_HOMES=""; ODI_HOMES=""; DB_HOMES=""; OAM_WHERE=""; BI_WHERE=""; SDP_WHERE=""
MISSING_PATCHES=""
DOM_JEE=0; DOM_JEE_WHERE=""

# ----------------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------------
section() {
  printf '\n%s\n%s\n%s\n' \
    "==============================================================================" \
    "$1" \
    "=============================================================================="
}

mask() {
  sed -E 's/((pass|pwd|password|secret|credential|token)[A-Za-z0-9_.-]*[=:][[:space:]]*)[^[:space:],;"]+/\1****/Ig'
}

canon() { readlink -f "$1" 2>/dev/null; }

attr() { printf '%s' "$2" | sed -nE "s/.*[[:space:]]$1=\"([^\"]*)\".*/\1/p"; }

getprop() { printf '%s\n' "$2" | tr ' ' '\n' | sed -n "s/^-D$1=//p" | head -1 | tr -d '"'; }

jh_from_exe() {
  local h
  h="$(dirname "$(dirname "$1")")"
  case "$h" in */jre) h="$(dirname "$h")" ;; esac
  printf '%s' "$h"
}

add_oh() {
  local d; d="$(canon "$1")"
  [ -n "$d" ] && [ -d "$d" ] || return 0
  [ -n "${SEEN_OH[$d]+x}" ] && return 0
  SEEN_OH[$d]=1; OHS+=("$d")
  echo "  -> Oracle Home candidat : $d  (source : $2)"
}

add_dom() {
  local d; d="$(canon "$1")"
  [ -n "$d" ] && [ -f "$d/config/config.xml" ] || return 0
  [ -n "${SEEN_DOM[$d]+x}" ] && return 0
  SEEN_DOM[$d]=1; DOMS+=("$d")
  echo "  -> Domaine candidat      : $d  (source : $2)"
}

add_inv() {
  local d; d="$(canon "$1")"
  [ -n "$d" ] && [ -f "$d/ContentsXML/inventory.xml" ] || return 0
  [ -n "${SEEN_INV[$d]+x}" ] && return 0
  SEEN_INV[$d]=1; INVS+=("$d")
}

inv_from_loc() {
  # $1 = fichier oraInst.loc
  local l; l="$(sed -n 's/^inventory_loc=//p' "$1" 2>/dev/null | head -1)"
  [ -n "$l" ] && add_inv "$l"
}

local_mounts() {
  df -l -P -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR>1 {print $6}' | grep -v '^/\.snapshots' | sort -u
}

# ----------------------------------------------------------------------------
# 1. Process java
# ----------------------------------------------------------------------------
scan_processes() {
  local pid user args exe0 exe jh f n=0 v cls cwd
  printf '%-8s %-16s %-8s %s\n' "PID" "COMPTE" "ODI/FMW" "EXECUTABLE JAVA"
  while read -r pid user args; do
    exe0="${args%% *}"
    [ "$(basename -- "$exe0" 2>/dev/null)" = "java" ] || continue
    n=$((n+1))
    exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
    case "$exe" in */java) ;; *) exe="$exe0" ;; esac
    jh="$(jh_from_exe "$exe")"
    PID_ARGS[$pid]="$args"; PID_USER[$pid]="$user"; PID_EXE[$pid]="$exe"; PID_JH[$pid]="$jh"
    f="-"
    if printf '%s' "$args" | grep -Eq "$FLAG_RE"; then f="OUI"; FLAG_PID[$pid]=1; fi
    printf '%-8s %-16s %-8s %s\n' "$pid" "$user" "$f" "$exe"
  done < <(ps -eww -o pid=,user:32=,args= 2>/dev/null)
  [ "$n" -eq 0 ] && echo "Aucun process java en execution."
  [ "${#FLAG_PID[@]}" -eq 0 ] && return 0

  for pid in "${!FLAG_PID[@]}"; do
    args="${PID_ARGS[$pid]}"; exe="${PID_EXE[$pid]}"; jh="${PID_JH[$pid]}"
    echo
    echo "--- Process $pid (compte ${PID_USER[$pid]}) ---"
    echo "Demarre le      : $(ps -o lstart= -p "$pid" 2>/dev/null)"
    echo "Executable      : $exe"
    echo "Version Java    : $(timeout 20 "$exe" -version 2>&1 | head -2 | tr '\n' ' ')"
    cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null)"
    echo "Repertoire      : ${cwd:-non lisible}"
    cls="$(printf '%s\n' "$args" | tr ' ' '\n' | grep -E '^(oracle|weblogic|com\.sunopsis|com\.oracle)\.[A-Za-z0-9_.$]+$' | tail -1)"
    echo "Classe lancee   : ${cls:-non determinee}"
    echo "Proprietes utiles :"
    printf '%s\n' "$args" | tr ' ' '\n' \
      | grep -E '^-D(weblogic\.Name|DOMAIN_HOME|domain\.home|oracle\.home|ORACLE_HOME|common\.components\.home|wls\.home|weblogic\.home|odi\.|oracle\.odi|agent)' \
      | mask | sed 's/^/  /'
    echo "Ligne de commande (masquee, 1500 premiers caracteres) :"
    printf '%s\n' "$args" | mask | cut -c1-1500 | sed 's/^/  /'

    case "$args" in *weblogic.Server*) WLS_RUNNING=1 ;; esac
    case "$args" in *weblogic.NodeManager*) NM_RUNNING=1 ;; esac
    case "$args" in *oracle.odi*|*odi*Agent*|*Agent*odi*) ODI_RUNNING=1 ;; esac
    case "$args" in *oam_server*|*oam-server*) OAM_HINT=1; OAM_WHERE="$OAM_WHERE process:$pid" ;; esac
    case "$args" in *bi_server*|*obis*) BI_HINT=1; BI_WHERE="$BI_WHERE process:$pid" ;; esac

    [ -z "$DEFAULT_JH" ] && DEFAULT_JH="$jh"
    v="$(getprop oracle.home "$args")";             [ -n "$v" ] && add_oh "$v" "process $pid -Doracle.home"
    v="$(getprop ORACLE_HOME "$args")";             [ -n "$v" ] && add_oh "$v" "process $pid -DORACLE_HOME"
    v="$(getprop common.components.home "$args")";  [ -n "$v" ] && add_oh "$(dirname "$v")" "process $pid -Dcommon.components.home"
    v="$(getprop wls.home "$args")";                [ -n "$v" ] && add_oh "$(dirname "$(dirname "$v")")" "process $pid -Dwls.home"
    v="$(getprop weblogic.home "$args")";           [ -n "$v" ] && add_oh "$(dirname "$(dirname "$v")")" "process $pid -Dweblogic.home"
    v="$(getprop DOMAIN_HOME "$args")";             [ -n "$v" ] && add_dom "$v" "process $pid -DDOMAIN_HOME"
    v="$(getprop domain.home "$args")";             [ -n "$v" ] && add_dom "$v" "process $pid -Ddomain.home"
    [ -n "$cwd" ] && add_dom "$cwd" "repertoire courant du process $pid"
  done
}

# ----------------------------------------------------------------------------
# 2. Recherche des Oracle Homes et domaines
# ----------------------------------------------------------------------------
find_homes() {
  local m f inv x l name loc removed
  echo "Pointeurs d'inventaire :"
  if [ -f /etc/oraInst.loc ]; then
    echo "  /etc/oraInst.loc : $(sed -n 's/^inventory_loc=//p' /etc/oraInst.loc | head -1)"
    inv_from_loc /etc/oraInst.loc
  else
    echo "  /etc/oraInst.loc absent"
  fi

  echo
  echo "Parcours des volumes locaux (OPatch, config.xml WebLogic, oraInst.loc) :"
  local_mounts | sed 's/^/  volume : /'
  while IFS= read -r m; do
    find "$m" -xdev -name .snapshots -prune -o \
      \( -type d -name OPatch -print -prune \) -o \
      \( -type f -name config.xml -path '*/config/config.xml' -print \) -o \
      \( -type f -name oraInst.loc -print \) 2>/dev/null
  done < <(local_mounts) > "$TMPF.find"

  while IFS= read -r f; do
    case "$f" in
      */OPatch)             add_oh "$(dirname "$f")" "disque (OPatch)" ;;
      */config/config.xml)  grep -q 'xmlns.oracle.com/weblogic/domain' "$f" 2>/dev/null && add_dom "$(dirname "$(dirname "$f")")" "disque (config.xml)" ;;
      */oraInst.loc)        inv_from_loc "$f" ;;
    esac
  done < "$TMPF.find"

  echo
  for inv in "${INVS[@]+"${INVS[@]}"}"; do
    x="$inv/ContentsXML/inventory.xml"
    echo "Inventaire central : $x"
    while read -r l; do
      name="$(attr NAME "$l")"; loc="$(attr LOC "$l")"; removed="$(attr REMOVED "$l")"
      if [ "$removed" = "T" ]; then
        echo "  - $name : $loc (supprime de l'inventaire)"
      else
        echo "  - $name : $loc"
        add_oh "$loc" "inventaire central"
      fi
    done < <(grep -oE '<HOME [^>]*>' "$x" 2>/dev/null)
  done
  [ "${#INVS[@]}" -eq 0 ] && echo "Aucun inventaire central Oracle trouve."
  echo
  echo "Oracle Homes retenus : ${#OHS[@]} ; domaines WebLogic/ODI retenus : ${#DOMS[@]}"
}

# ----------------------------------------------------------------------------
# 3. Analyse d'un Oracle Home
# ----------------------------------------------------------------------------
pres() {
  # $1 = OH, $2 = chemin relatif, $3 = commentaire
  if [ -e "$1/$2" ]; then printf '  [OUI] %-42s %s\n' "$2" "$3"; return 0
  else printf '  [non] %-42s %s\n' "$2" "$3"; return 1; fi
}

analyse_oh() {
  local oh="$1" owner t jh plist l p rc
  local -a runner=()
  echo
  echo "### Oracle Home : $oh"
  owner="$(stat -c %U "$oh" 2>/dev/null)"
  echo "Proprietaire    : ${owner:-inconnu}"

  t="indetermine"
  if [ -x "$oh/bin/oracle" ] || [ -d "$oh/rdbms" ]; then
    t="ORACLE DATABASE (serveur)"; DB_FOUND=1; DB_HOMES="$DB_HOMES $oh"
  elif [ -f "$oh/inventory/registry.xml" ] || [ -d "$oh/oracle_common" ]; then
    t="Fusion Middleware 12c+"
  elif [ -x "$oh/bin/sqlplus" ]; then
    t="client Oracle"
  fi
  echo "Type            : $t"
  if [ "$t" = "ORACLE DATABASE (serveur)" ]; then
    l="$(grep -oE '<COMP NAME="oracle.server" VER="[^"]*"' "$oh/inventory/ContentsXML/comps.xml" 2>/dev/null | head -1 | sed 's/.*VER=//')"
    echo "Version (inventaire) : ${l:-non lue}"
    echo "(Home de base de donnees : hors perimetre des CVE Fusion Middleware, voir section 7)"
    return 0
  fi

  if [ -f "$oh/inventory/registry.xml" ]; then
    echo "Distributions (inventory/registry.xml) :"
    while read -r l; do
      printf '  - %s | version %s | %s\n' "$(attr name "$l")" "$(attr version "$l")" "$(attr status "$l")"
    done < <(grep -oE '<distribution [^>]*>' "$oh/inventory/registry.xml")
    echo "Fonctionnalites liees aux CVE (inventory/registry.xml) :"
    grep -oE '<feature [^>]*>' "$oh/inventory/registry.xml" \
      | grep -iE 'data integrator|weblogic|jps|opss|platform security|access manager|business intelligence|delivery platform' \
      | while read -r l; do printf '  - %s | %s\n' "$(attr name "$l")" "$(attr version "$l")"; done | sort -u | head -40
  elif [ -f "$oh/inventory/ContentsXML/comps.xml" ]; then
    echo "Composants (inventory/ContentsXML/comps.xml, 25 premiers) :"
    grep -oE '<COMP NAME="[^"]*" VER="[^"]*"' "$oh/inventory/ContentsXML/comps.xml" | sed 's/^<COMP /  - /' | sort -u | head -25
  fi

  echo "Presence de composants :"
  if pres "$oh" odi "Oracle Data Integrator"; then ODI_FOUND=1; ODI_HOMES="$ODI_HOMES $oh"; fi
  pres "$oh" odi/agent "agent ODI"
  pres "$oh" odi/studio "ODI Studio"
  if pres "$oh" wlserver/server/lib/weblogic.jar "WebLogic Server -> CVE-2026-91569"; then WLS_BIN=1; WLS_HOMES="$WLS_HOMES $oh"; fi
  if ls -d "$oh"/oracle_common/modules/oracle.jps* >/dev/null 2>&1; then
    printf '  [OUI] %-42s %s\n' "oracle_common/modules/oracle.jps*" "OPSS -> CVE-2026-114824"
    OPSS_FOUND=1; OPSS_HOMES="$OPSS_HOMES $oh"
  else
    printf '  [non] %-42s %s\n' "oracle_common/modules/oracle.jps*" "OPSS -> CVE-2026-114824"
  fi
  pres "$oh" oracle_common/modules/thirdparty "jars tiers centralises (composant de la CVE-2026-114824)"
  if pres "$oh" idm "Identity & Access (OAM) -> CVE-2026-114835/-91500/-91510"; then OAM_HINT=1; OAM_WHERE="$OAM_WHERE $oh/idm"; fi
  if pres "$oh" bi "Business Intelligence (OBIEE) -> CVE-2026-114784"; then BI_HINT=1; BI_WHERE="$BI_WHERE $oh/bi"; fi
  l="$(find "$oh" -maxdepth 2 -type d \( -iname '*sdp*' -o -iname communications \) 2>/dev/null | head -1)"
  if [ -n "$l" ]; then
    printf '  [OUI] %-42s %s\n' "${l#"$oh"/}" "Service Delivery Platform ? -> CVE-2026-91558 (heuristique)"
    SDP_HINT=1; SDP_WHERE="$SDP_WHERE $l"
  else
    printf '  [non] %-42s %s\n' "*sdp* / communications" "Service Delivery Platform -> CVE-2026-91558 (heuristique)"
  fi
  pres "$oh" ohs "Oracle HTTP Server"
  pres "$oh" soa "SOA Suite"
  pres "$oh" em "Enterprise Manager FMW Control"

  jh=""
  if [ -f "$oh/oui/.globalEnv.properties" ]; then
    jh="$(sed -n 's/^JAVA_HOME=//p' "$oh/oui/.globalEnv.properties" | head -1 | sed 's/\\\(.\)/\1/g')"
    echo "JAVA_HOME d'installation (oui/.globalEnv.properties) : ${jh:-non renseigne}"
  fi
  if [ -z "$jh" ] || [ ! -x "$jh/bin/java" ]; then jh="$DEFAULT_JH"; fi
  [ -z "$jh" ] && [ -n "${JAVA_HOME:-}" ] && jh="$JAVA_HOME"
  echo "JAVA_HOME utilise pour OPatch : ${jh:-aucun}"

  plist="$TMPF.patches"
  : > "$plist"
  if [ -x "$oh/OPatch/opatch" ]; then
    if [ "$RUN_OPATCH" -eq 1 ] && [ -n "$jh" ]; then
      if [ "$(id -u)" -eq 0 ] && [ -n "$owner" ] && [ "$owner" != "root" ]; then
        if command -v runuser >/dev/null 2>&1; then runner=(runuser -u "$owner" --); else runner=(sudo -u "$owner"); fi
        echo "OPatch execute sous le compte : $owner"
      fi
      echo "Version d'OPatch :"
      ( cd "$oh" && timeout "$OPATCH_TIMEOUT" ${runner[@]+"${runner[@]}"} env JAVA_HOME="$jh" "$oh/OPatch/opatch" version ) 2>&1 | head -5 | sed 's/^/  /'
      echo "Patchs appliques (opatch lspatches) :"
      ( cd "$oh" && timeout "$OPATCH_TIMEOUT" ${runner[@]+"${runner[@]}"} env JAVA_HOME="$jh" "$oh/OPatch/opatch" lspatches -oh "$oh" ) > "$plist" 2>&1
      rc=$?
      sed 's/^/  /' "$plist"
      [ "$rc" -ne 0 ] && echo "  (code retour OPatch : $rc - voir les fichiers d'inventaire ci-dessous)"
    else
      echo "OPatch non lance (option -n ou JAVA_HOME introuvable)."
    fi
  else
    echo "OPatch absent de cet Oracle Home."
  fi

  echo "Patchs vus dans les fichiers d'inventaire (indicatif) :"
  {
    ls -1 "$oh/inventory/patches" 2>/dev/null
    ls -1 "$oh/.patch_storage" 2>/dev/null
  } | sed -n 's/^\([0-9]\{6,\}\).*/\1/p' | sort -u | tee -a "$plist" | tr '\n' ' ' | sed 's/^/  /'
  echo

  if [ -n "$EXPECTED" ] && [ "$t" = "Fusion Middleware 12c+" ]; then
    echo "Controle des patchs attendus (-p) :"
    for p in $EXPECTED; do
      if grep -qw -- "$p" "$plist"; then echo "  [present] $p"
      else echo "  [ABSENT]  $p"; MISSING_PATCHES="$MISSING_PATCHES $oh:$p"; fi
    done
  fi
}

# ----------------------------------------------------------------------------
# 4. Analyse d'un domaine WebLogic / ODI
# ----------------------------------------------------------------------------
analyse_dom() {
  local d="$1" cfg="$1/config/config.xml" odi="$1/config/fmwconfig/components/ODI" apps
  echo
  echo "### Domaine : $d"
  echo "Nom             : $(grep -m1 -oE '<name>[^<]*</name>' "$cfg" | sed -E 's#</?name>##g')"
  echo "Version         : $(grep -m1 -oE '<domain-version>[^<]*' "$cfg" | sed 's/.*>//')"
  echo "Serveur d'admin : $(grep -m1 -oE '<admin-server-name>[^<]*' "$cfg" | sed 's/.*>//')"
  echo "Serveurs WebLogic declares (nom / adresse d'ecoute / port / port SSL) :"
  awk '
    /<server>/                 { s=1; ssl=0; nap=0; n=""; p=""; a=""; sp="" }
    s && /<ssl>/               { ssl=1 }
    s && /<\/ssl>/             { ssl=0 }
    s && /<network-access-point>/   { nap=1 }
    s && /<\/network-access-point>/ { nap=0 }
    s && !ssl && !nap && n=="" && match($0, /<name>[^<]*<\/name>/)        { n=substr($0, RSTART+6, RLENGTH-13) }
    s && !ssl && !nap && match($0, /<listen-port>[^<]*<\/listen-port>/)   { p=substr($0, RSTART+13, RLENGTH-27) }
    s && !ssl && !nap && match($0, /<listen-address>[^<]*<\/listen-address>/) { a=substr($0, RSTART+16, RLENGTH-33) }
    s && ssl && match($0, /<listen-port>[^<]*<\/listen-port>/)            { sp=substr($0, RSTART+13, RLENGTH-27) }
    s && /<\/server>/ {
      printf "  - %s / %s / %s / %s\n", n, (a=="" ? "toutes interfaces" : a), (p=="" ? "7001 (defaut)" : p), (sp=="" ? "-" : sp)
      s=0; c++
    }
    END { if (c==0) print "  (aucun serveur WebLogic declare)" }
  ' "$cfg"
  echo "Applications deployees (oraclediagent = agent JEE, odiconsole = ODI Console) :"
  apps="$(awk '
    /<app-deployment>/ { a=1; n="" }
    a && n=="" && match($0, /<name>[^<]*<\/name>/) { n=substr($0, RSTART+6, RLENGTH-13); print "  - " n; c++ }
    /<\/app-deployment>/ { a=0 }
    END { if (c==0) print "  (aucune)" }
  ' "$cfg")"
  printf '%s\n' "$apps"
  case "$apps" in *oraclediagent*|*odiconsole*) DOM_JEE=1; DOM_JEE_WHERE="$DOM_JEE_WHERE $d" ;; esac
  if [ -d "$odi" ]; then
    echo "Agents ODI declares dans le domaine : $(ls -1 "$odi" 2>/dev/null | tr '\n' ' ')"
    echo "Parametres reseau des agents (port/host/protocol, mots de passe exclus) :"
    find "$odi" -maxdepth 5 -type f \( -name '*.properties' -o -name '*.xml' \) 2>/dev/null | head -30 | while read -r f; do
      grep -HiE 'port|host|protocol' "$f" 2>/dev/null | grep -viE 'pass|pwd|secret|credential' | head -10
    done | mask | sed 's/^/  /'
  fi
  if [ -f "$d/nodemanager/nodemanager.properties" ]; then
    echo "Node Manager (nodemanager.properties) :"
    grep -E '^(ListenAddress|ListenPort|SecureListener)=' "$d/nodemanager/nodemanager.properties" | sed 's/^/  /'
  fi
}

# ----------------------------------------------------------------------------
# 5. Ports en ecoute
# ----------------------------------------------------------------------------
scan_ports() {
  local _st _rq _sq laddr _peer procinfo pids name expo mark p
  if ! command -v ss >/dev/null 2>&1; then
    if command -v netstat >/dev/null 2>&1; then
      echo "ss absent ; sortie netstat brute :"
      netstat -tlnp 2>/dev/null
    else
      echo "Ni ss ni netstat disponibles : ports non releves."
    fi
    return
  fi
  [ "$(id -u)" -ne 0 ] && echo "(non root : les process des autres comptes ne sont pas identifies)"
  printf '%-8s %-42s %-7s %-14s %s\n' "MARQUE" "ADRESSE:PORT" "EXPO" "PID" "PROCESS"
  while read -r _st _rq _sq laddr _peer procinfo; do
    pids="$(printf '%s' "$procinfo" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' ')"
    name="$(printf '%s' "$procinfo" | grep -oE '\(\("[^"]+"' | head -1 | tr -d '("')"
    case "$laddr" in 127.*|\[::1\]*|::1:*|localhost:*) expo="local" ;; *) expo="reseau" ;; esac
    mark="-"
    for p in $pids; do [ -n "${FLAG_PID[$p]+x}" ] && mark="ODI/FMW"; done
    printf '%-8s %-42s %-7s %-14s %s\n' "$mark" "$laddr" "$expo" "${pids:--}" "${name:--}"
    [ "$mark" != "-" ] && LISTEN_FLAG+=("$laddr ($expo, pid ${pids% })")
  done < <(ss -H -tlnp 2>/dev/null)
}

# ----------------------------------------------------------------------------
# 6. Pare-feu local
# ----------------------------------------------------------------------------
scan_firewall() {
  if command -v firewall-cmd >/dev/null 2>&1; then
    echo "firewalld : $(firewall-cmd --state 2>&1)"
    firewall-cmd --list-all 2>/dev/null | sed 's/^/  /'
  else
    echo "firewall-cmd absent."
  fi
  if command -v iptables >/dev/null 2>&1; then
    echo "Regles iptables de la chaine INPUT (30 premieres) :"
    iptables -S INPUT 2>/dev/null | head -30 | sed 's/^/  /'
  fi
}

# ----------------------------------------------------------------------------
# 7. Bases Oracle
# ----------------------------------------------------------------------------
scan_db() {
  local l
  echo "Process d'instance ou de listener Oracle (ora_pmon_*, tnslsnr) :"
  l="$(ps -eo pid=,user=,args= 2>/dev/null | grep -E 'ora_pmon_|tnslsnr' | grep -v grep)"
  if [ -n "$l" ]; then DB_FOUND=1; printf '%s\n' "$l" | sed 's/^/  /'; else echo "  aucun"; fi
  echo "/etc/oratab :"
  if [ -f /etc/oratab ]; then
    l="$(grep -vE '^[[:space:]]*(#|$)' /etc/oratab)"
    if [ -n "$l" ]; then DB_FOUND=1; printf '%s\n' "$l" | sed 's/^/  /'; else echo "  vide"; fi
  else
    echo "  absent"
  fi
  echo "Oracle Homes de type base de donnees :${DB_HOMES:- aucun}"
}

# ----------------------------------------------------------------------------
# 8. Synthese
# ----------------------------------------------------------------------------
synthese() {
  local listen=" aucun" i
  if [ "${#LISTEN_FLAG[@]}" -gt 0 ]; then
    listen=""
    for i in "${LISTEN_FLAG[@]}"; do listen="$listen $i;"; done
  fi

  echo "Base de donnees Oracle : $([ "$DB_FOUND" -eq 1 ] && echo "DETECTEE (voir sections 3 et 7)" || echo "aucune detectee")"
  echo "Oracle Homes           : ${#OHS[@]}"
  echo "ODI installe           : $([ "$ODI_FOUND" -eq 1 ] && echo "oui ->$ODI_HOMES" || echo "non")"
  echo "Agent ODI en execution : $([ "$ODI_RUNNING" -eq 1 ] && echo "oui" || echo "non detecte")"
  echo "Ports ODI/FMW ecoutes  :$listen"
  echo
  echo "CVE-2026-91569 (WebLogic Server, CVSS 10.0)"
  if [ "$WLS_RUNNING" -eq 1 ]; then
    echo "  => A ANALYSER : un serveur WebLogic est EN EXECUTION. Patch et exposition reseau a traiter."
  elif [ "$NM_RUNNING" -eq 1 ]; then
    echo "  => A ANALYSER : Node Manager WebLogic en execution (aucun serveur WebLogic lance au moment du releve)."
  elif [ "$WLS_BIN" -eq 1 ]; then
    echo "  => A ANALYSER : binaires WebLogic presents mais aucun serveur lance (${WLS_HOMES# })."
    echo "     Exposition nulle tant qu'il n'est pas lance ; le patch reste a appliquer."
  elif [ "$DOM_JEE" -eq 1 ]; then
    echo "  => A VERIFIER : un domaine declare un agent JEE ou ODI Console (${DOM_JEE_WHERE# }) mais les binaires WebLogic n'ont pas ete trouves."
  else
    echo "  => NON CONCERNE : WebLogic Server absent."
  fi
  echo "CVE-2026-114824 (Oracle Platform Security for Java, CVSS 10.0)"
  if [ "$OPSS_FOUND" -eq 1 ]; then
    echo "  => A ANALYSER : librairies OPSS presentes (${OPSS_HOMES# })."
    echo "     Exploitable seulement via un service HTTP qui les charge : voir les ports ODI/FMW ci-dessus."
    echo "     Verifier l'applicabilite du patch a ce type d'installation dans le Patch Availability Document."
  else
    echo "  => NON CONCERNE : OPSS absent des Oracle Homes trouves."
  fi
  echo "CVE-2026-114835 / CVE-2026-91500 / CVE-2026-91510 (Oracle Access Manager, CVSS 10.0)"
  if [ "$OAM_HINT" -eq 1 ]; then echo "  => A ANALYSER : indices OAM ->$OAM_WHERE"; else echo "  => NON CONCERNE : aucun composant OAM trouve."; fi
  echo "CVE-2026-114784 (Oracle Business Intelligence Enterprise Edition, CVSS 10.0)"
  if [ "$BI_HINT" -eq 1 ]; then echo "  => A ANALYSER : indices OBIEE ->$BI_WHERE"; else echo "  => NON CONCERNE : aucun composant OBIEE trouve."; fi
  echo "CVE-2026-91558 (Service Delivery Platform, CVSS 8.3)"
  if [ "$SDP_HINT" -eq 1 ]; then echo "  => A VERIFIER (detection heuristique) ->$SDP_WHERE"; else echo "  => NON CONCERNE : aucun composant SDP trouve."; fi
  echo
  if [ -n "$EXPECTED" ]; then
    echo "Patchs attendus absents :${MISSING_PATCHES:- aucun}"
  else
    echo "Patchs attendus : non controles (option -p non fournie). Comparer la section 3 au Patch Availability Document."
  fi
}

# ----------------------------------------------------------------------------
# Programme principal
# ----------------------------------------------------------------------------
main() {
  local oh d
  section "0. CONTEXTE"
  echo "Script          : check_oracle_fmw.sh v$SCRIPT_VERSION (lecture seule)"
  echo "Machine         : $(hostname -f 2>/dev/null || hostname)"
  echo "Date            : $(date '+%d/%m/%Y %H:%M:%S %Z')"
  echo "Execute par     : $(id)"
  [ "$(id -u)" -ne 0 ] && echo "ATTENTION       : script non lance en root : process, ports et Oracle Homes des autres comptes partiellement visibles."
  grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null | sed 's/^/OS              : /'
  echo "Noyau           : $(uname -r)"
  echo "Patchs attendus : ${EXPECTED:-non fournis}"

  section "1. PROCESS JAVA (detail des process ODI / WebLogic / FMW)"
  scan_processes

  section "2. RECHERCHE DES ORACLE HOMES ET DOMAINES"
  find_homes

  section "3. ANALYSE DES ORACLE HOMES"
  [ "${#OHS[@]}" -eq 0 ] && echo "Aucun Oracle Home trouve."
  for oh in "${OHS[@]+"${OHS[@]}"}"; do analyse_oh "$oh"; done

  section "4. DOMAINES WEBLOGIC / ODI"
  [ "${#DOMS[@]}" -eq 0 ] && echo "Aucun domaine trouve."
  for d in "${DOMS[@]+"${DOMS[@]}"}"; do analyse_dom "$d"; done

  section "5. PORTS TCP EN ECOUTE"
  scan_ports

  section "6. PARE-FEU LOCAL"
  scan_firewall

  section "7. BASES DE DONNEES ORACLE"
  scan_db

  section "8. SYNTHESE PRELIMINAIRE (a valider par l'analyste)"
  synthese

  echo
  echo "Rapport : $REPORT"
}

main 2>&1 | tee "$REPORT"
