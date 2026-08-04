#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ldap-common.sh
#   389 Directory Server 사용자 관리 스크립트 공통 함수 모음 (source 전용)
#   ldap-add-user.sh / ldap-delete-user.sh / ldap-change-password.sh 에서 사용
# ---------------------------------------------------------------------------

[[ -n "${_LDAP_COMMON_LOADED:-}" ]] && return 0
_LDAP_COMMON_LOADED=1

LDAP_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ── 로깅 ────────────────────────────────────────────────────────────────────
log()  { printf '[INFO ] %s\n' "$*" >&2; }
warn() { printf '[WARN ] %s\n' "$*" >&2; }
err()  { printf '[ERROR] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ── 임시 파일 관리 ───────────────────────────────────────────────────────────
_LDAP_TMP_FILES=()

mktemp_secure() {
  local f
  f="$(mktemp "${TMPDIR:-/tmp}/ldaputil.XXXXXXXX")" || die "임시 파일 생성 실패"
  chmod 600 "$f"
  _LDAP_TMP_FILES+=("$f")
  printf '%s' "$f"
}

cleanup_tmp() {
  local f
  for f in "${_LDAP_TMP_FILES[@]:-}"; do
    [[ -n "$f" && -f "$f" ]] || continue
    shred -u "$f" 2>/dev/null || rm -f "$f"
  done
  _LDAP_TMP_FILES=()
}
trap cleanup_tmp EXIT INT TERM

# ── 사전 점검 ───────────────────────────────────────────────────────────────
require_cmds() {
  local c missing=()
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
  if (( ${#missing[@]} > 0 )); then
    err "필요한 명령을 찾을 수 없습니다: ${missing[*]}"
    die "openldap-clients(RHEL 계열) 또는 ldap-utils(Debian 계열) 패키지를 설치하십시오."
  fi
}

# ── 설정 로드 ───────────────────────────────────────────────────────────────
load_config() {
  local cfg="${LDAP_ENV_FILE:-$LDAP_SCRIPT_DIR/ldap.env}"

  if [[ -f "$cfg" ]]; then
    # shellcheck disable=SC1090
    source "$cfg"
  elif [[ -n "${LDAP_ENV_FILE:-}" ]]; then
    die "설정 파일을 찾을 수 없습니다: $cfg"
  else
    warn "설정 파일이 없습니다($cfg). 환경변수 값만 사용합니다."
  fi

  : "${LDAP_URI:?LDAP_URI 를 설정하십시오 (예: ldaps://ldap01.example.com:636)}"
  : "${LDAP_BASE_DN:?LDAP_BASE_DN 을 설정하십시오 (예: dc=example,dc=com)}"
  : "${LDAP_BIND_DN:?LDAP_BIND_DN 을 설정하십시오}"

  LDAP_USER_BASE="${LDAP_USER_BASE:-ou=People,${LDAP_BASE_DN}}"
  LDAP_GROUP_BASE="${LDAP_GROUP_BASE:-ou=Groups,${LDAP_BASE_DN}}"
  LDAP_DEFAULT_GROUP="${LDAP_DEFAULT_GROUP:-cdpusers}"
  LDAP_UID_MIN="${LDAP_UID_MIN:-20000}"
  LDAP_GID_MIN="${LDAP_GID_MIN:-20000}"
  LDAP_HOME_BASE="${LDAP_HOME_BASE:-/home}"
  LDAP_SHELL="${LDAP_SHELL:-/bin/bash}"
  LDAP_RANDOM_PW_LEN="${LDAP_RANDOM_PW_LEN:-16}"

  if [[ -n "${LDAP_TLS_CACERT:-}" ]]; then
    if [[ -r "$LDAP_TLS_CACERT" ]]; then
      export LDAPTLS_CACERT="$LDAP_TLS_CACERT"
    else
      warn "CA 인증서를 읽을 수 없습니다: $LDAP_TLS_CACERT (시스템 신뢰 저장소를 사용합니다)"
    fi
  fi
  export LDAPTLS_REQCERT="${LDAP_TLS_REQCERT:-demand}"

  if [[ "$LDAP_URI" != ldaps://* && "$LDAP_URI" != ldapi://* ]]; then
    warn "평문 LDAP(${LDAP_URI}) 로 접속합니다. 패스워드가 네트워크에 노출될 수 있습니다."
    if [[ "${LDAP_PW_METHOD:-extop}" != "modify" ]]; then
      warn "389 DS 는 패스워드 변경(Password Modify 확장 조작)을 보안 연결에서만 허용하므로"
      warn "'Confidentiality required (13)' 오류가 발생할 수 있습니다."
      warn "→ ldaps:// / ldapi:// 사용을 권장하며, 불가피한 경우 --via-modify 옵션을 사용하십시오."
    fi
  fi
}

# ── 인증 인자 구성 ──────────────────────────────────────────────────────────
# LDAP_AUTH_ARGS 배열을 만든다. resolve_bind_password 이후 호출.
LDAP_AUTH_ARGS=()

resolve_bind_password() {
  local pw
  if [[ -n "${LDAP_BIND_PW_FILE:-}" ]]; then
    [[ -r "$LDAP_BIND_PW_FILE" ]] || die "패스워드 파일을 읽을 수 없습니다: $LDAP_BIND_PW_FILE"
    LDAP_PW_FILE="$LDAP_BIND_PW_FILE"
  elif [[ -n "${LDAP_BIND_PW:-}" ]]; then
    LDAP_PW_FILE="$(mktemp_secure)"
    printf '%s' "$LDAP_BIND_PW" > "$LDAP_PW_FILE"
  else
    [[ -t 0 ]] || die "바인드 패스워드가 없습니다. LDAP_BIND_PW_FILE 또는 LDAP_BIND_PW 를 설정하십시오."
    read -rsp "${LDAP_BIND_DN} 패스워드: " pw; printf '\n' >&2
    [[ -n "$pw" ]] || die "패스워드가 비어 있습니다."
    LDAP_PW_FILE="$(mktemp_secure)"
    printf '%s' "$pw" > "$LDAP_PW_FILE"
    unset pw
  fi
  LDAP_AUTH_ARGS=( -H "$LDAP_URI" -x -D "$LDAP_BIND_DN" -y "$LDAP_PW_FILE" )
}

# 자기 자신으로 바인드 (--self 모드)
resolve_self_bind() {
  local dn=$1 pw
  read -rsp "현재 패스워드: " pw; printf '\n' >&2
  [[ -n "$pw" ]] || die "패스워드가 비어 있습니다."
  LDAP_SELF_PW_FILE="$(mktemp_secure)"
  printf '%s' "$pw" > "$LDAP_SELF_PW_FILE"
  unset pw
  LDAP_AUTH_ARGS=( -H "$LDAP_URI" -x -D "$dn" -y "$LDAP_SELF_PW_FILE" )
}

# ── LDIF 유틸 ───────────────────────────────────────────────────────────────
# 여러 줄로 접힌(folded) LDIF 를 한 줄로 펼친다.
unfold_ldif() {
  awk '
    { if (substr($0,1,1) == " ") { printf "%s", substr($0,2) }
      else { if (NR > 1) printf "\n"; printf "%s", $0 } }
    END { if (NR > 0) printf "\n" }
  '
}

# 표준입력 LDIF 에서 특정 속성 값만 추출 (base64 값 자동 디코드)
ldif_values() {
  local attr="${1,,}" line name val
  while IFS= read -r line; do
    [[ "$line" == *:* ]] || continue
    name="${line%%:*}"
    [[ "${name,,}" == "$attr" ]] || continue
    val="${line#*:}"
    if [[ "$val" == :* ]]; then
      val="${val#:}"
      printf '%s\n' "$(printf '%s' "${val# }" | base64 -d)"
    else
      printf '%s\n' "${val# }"
    fi
  done
}

# LDIF 한 줄 생성. ASCII 범위를 벗어나거나 특수 문자로 시작/끝나면 base64 로 인코딩.
ldif_attr() {
  local name=$1 value=$2 encoded
  if printf '%s' "$value" | LC_ALL=C grep -q '[^ -~]' \
     || [[ "$value" == [\ :\<]* || "$value" == *' ' ]]; then
    encoded="$(printf '%s' "$value" | base64 | tr -d '\n')"
    printf '%s:: %s\n' "$name" "$encoded"
  else
    printf '%s: %s\n' "$name" "$value"
  fi
}

# ── 이름 검증 ───────────────────────────────────────────────────────────────
# DN 이스케이프 이슈를 피하기 위해 계정/그룹명은 보수적으로 제한한다.
validate_name() {
  local name=$1 kind=${2:-계정명}
  [[ -n "$name" ]] || die "${kind}이(가) 비어 있습니다."
  (( ${#name} <= 64 )) || die "${kind}이(가) 너무 깁니다(64자 초과): $name"
  [[ "$name" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] \
    || die "${kind}은(는) 영문/숫자로 시작하고 [a-zA-Z0-9._-] 만 사용할 수 있습니다: $name"
}

user_dn()  { printf 'uid=%s,%s' "$1" "$LDAP_USER_BASE"; }
group_dn() { printf 'cn=%s,%s' "$1" "$LDAP_GROUP_BASE"; }

# ── LDAP 조회/변경 ──────────────────────────────────────────────────────────
# ldap_search <base> <filter> [attrs...]
ldap_search() {
  local base=$1 filter=$2 out rc=0
  shift 2
  out="$(ldapsearch -LLL "${LDAP_AUTH_ARGS[@]}" -b "$base" -s sub "$filter" "$@" 2>&1)" || rc=$?
  if (( rc != 0 )); then
    (( rc == 32 )) && return 0          # No such object → 빈 결과
    err "LDAP 조회 실패 (base=$base, rc=$rc)"
    printf '%s\n' "$out" >&2
    return "$rc"
  fi
  printf '%s\n' "$out" | unfold_ldif
}

entry_exists() {
  local dn=$1 out rc=0
  out="$(ldapsearch -LLL "${LDAP_AUTH_ARGS[@]}" -b "$dn" -s base '(objectClass=*)' dn 2>&1)" || rc=$?
  case "$rc" in
    0)  [[ -n "$out" ]] && return 0 || return 1 ;;
    32) return 1 ;;                     # No such object
    *)  err "LDAP 조회 실패 (dn=$dn, rc=$rc)"; printf '%s\n' "$out" >&2; exit "$rc" ;;
  esac
}

# 표준입력의 LDIF 를 적용. DRY_RUN=1 이면 출력만 한다.
# ldap_apply <설명>
ldap_apply() {
  local desc=$1 ldif out rc=0
  ldif="$(cat)"
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] ${desc}"
    printf '%s\n' "$ldif" | sed 's/^/          | /' >&2
    return 0
  fi
  out="$(printf '%s\n' "$ldif" | ldapmodify "${LDAP_AUTH_ARGS[@]}" 2>&1)" || rc=$?
  if (( rc != 0 )); then
    err "${desc} 실패 (rc=$rc)"
    printf '%s\n' "$out" >&2
    return "$rc"
  fi
  log "${desc} 완료"
}

# ldap_set_password <dn> <new-password-file> [old-password-file]
#   LDAP_PW_METHOD=extop  (기본) ldappasswd — RFC 3062 확장 조작. 보안 연결 필요.
#   LDAP_PW_METHOD=modify        userPassword 속성을 직접 replace. 평문 연결에서도 동작하지만
#                                패스워드가 네트워크에 그대로 노출된다.
ldap_set_password() {
  local dn=$1 newpw=$2 oldpw=${3:-} out rc=0 args=() pw

  if [[ "${LDAP_PW_METHOD:-extop}" == "modify" ]]; then
    pw="$(cat "$newpw")"
    [[ -n "$pw" ]] || { err "패스워드가 비어 있습니다."; return 1; }
    {
      printf 'dn: %s\n' "$dn"
      printf 'changetype: modify\n'
      printf 'replace: userPassword\n'
      ldif_attr userPassword "$pw"
    } | ldap_apply "패스워드 설정 (userPassword modify)"
    return $?
  fi

  args=( "${LDAP_AUTH_ARGS[@]}" -T "$newpw" )
  [[ -n "$oldpw" ]] && args+=( -t "$oldpw" )
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log "[dry-run] 패스워드 변경: $dn"
    return 0
  fi
  out="$(ldappasswd "${args[@]}" "$dn" 2>&1)" || rc=$?
  if (( rc != 0 )); then
    err "패스워드 설정 실패 (dn=$dn, rc=$rc)"
    printf '%s\n' "$out" >&2
    if [[ "$out" == *"secure connection"* || "$out" == *"Confidentiality required"* ]]; then
      err "389 DS 는 Password Modify 확장 조작을 보안 연결에서만 허용합니다."
      err "ldaps:// 로 접속하거나, LDAPI/STARTTLS 를 사용하거나, --via-modify 옵션을 사용하십시오."
    fi
    return "$rc"
  fi
  return 0
}

# ── ID 자동 할당 ────────────────────────────────────────────────────────────
# next_id <attr> <base> <filter> <min>
next_id() {
  local attr=$1 base=$2 filter=$3 min=$4 max_used
  max_used="$(ldap_search "$base" "$filter" "$attr" | ldif_values "$attr" | sort -n | tail -n1)"
  if [[ -z "$max_used" || ! "$max_used" =~ ^[0-9]+$ || "$max_used" -lt "$min" ]]; then
    printf '%s' "$min"
  else
    printf '%s' "$(( max_used + 1 ))"
  fi
}

next_uid_number() { next_id uidNumber "$LDAP_USER_BASE"  '(objectClass=posixAccount)' "$LDAP_UID_MIN"; }
next_gid_number() { next_id gidNumber "$LDAP_GROUP_BASE" '(objectClass=posixGroup)'   "$LDAP_GID_MIN"; }

# ── 패스워드 입력/생성 ──────────────────────────────────────────────────────
read_password_into_file() {
  local prompt=$1 file=$2 p1 p2
  [[ -t 0 ]] || die "대화형 입력이 불가능합니다. --password / --password-file / --random 을 사용하십시오."
  read -rsp "${prompt}: " p1; printf '\n' >&2
  read -rsp "${prompt} (확인): " p2; printf '\n' >&2
  [[ -n "$p1" ]]        || die "빈 패스워드는 사용할 수 없습니다."
  [[ "$p1" == "$p2" ]]  || die "패스워드가 일치하지 않습니다."
  printf '%s' "$p1" > "$file"
  unset p1 p2
}

_rand_chars() {  # <charset> <count>
  local set=$1 n=$2 out=""
  while (( ${#out} < n )); do
    out+="$(LC_ALL=C tr -dc "$set" < /dev/urandom | head -c "$(( n - ${#out} ))")" || true
  done
  printf '%s' "$out"
}

# 대문자/소문자/숫자/특수문자를 각각 최소 1자 포함하는 랜덤 패스워드 생성
gen_password() {
  local len=${1:-16} raw
  (( len >= 8 )) || len=8
  raw="$(_rand_chars 'A-Z' 1)$(_rand_chars 'a-z' 1)$(_rand_chars '0-9' 1)$(_rand_chars '!@#%^_=+-' 1)"
  raw+="$(_rand_chars 'A-Za-z0-9!@#%^_=+-' "$(( len - 4 ))")"
  printf '%s' "$raw" | fold -w1 | shuf | tr -d '\n'
}

# ── 공통 확인 ───────────────────────────────────────────────────────────────
confirm() {
  local prompt=$1 ans
  [[ "${ASSUME_YES:-0}" == "1" ]] && return 0
  [[ -t 0 ]] || die "확인 입력이 불가능합니다. -y/--yes 옵션을 사용하십시오."
  read -rp "${prompt} [y/N]: " ans
  [[ "$ans" == [yY] || "$ans" == [yY][eE][sS] ]]
}

# 스크립트 공통 초기화
ldap_init() {
  require_cmds ldapsearch ldapmodify ldappasswd base64 awk sort
  load_config
  resolve_bind_password
}
