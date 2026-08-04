#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ldap-add-user.sh
#   389 Directory Server 에 CDP 연동용 사용자 계정을 생성한다.
#   objectClass: inetOrgPerson + posixAccount + shadowAccount
#   (SSSD 로 OS 계정 해석, Ranger Usersync 로 사용자/그룹 동기화가 가능한 스키마)
# ---------------------------------------------------------------------------
set -euo pipefail
# shellcheck source=./ldap-common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/ldap-common.sh"

usage() {
  cat <<'EOF'
사용법: ldap-add-user.sh -u <계정명> [옵션]

필수
  -u, --uid <계정명>          생성할 사용자 계정명 (uid)

이름/속성
  -c, --cn <표시이름>         cn (기본: "<이름> <성>" 또는 계정명)
  -f, --first <이름>          givenName
  -l, --last <성>             sn (기본: 계정명)
  -m, --mail <이메일>         mail
  -H, --home <경로>           홈 디렉터리 (기본: <LDAP_HOME_BASE>/<계정명>)
  -s, --shell <셸>            로그인 셸 (기본: LDAP_SHELL)
  -i, --uid-number <번호>     uidNumber 직접 지정 (기본: 자동 할당)

그룹
  -g, --group <그룹명>        1차 그룹 (기본: LDAP_DEFAULT_GROUP, 없으면 자동 생성)
  -G, --groups <g1,g2,...>    추가 그룹 (memberUid 로 등록, 없는 그룹은 자동 생성)
      --no-create-group       그룹이 없으면 생성하지 않고 오류 처리

패스워드 (미지정 시 터미널에서 입력)
  -p, --password <패스워드>   평문 지정 (ps 노출 위험, 테스트 용도로만 사용)
      --password-file <경로>  패스워드 파일에서 읽기
      --random                랜덤 패스워드 생성 후 화면에 출력

기타
      --dry-run               실제 적용 없이 수행할 LDIF 만 출력
  -h, --help                  도움말

예시
  ./ldap-add-user.sh -u hong -f 길동 -l 홍 -m hong@example.com -G cdpusers,analysts
  ./ldap-add-user.sh -u svc_nifi -c "NiFi Service" --random --dry-run
EOF
}

# ── 인자 파싱 ───────────────────────────────────────────────────────────────
USERNAME=""; CN=""; GIVENNAME=""; SN=""; MAIL=""; HOMEDIR=""; SHELL_PATH=""
UIDNUMBER=""; PRIMARY_GROUP=""; EXTRA_GROUPS=""; CREATE_GROUP=1
PASSWORD=""; PASSWORD_FILE=""; RANDOM_PW=0; DRY_RUN=0

while (( $# > 0 )); do
  case "$1" in
    -u|--uid)         USERNAME="${2:?}"; shift 2 ;;
    -c|--cn)          CN="${2:?}"; shift 2 ;;
    -f|--first)       GIVENNAME="${2:?}"; shift 2 ;;
    -l|--last)        SN="${2:?}"; shift 2 ;;
    -m|--mail)        MAIL="${2:?}"; shift 2 ;;
    -H|--home)        HOMEDIR="${2:?}"; shift 2 ;;
    -s|--shell)       SHELL_PATH="${2:?}"; shift 2 ;;
    -i|--uid-number)  UIDNUMBER="${2:?}"; shift 2 ;;
    -g|--group)       PRIMARY_GROUP="${2:?}"; shift 2 ;;
    -G|--groups)      EXTRA_GROUPS="${2:?}"; shift 2 ;;
    --no-create-group) CREATE_GROUP=0; shift ;;
    -p|--password)    PASSWORD="${2:?}"; shift 2 ;;
    --password-file)  PASSWORD_FILE="${2:?}"; shift 2 ;;
    --random)         RANDOM_PW=1; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) usage >&2; die "알 수 없는 옵션: $1" ;;
  esac
done

[[ -n "$USERNAME" ]] || { usage >&2; die "-u/--uid 는 필수입니다."; }
validate_name "$USERNAME" "계정명"
[[ -n "$UIDNUMBER" && ! "$UIDNUMBER" =~ ^[0-9]+$ ]] && die "uidNumber 는 숫자여야 합니다: $UIDNUMBER"

export DRY_RUN
ldap_init

PRIMARY_GROUP="${PRIMARY_GROUP:-$LDAP_DEFAULT_GROUP}"
SHELL_PATH="${SHELL_PATH:-$LDAP_SHELL}"
HOMEDIR="${HOMEDIR:-${LDAP_HOME_BASE%/}/$USERNAME}"
SN="${SN:-$USERNAME}"
if [[ -z "$CN" ]]; then
  if [[ -n "$GIVENNAME" ]]; then CN="$GIVENNAME $SN"; else CN="$USERNAME"; fi
fi
validate_name "$PRIMARY_GROUP" "그룹명"

# ── 사전 점검 ───────────────────────────────────────────────────────────────
entry_exists "$LDAP_USER_BASE"  || die "사용자 컨테이너가 없습니다: $LDAP_USER_BASE (ldif/01-base-structure.ldif 를 먼저 적용하십시오)"
entry_exists "$LDAP_GROUP_BASE" || die "그룹 컨테이너가 없습니다: $LDAP_GROUP_BASE (ldif/01-base-structure.ldif 를 먼저 적용하십시오)"

USER_DN="$(user_dn "$USERNAME")"
entry_exists "$USER_DN" && die "이미 존재하는 계정입니다: $USER_DN"

# ── 그룹 준비 ───────────────────────────────────────────────────────────────
# ensure_group <그룹명> → gidNumber 출력
ensure_group() {
  local gname=$1 gdn gid
  gdn="$(group_dn "$gname")"
  if entry_exists "$gdn"; then
    gid="$(ldap_search "$LDAP_GROUP_BASE" "(&(objectClass=posixGroup)(cn=$gname))" gidNumber | ldif_values gidNumber | head -n1)"
    [[ -n "$gid" ]] || die "그룹에 gidNumber 가 없습니다: $gdn"
    printf '%s' "$gid"
    return 0
  fi

  (( CREATE_GROUP == 1 )) || die "존재하지 않는 그룹입니다: $gdn"
  gid="$(next_gid_number)"
  log "그룹 생성: $gdn (gidNumber=$gid)"
  {
    printf 'dn: %s\n' "$gdn"
    printf 'changetype: add\n'
    printf 'objectClass: top\n'
    printf 'objectClass: posixGroup\n'
    ldif_attr cn "$gname"
    printf 'gidNumber: %s\n' "$gid"
  } | ldap_apply "그룹 추가 ($gname)" || die "그룹 생성 실패: $gname"
  printf '%s' "$gid"
}

GIDNUMBER="$(ensure_group "$PRIMARY_GROUP")"
[[ -n "$UIDNUMBER" ]] || UIDNUMBER="$(next_uid_number)"

# ── 사용자 엔트리 생성 ──────────────────────────────────────────────────────
log "사용자 생성: $USER_DN (uidNumber=$UIDNUMBER, gidNumber=$GIDNUMBER)"
{
  printf 'dn: %s\n' "$USER_DN"
  printf 'changetype: add\n'
  printf 'objectClass: top\n'
  printf 'objectClass: person\n'
  printf 'objectClass: organizationalPerson\n'
  printf 'objectClass: inetOrgPerson\n'
  printf 'objectClass: posixAccount\n'
  printf 'objectClass: shadowAccount\n'
  ldif_attr uid "$USERNAME"
  ldif_attr cn  "$CN"
  ldif_attr sn  "$SN"
  [[ -n "$GIVENNAME" ]] && ldif_attr givenName "$GIVENNAME"
  [[ -n "$MAIL" ]]      && ldif_attr mail "$MAIL"
  printf 'uidNumber: %s\n' "$UIDNUMBER"
  printf 'gidNumber: %s\n' "$GIDNUMBER"
  ldif_attr homeDirectory "$HOMEDIR"
  ldif_attr loginShell "$SHELL_PATH"
  ldif_attr gecos "$CN"
} | ldap_apply "사용자 추가 ($USERNAME)" || die "사용자 생성 실패: $USERNAME"

# ── 패스워드 설정 ───────────────────────────────────────────────────────────
GENERATED_PW=""
PW_FILE="$(mktemp_secure)"
if [[ -n "$PASSWORD_FILE" ]]; then
  [[ -r "$PASSWORD_FILE" ]] || die "패스워드 파일을 읽을 수 없습니다: $PASSWORD_FILE"
  PW_FILE="$PASSWORD_FILE"
elif [[ -n "$PASSWORD" ]]; then
  printf '%s' "$PASSWORD" > "$PW_FILE"
elif (( RANDOM_PW == 1 )) || [[ ! -t 0 ]]; then
  GENERATED_PW="$(gen_password "$LDAP_RANDOM_PW_LEN")"
  printf '%s' "$GENERATED_PW" > "$PW_FILE"
else
  read_password_into_file "$USERNAME 초기 패스워드" "$PW_FILE"
fi

if ! ldap_set_password "$USER_DN" "$PW_FILE"; then
  warn "계정은 생성되었지만 패스워드 설정에 실패했습니다."
  warn "패스워드 정책(길이/복잡도)을 확인한 뒤 ./ldap-change-password.sh -u $USERNAME 로 재설정하십시오."
  exit 1
fi
log "패스워드 설정 완료"

# ── 추가 그룹 등록 ──────────────────────────────────────────────────────────
if [[ -n "$EXTRA_GROUPS" ]]; then
  IFS=',' read -r -a _groups <<< "$EXTRA_GROUPS"
  for g in "${_groups[@]}"; do
    g="${g// /}"
    [[ -n "$g" ]] || continue
    validate_name "$g" "그룹명"
    ensure_group "$g" >/dev/null
    gdn="$(group_dn "$g")"
    existing="$(ldap_search "$LDAP_GROUP_BASE" "(&(cn=$g)(memberUid=$USERNAME))" dn)"
    if [[ -n "$existing" ]]; then
      log "이미 그룹 멤버입니다: $g"
      continue
    fi
    {
      printf 'dn: %s\n' "$gdn"
      printf 'changetype: modify\n'
      printf 'add: memberUid\n'
      ldif_attr memberUid "$USERNAME"
    } | ldap_apply "그룹 멤버 추가 ($g ← $USERNAME)" || warn "그룹 멤버 추가 실패: $g"
  done
fi

# ── 결과 요약 ───────────────────────────────────────────────────────────────
cat >&2 <<EOF

────────────────────────────────────────────────
 계정 생성 완료
   DN          : $USER_DN
   uid         : $USERNAME
   uidNumber   : $UIDNUMBER
   1차 그룹    : $PRIMARY_GROUP (gid=$GIDNUMBER)
   추가 그룹   : ${EXTRA_GROUPS:-(없음)}
   홈 디렉터리 : $HOMEDIR
   로그인 셸   : $SHELL_PATH
$( [[ -n "$GENERATED_PW" ]] && printf '   생성 패스워드: %s\n' "$GENERATED_PW" )
 확인:  id $USERNAME          (SSSD 구성된 호스트)
        getent passwd $USERNAME
────────────────────────────────────────────────
EOF
