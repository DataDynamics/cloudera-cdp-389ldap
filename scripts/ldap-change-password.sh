#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ldap-change-password.sh
#   389 Directory Server 사용자의 패스워드를 변경한다.
#   - 관리자 모드(기본): LDAP_BIND_DN 으로 바인드하여 대상 계정 패스워드를 재설정
#   - 셀프 모드(--self): 사용자가 현재 패스워드로 바인드하여 직접 변경
#   패스워드 해시는 서버의 passwordStorageScheme(권장: PBKDF2-SHA512) 로 저장된다.
# ---------------------------------------------------------------------------
set -euo pipefail
# shellcheck source=./ldap-common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/ldap-common.sh"

usage() {
  cat <<'EOF'
사용법: ldap-change-password.sh -u <계정명> [옵션]

필수
  -u, --uid <계정명>          패스워드를 변경할 사용자 계정명

패스워드 (미지정 시 터미널에서 입력)
  -p, --password <패스워드>   새 패스워드 평문 지정 (ps 노출 위험, 테스트 용도로만 사용)
      --password-file <경로>  새 패스워드를 파일에서 읽기
      --random                랜덤 패스워드 생성 후 화면에 출력

모드
      --self                  사용자 본인이 현재 패스워드로 인증하여 변경
      --unlock                계정 잠금(nsAccountLock) 및 로그인 실패 잠금 해제만 수행
      --via-modify            ldappasswd(확장 조작) 대신 userPassword 를 직접 replace.
                              TLS 없는 ldap:// 연결에서도 동작하지만 패스워드가 평문으로
                              전송되므로, LDAPS/LDAPI 를 쓸 수 없는 경우에만 사용할 것.

기타
      --dry-run               실제 적용 없이 동작만 출력
  -h, --help                  도움말

예시
  ./ldap-change-password.sh -u hong                    # 관리자가 대화형으로 재설정
  ./ldap-change-password.sh -u hong --random           # 임시 패스워드 발급
  ./ldap-change-password.sh -u hong --self             # 본인이 직접 변경
  ./ldap-change-password.sh -u hong --unlock           # 5회 실패로 잠긴 계정 해제
  ./ldap-change-password.sh -u hong --via-modify       # TLS 없는 환경(평문 노출 감수)
EOF
}

USERNAME=""; PASSWORD=""; PASSWORD_FILE=""; RANDOM_PW=0; SELF=0; UNLOCK=0; DRY_RUN=0
LDAP_PW_METHOD="extop"

while (( $# > 0 )); do
  case "$1" in
    -u|--uid)        USERNAME="${2:?}"; shift 2 ;;
    -p|--password)   PASSWORD="${2:?}"; shift 2 ;;
    --password-file) PASSWORD_FILE="${2:?}"; shift 2 ;;
    --random)        RANDOM_PW=1; shift ;;
    --self)          SELF=1; shift ;;
    --unlock)        UNLOCK=1; shift ;;
    --via-modify)    LDAP_PW_METHOD="modify"; shift ;;
    --dry-run)       DRY_RUN=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) usage >&2; die "알 수 없는 옵션: $1" ;;
  esac
done

[[ -n "$USERNAME" ]] || { usage >&2; die "-u/--uid 는 필수입니다."; }
validate_name "$USERNAME" "계정명"
(( SELF == 1 && UNLOCK == 1 )) && die "--self 와 --unlock 은 함께 사용할 수 없습니다."

export DRY_RUN LDAP_PW_METHOD
require_cmds ldapsearch ldapmodify ldappasswd base64 awk sort
load_config

USER_DN="uid=${USERNAME},${LDAP_USER_BASE}"

# ── 바인드 ──────────────────────────────────────────────────────────────────
OLD_PW_FILE=""
if (( SELF == 1 )); then
  log "셀프 모드: $USER_DN 으로 바인드합니다."
  resolve_self_bind "$USER_DN"
  OLD_PW_FILE="$LDAP_SELF_PW_FILE"
else
  resolve_bind_password
  entry_exists "$USER_DN" || die "존재하지 않는 계정입니다: $USER_DN"
fi

# ── 잠금 해제 모드 ──────────────────────────────────────────────────────────
if (( UNLOCK == 1 )); then
  {
    printf 'dn: %s\n' "$USER_DN"
    printf 'changetype: modify\n'
    printf 'delete: nsAccountLock\n'
  } | ldap_apply "계정 잠금(nsAccountLock) 해제" \
    || log "nsAccountLock 속성이 없어 건너뜁니다."

  {
    printf 'dn: %s\n' "$USER_DN"
    printf 'changetype: modify\n'
    printf 'delete: passwordRetryCount\n'
  } | ldap_apply "로그인 실패 카운터 초기화" \
    || log "실패 카운터가 없어 건너뜁니다. (패스워드 정책 미적용 상태일 수 있습니다)"

  {
    printf 'dn: %s\n' "$USER_DN"
    printf 'changetype: modify\n'
    printf 'delete: accountUnlockTime\n'
  } | ldap_apply "잠금 해제 시각(accountUnlockTime) 제거" \
    || log "accountUnlockTime 속성이 없어 건너뜁니다."

  log "계정 잠금 해제 처리를 마쳤습니다: $USERNAME"
  exit 0
fi

# ── 새 패스워드 준비 ────────────────────────────────────────────────────────
GENERATED_PW=""
NEW_PW_FILE="$(mktemp_secure)"
if [[ -n "$PASSWORD_FILE" ]]; then
  [[ -r "$PASSWORD_FILE" ]] || die "패스워드 파일을 읽을 수 없습니다: $PASSWORD_FILE"
  NEW_PW_FILE="$PASSWORD_FILE"
elif [[ -n "$PASSWORD" ]]; then
  printf '%s' "$PASSWORD" > "$NEW_PW_FILE"
elif (( RANDOM_PW == 1 )); then
  GENERATED_PW="$(gen_password "$LDAP_RANDOM_PW_LEN")"
  printf '%s' "$GENERATED_PW" > "$NEW_PW_FILE"
else
  read_password_into_file "$USERNAME 새 패스워드" "$NEW_PW_FILE"
fi

# ── 변경 ────────────────────────────────────────────────────────────────────
if (( SELF == 1 )); then
  ldap_set_password "$USER_DN" "$NEW_PW_FILE" "$OLD_PW_FILE" || die "패스워드 변경 실패"
else
  ldap_set_password "$USER_DN" "$NEW_PW_FILE" || die "패스워드 변경 실패"
fi

log "패스워드 변경 완료: $USER_DN"
if [[ -n "$GENERATED_PW" ]]; then
  cat >&2 <<EOF

────────────────────────────────────────────────
 계정        : $USERNAME
 새 패스워드 : $GENERATED_PW
 (안전한 경로로 전달하고, 최초 로그인 후 변경하도록 안내하십시오)
────────────────────────────────────────────────
EOF
fi

if (( SELF == 0 )); then
  log "패스워드 정책에 passwordMustChange 가 켜져 있으면 사용자는 다음 로그인 시 변경을 요구받습니다."
fi
log "확인:  ldapwhoami -H \"$LDAP_URI\" -x -D \"$USER_DN\" -W"
