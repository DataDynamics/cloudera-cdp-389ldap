#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ldap-delete-user.sh
#   389 Directory Server 에서 사용자 계정을 삭제한다.
#   기본 동작: 모든 그룹의 memberUid 정리 → 사용자 엔트리 삭제
#   삭제 대신 비활성화(--disable)도 지원한다. (nsAccountLock: true)
# ---------------------------------------------------------------------------
set -euo pipefail
# shellcheck source=./ldap-common.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/ldap-common.sh"

usage() {
  cat <<'EOF'
사용법: ldap-delete-user.sh -u <계정명> [옵션]

필수
  -u, --uid <계정명>      삭제할 사용자 계정명

옵션
      --disable           삭제하지 않고 계정을 잠금 처리 (nsAccountLock: true)
      --enable            잠긴 계정을 다시 활성화 (nsAccountLock 제거)
      --keep-groups       그룹의 memberUid 를 정리하지 않음
      --purge-group       사용자와 동일한 이름의 그룹이 비어 있으면 함께 삭제
  -y, --yes               확인 프롬프트 없이 진행
      --dry-run           실제 적용 없이 수행할 LDIF 만 출력
  -h, --help              도움말

예시
  ./ldap-delete-user.sh -u hong
  ./ldap-delete-user.sh -u hong --disable -y      # 퇴사자 임시 잠금
  ./ldap-delete-user.sh -u hong -y --purge-group
EOF
}

USERNAME=""; DISABLE=0; ENABLE=0; KEEP_GROUPS=0; PURGE_GROUP=0; ASSUME_YES=0; DRY_RUN=0

while (( $# > 0 )); do
  case "$1" in
    -u|--uid)      USERNAME="${2:?}"; shift 2 ;;
    --disable)     DISABLE=1; shift ;;
    --enable)      ENABLE=1; shift ;;
    --keep-groups) KEEP_GROUPS=1; shift ;;
    --purge-group) PURGE_GROUP=1; shift ;;
    -y|--yes)      ASSUME_YES=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) usage >&2; die "알 수 없는 옵션: $1" ;;
  esac
done

[[ -n "$USERNAME" ]] || { usage >&2; die "-u/--uid 는 필수입니다."; }
validate_name "$USERNAME" "계정명"
(( DISABLE == 1 && ENABLE == 1 )) && die "--disable 와 --enable 은 함께 사용할 수 없습니다."

export DRY_RUN ASSUME_YES
ldap_init

USER_DN="$(user_dn "$USERNAME")"
entry_exists "$USER_DN" || die "존재하지 않는 계정입니다: $USER_DN"

# ── 계정 정보 확인 ──────────────────────────────────────────────────────────
INFO="$(ldap_search "$LDAP_USER_BASE" "(uid=$USERNAME)" uid uidNumber gidNumber cn homeDirectory)"
log "대상 계정: $USER_DN"
printf '%s\n' "$INFO" | sed 's/^/         /' >&2

# ── 활성화 ──────────────────────────────────────────────────────────────────
if (( ENABLE == 1 )); then
  {
    printf 'dn: %s\n' "$USER_DN"
    printf 'changetype: modify\n'
    printf 'delete: nsAccountLock\n'
  } | ldap_apply "계정 잠금 해제 ($USERNAME)" \
    || warn "잠금 상태가 아니거나 해제에 실패했습니다."
  exit 0
fi

# ── 비활성화 ────────────────────────────────────────────────────────────────
if (( DISABLE == 1 )); then
  confirm "계정 '$USERNAME' 을(를) 잠금 처리합니다. 계속할까요?" || die "취소되었습니다."
  {
    printf 'dn: %s\n' "$USER_DN"
    printf 'changetype: modify\n'
    printf 'replace: nsAccountLock\n'
    printf 'nsAccountLock: true\n'
  } | ldap_apply "계정 잠금 ($USERNAME)" || die "계정 잠금 실패"
  log "잠긴 계정은 인증이 거부되지만 HDFS/Hive 등의 소유권 정보는 그대로 유지됩니다."
  exit 0
fi

# ── 삭제 ────────────────────────────────────────────────────────────────────
warn "계정을 삭제해도 HDFS/Hive 등에 남아 있는 데이터 소유권은 정리되지 않습니다."
warn "동일한 uidNumber 가 재사용되면 기존 데이터에 접근될 수 있으니 주의하십시오."
confirm "계정 '$USERNAME' ($USER_DN) 을(를) 삭제합니다. 계속할까요?" || die "취소되었습니다."

# 1) 그룹 멤버십 정리
if (( KEEP_GROUPS == 0 )); then
  MEMBER_GROUPS="$(ldap_search "$LDAP_GROUP_BASE" "(&(objectClass=posixGroup)(memberUid=$USERNAME))" dn | ldif_values dn)"
  if [[ -n "$MEMBER_GROUPS" ]]; then
    while IFS= read -r gdn; do
      [[ -n "$gdn" ]] || continue
      {
        printf 'dn: %s\n' "$gdn"
        printf 'changetype: modify\n'
        printf 'delete: memberUid\n'
        ldif_attr memberUid "$USERNAME"
      } | ldap_apply "그룹 멤버 제거 ($gdn)" || warn "그룹 멤버 제거 실패: $gdn"
    done <<< "$MEMBER_GROUPS"
  else
    log "멤버로 등록된 그룹이 없습니다."
  fi
fi

# 2) 사용자 엔트리 삭제
{
  printf 'dn: %s\n' "$USER_DN"
  printf 'changetype: delete\n'
} | ldap_apply "사용자 삭제 ($USERNAME)" || die "사용자 삭제 실패: $USERNAME"

# 3) 동일 이름의 빈 그룹 정리 (옵션)
if (( PURGE_GROUP == 1 )); then
  GDN="$(group_dn "$USERNAME")"
  if entry_exists "$GDN"; then
    MEMBERS="$(ldap_search "$LDAP_GROUP_BASE" "(cn=$USERNAME)" memberUid | ldif_values memberUid)"
    if [[ -z "$MEMBERS" ]]; then
      {
        printf 'dn: %s\n' "$GDN"
        printf 'changetype: delete\n'
      } | ldap_apply "빈 그룹 삭제 ($GDN)" || warn "그룹 삭제 실패: $GDN"
    else
      warn "그룹에 아직 멤버가 남아 있어 삭제하지 않았습니다: $GDN"
    fi
  fi
fi

log "완료되었습니다. 클러스터 호스트에서 캐시를 정리하려면: sss_cache -E (또는 systemctl restart sssd)"
log "Ranger 를 사용 중이라면 Usersync 주기(기본 1시간) 이후 반영되며, Ranger 정책의 사용자 항목은 별도 정리가 필요합니다."
