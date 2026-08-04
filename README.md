# Cloudera CDP + 389 Directory Server (389 LDAP) 연동 가이드

오픈소스 LDAP 서버인 **389 Directory Server(389 DS)** 를 설치하고, **Cloudera CDP Private Cloud Base** 의
LDAP 인증(Cloudera Manager / Ranger / Hue / Hive / Impala / Knox) 및 클러스터 호스트의 OS 계정 해석(SSSD)에
연동하는 방법을 정리한 문서입니다. 사용자 추가 / 삭제 / 패스워드 변경을 위한 셸 스크립트도 함께 제공합니다.

---

## 목차

1. [구성 개요](#1-구성-개요)
2. [사전 준비](#2-사전-준비)
3. [389 DS 설치](#3-389-ds-설치)
4. [인스턴스 생성](#4-인스턴스-생성)
5. [TLS(LDAPS) 구성](#5-tlsldaps-구성)
6. [디렉터리 구조 · 서비스 계정 · ACI](#6-디렉터리-구조--서비스-계정--aci)
7. [패스워드 정책과 인덱스](#7-패스워드-정책과-인덱스)
8. [사용자 관리 스크립트](#8-사용자-관리-스크립트)
9. [클러스터 호스트 SSSD 연동 (필수)](#9-클러스터-호스트-sssd-연동-필수)
10. [Cloudera CDP 컴포넌트 연동](#10-cloudera-cdp-컴포넌트-연동)
11. [검증 절차](#11-검증-절차)
12. [운영 · 백업 · 트러블슈팅](#12-운영--백업--트러블슈팅)
13. [보안 체크리스트](#13-보안-체크리스트)

---

## 1. 구성 개요

```
                    ┌──────────────────────────────────────────┐
                    │        389 DS (ldap01.example.com)       │
                    │  suffix: dc=example,dc=com               │
                    │   ├─ ou=People   (posixAccount + person) │
                    │   ├─ ou=Groups   (posixGroup / memberUid)│
                    │   └─ ou=Services (bind 계정)             │
                    └──────┬───────────────────────────┬───────┘
                    ldaps(636)                     ldaps(636)
                           │                           │
        ┌──────────────────┴───────────┐   ┌───────────┴─────────────────┐
        │  CDP 서비스 인증              │   │  클러스터 호스트 OS 계정     │
        │  - Cloudera Manager (외부인증)│   │  - SSSD (id/auth provider)  │
        │  - Ranger Admin / Usersync    │   │  - getent passwd / id       │
        │  - Hue / Hive / Impala / Knox │   │  - HDFS·YARN 그룹 매핑      │
        └───────────────────────────────┘   └─────────────────────────────┘
```

문서 전체에서 사용하는 예시 값 — 실제 환경에 맞게 치환하십시오.

| 항목 | 예시 값 |
|---|---|
| LDAP 호스트 | `ldap01.example.com` |
| 인스턴스명 | `cdp` (설정 경로 `/etc/dirsrv/slapd-cdp`) |
| 서픽스(Base DN) | `dc=example,dc=com` |
| 사용자 컨테이너 | `ou=People,dc=example,dc=com` |
| 그룹 컨테이너 | `ou=Groups,dc=example,dc=com` |
| 읽기 전용 바인드 | `uid=cdpbind,ou=Services,dc=example,dc=com` |
| 관리용 바인드 | `uid=cdpadmin,ou=Services,dc=example,dc=com` |
| 포트 | 389(STARTTLS) / **636(LDAPS, 권장)** |

**스키마 선택**: 사용자는 `inetOrgPerson + posixAccount + shadowAccount`, 그룹은 `posixGroup(memberUid)` 를 사용합니다.
CDP 는 HDFS/YARN 이 OS 레벨에서 사용자·그룹을 해석해야 하므로(`ShellBasedUnixGroupsMapping`) POSIX 속성이 필수이며,
RFC2307 스키마는 SSSD 와 Ranger Usersync 양쪽에서 그대로 사용할 수 있습니다.

### 리포지토리 구성

```
.
├── README.md
├── ldif/
│   ├── 01-base-structure.ldif    # ou=People / ou=Groups / ou=Services / 기본 그룹
│   ├── 02-service-accounts.ldif  # cdpbind(읽기 전용), cdpadmin(관리)
│   └── 03-aci.ldif               # 접근 제어(ACI)
└── scripts/
    ├── ldap.env.example          # 접속 정보 템플릿 → ldap.env 로 복사 후 사용
    ├── ldap-common.sh            # 공통 함수 (source 전용)
    ├── ldap-add-user.sh          # 사용자 추가
    ├── ldap-delete-user.sh       # 사용자 삭제 / 잠금 / 잠금 해제
    └── ldap-change-password.sh   # 패스워드 변경 / 계정 잠금 해제
```

---

## 2. 사전 준비

| 항목 | 요구 사항 |
|---|---|
| OS | RHEL/Rocky/AlmaLinux 8·9, Ubuntu 20.04·22.04 |
| 사양(소규모) | 2 vCPU / 4 GB RAM / 20 GB (`/var/lib/dirsrv`) |
| 호스트명 | FQDN 정방향·역방향 DNS 등록 필수 (인증서 CN/SAN 과 일치) |
| 시간 동기화 | chrony/ntp 로 CDP 클러스터와 동기화 |
| 방화벽 | 389/tcp, 636/tcp 개방 |

```bash
# 호스트명 · DNS 확인
hostnamectl set-hostname ldap01.example.com
getent hosts ldap01.example.com

# 시간 동기화
sudo systemctl enable --now chronyd

# 방화벽
sudo firewall-cmd --permanent --add-service=ldap --add-service=ldaps
sudo firewall-cmd --reload

# 파일 디스크립터 상향 (동시 접속이 많은 경우)
sudo mkdir -p /etc/systemd/system/dirsrv@.service.d
printf '[Service]\nLimitNOFILE=65536\n' | sudo tee /etc/systemd/system/dirsrv@.service.d/limits.conf
sudo systemctl daemon-reload
```

> SELinux 는 `Enforcing` 상태 그대로 두어도 됩니다. 389 DS 패키지가 정책을 함께 제공하며,
> 표준 포트(389/636) 외의 포트를 쓸 때만 `semanage port -a -t ldap_port_t -p tcp <포트>` 가 필요합니다.

---

## 3. 389 DS 설치

### RHEL / Rocky / AlmaLinux 9

```bash
sudo dnf install -y 389-ds-base openldap-clients
```

### RHEL / Rocky / AlmaLinux 8

```bash
sudo dnf module -y enable 389-directory-server:stable
sudo dnf install -y 389-ds-base openldap-clients
```

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y 389-ds-base ldap-utils
```

설치 확인:

```bash
dscreate --version     # 또는 rpm -q 389-ds-base
```

주요 명령어

| 명령 | 용도 |
|---|---|
| `dscreate` | 인스턴스 생성 |
| `dsctl <인스턴스>` | 기동/정지/백업 등 로컬 제어 |
| `dsconf <인스턴스\|URL>` | 설정 변경(백엔드, 플러그인, 정책, TLS) |
| `dsidm <인스턴스>` | 사용자/그룹 관리 (본 문서의 스크립트가 대체) |

---

## 4. 인스턴스 생성

### 4.1 설정 파일(.inf) 작성

```bash
sudo dscreate create-template /root/cdp-389ds.inf.tmpl   # 전체 옵션 확인용 템플릿
sudo vi /root/cdp-389ds.inf
```

`/root/cdp-389ds.inf`:

```ini
[general]
config_version = 2
full_machine_name = ldap01.example.com
strict_host_checking = True
selinux = True

[slapd]
instance_name = cdp
root_dn = cn=Directory Manager
root_password = ChangeMe_DirMgr#2024
port = 389
secure_port = 636
self_sign_cert = True

[backend-userroot]
suffix = dc=example,dc=com
create_suffix_entry = True
sample_entries = no
```

> * `root_password` 가 평문으로 남으므로 인스턴스 생성 후 `.inf` 파일은 반드시 삭제(`shred -u`)하십시오.
> * `.inf` 는 Python `configparser` 로 파싱되므로 **값에 `%` 를 쓰려면 `%%` 로 이스케이프**해야 합니다
>   (`Pass%word` → `InterpolationSyntaxError`). 혼선을 피하려면 단순한 패스워드로 생성한 뒤
>   `dsconf cdp directory_manager password_change` 로 변경하는 방법을 권장합니다.
> * 사내 CA 인증서를 사용할 예정이라면 `self_sign_cert = True` 로 생성한 뒤 [5장](#5-tlsldaps-구성)에서 교체합니다.

### 4.2 인스턴스 생성 및 기동

```bash
sudo dscreate from-file /root/cdp-389ds.inf
sudo shred -u /root/cdp-389ds.inf

sudo systemctl enable --now dirsrv@cdp
sudo dsctl cdp status
```

### 4.3 접속 확인

```bash
ldapsearch -H ldap://ldap01.example.com:389 -x -D "cn=Directory Manager" -W \
  -b "dc=example,dc=com" -s base "(objectClass=*)" dn
```

대화형 생성을 원하면 `sudo dscreate interactive` 를 사용해도 됩니다.

---

## 5. TLS(LDAPS) 구성

CDP 컴포넌트는 대부분 LDAP 바인드 시 패스워드를 평문으로 전송하므로 **LDAPS(636) 사용이 사실상 필수**입니다.

> **중요**: 389 DS 는 패스워드 변경(RFC 3062 Password Modify 확장 조작)을 **보안 연결에서만 허용**합니다.
> 평문 `ldap://` 로 `ldappasswd` 를 실행하면 `Confidentiality required (13) - Operation requires a secure connection`
> 오류가 발생합니다. 즉, 본 문서의 `ldap-add-user.sh` / `ldap-change-password.sh` 는
> **LDAPS(또는 STARTTLS/LDAPI) 구성이 완료된 뒤에야 정상 동작**합니다.

### 5.1 자체 서명 인증서 사용 (PoC/개발)

`dscreate` 시 `self_sign_cert = True` 였다면 이미 636 포트가 활성화되어 있습니다. CA 인증서를 추출해 클라이언트에 배포합니다.

```bash
# 자체 서명 CA 추출 (nickname: Self-Signed-CA)
sudo certutil -L -d /etc/dirsrv/slapd-cdp -n "Self-Signed-CA" -a | sudo tee /root/389ds-ca.pem

# 클러스터 호스트에 배포 후 신뢰 저장소에 등록
sudo cp /root/389ds-ca.pem /etc/pki/ca-trust/source/anchors/389ds-ca.pem
sudo update-ca-trust extract
```

### 5.2 사내 CA / 상용 인증서 사용 (운영 권장)

```bash
# 1) CA 인증서 등록
sudo dsconf cdp security ca-certificate add --file /root/corp-ca.pem --name "CorpCA"
sudo dsconf cdp security ca-certificate set-trust-flags "CorpCA" --flags "CT,,"

# 2) 서버 인증서 + 키 등록 (CN/SAN 은 ldap01.example.com 이어야 함)
sudo dsconf cdp security certificate add --file /root/ldap01.crt --name "Server-Cert" --primary-cert

# 3) TLS 활성화 및 최소 버전 지정
sudo dsconf cdp security enable
sudo dsconf cdp security set --tls-protocol-min TLS1.2 --secure-port 636
sudo systemctl restart dirsrv@cdp
```

### 5.3 검증

```bash
# TLS 핸드셰이크 확인
openssl s_client -connect ldap01.example.com:636 -showcerts </dev/null | head -20

# LDAPS 조회
LDAPTLS_CACERT=/etc/pki/ca-trust/source/anchors/389ds-ca.pem \
ldapsearch -H ldaps://ldap01.example.com:636 -x -D "cn=Directory Manager" -W \
  -b "dc=example,dc=com" -s base dn
```

### 5.4 평문 바인드 차단 (선택, TLS 검증 후 적용)

```bash
sudo dsconf cdp config replace nsslapd-require-secure-binds=on
```

---

## 6. 디렉터리 구조 · 서비스 계정 · ACI

`ldif/` 의 파일에서 `dc=example,dc=com` 을 실제 서픽스로 치환한 뒤 순서대로 적용합니다.

```bash
export LDAPTLS_CACERT=/etc/pki/ca-trust/source/anchors/389ds-ca.pem
LDAP_URL=ldaps://ldap01.example.com:636

# 1) 기본 구조 (ou=People / ou=Groups / ou=Services / 기본 그룹)
ldapmodify -H "$LDAP_URL" -x -D "cn=Directory Manager" -W -a -f ldif/01-base-structure.ldif

# 2) 서비스(바인드) 계정
ldapmodify -H "$LDAP_URL" -x -D "cn=Directory Manager" -W -a -f ldif/02-service-accounts.ldif

# 3) 바인드 계정 패스워드 설정
ldappasswd -H "$LDAP_URL" -x -D "cn=Directory Manager" -W -S "uid=cdpbind,ou=Services,dc=example,dc=com"
ldappasswd -H "$LDAP_URL" -x -D "cn=Directory Manager" -W -S "uid=cdpadmin,ou=Services,dc=example,dc=com"

# 4) 접근 제어(ACI)
ldapmodify -H "$LDAP_URL" -x -D "cn=Directory Manager" -W -f ldif/03-aci.ldif
```

적용되는 권한 요약

| 주체 | 대상 | 권한 |
|---|---|---|
| `uid=cdpbind` | `ou=People`, `ou=Groups` | read / search / compare (userPassword 제외) |
| `uid=cdpadmin` | `ou=People`, `ou=Groups` | all (사용자·그룹 생성/수정/삭제) |
| 사용자 본인(`self`) | 자신의 `userPassword` | write |

> 389 DS 는 기본적으로 **익명 읽기**를 허용하는 ACI 를 가지고 있습니다.
> 위 ACI 적용 및 동작 확인 후 `ldif/03-aci.ldif` 하단의 주석 블록을 참고해 제거하십시오.

---

## 7. 패스워드 정책과 인덱스

### 7.1 글로벌 패스워드 정책

```bash
sudo dsconf cdp config replace \
  passwordStorageScheme=PBKDF2-SHA512 \
  passwordMinLength=12 \
  passwordMinDigits=1 \
  passwordMinUppers=1 \
  passwordMinLowers=1 \
  passwordMinSpecials=1 \
  passwordHistory=on \
  passwordInHistory=5 \
  passwordExp=on \
  passwordMaxAge=7776000 \
  passwordWarning=604800 \
  passwordLockout=on \
  passwordMaxFailure=5 \
  passwordLockoutDuration=1800 \
  passwordResetFailureCount=600 \
  passwordCheckSyntax=on

# 관리자가 재설정한 패스워드는 첫 로그인 시 변경을 강제 (선택)
sudo dsconf cdp config replace passwordMustChange=on
```

> `passwordMustChange=on` 을 켜면 Hue/Hive 등 **패스워드 변경 UI 가 없는 컴포넌트에서 로그인 실패**가 발생할 수 있습니다.
> 신규 계정은 `ldap-change-password.sh --self` 로 사용자가 먼저 변경하도록 운영 절차를 마련하십시오.

### 7.2 인덱스

CDP 인증·Usersync 는 `uid`, `uidNumber`, `memberUid` 를 반복 조회하므로 인덱스를 확인/추가합니다.

```bash
sudo dsconf cdp backend index list userroot

sudo dsconf cdp backend index add --attr memberUid --index-type eq --index-type pres userroot
sudo dsconf cdp backend index add --attr uidNumber --index-type eq --index-type pres userroot
sudo dsconf cdp backend index add --attr gidNumber --index-type eq --index-type pres userroot

sudo dsconf cdp backend index reindex --attr memberUid userroot
```

### 7.3 (선택) memberOf 플러그인

`groupOfNames`/`member` 기반 그룹을 함께 쓰거나, 애플리케이션이 `memberOf` 속성을 요구하는 경우에만 활성화합니다.
본 가이드의 기본 구성(`posixGroup` + `memberUid`)에서는 필요하지 않습니다.

```bash
sudo dsconf cdp plugin memberof enable
sudo dsconf cdp plugin memberof set --groupattr member --memberofattr memberOf
sudo systemctl restart dirsrv@cdp
sudo dsconf cdp plugin memberof fixup -f "(objectClass=inetOrgPerson)" "dc=example,dc=com"
```

---

## 8. 사용자 관리 스크립트

`scripts/` 의 스크립트는 `ldapsearch` / `ldapmodify` / `ldappasswd`(openldap-clients) 만 있으면 어느 호스트에서든 실행할 수 있습니다.

### 8.1 설정

```bash
cd scripts
cp ldap.env.example ldap.env
chmod 600 ldap.env
vi ldap.env
```

`ldap.env` 주요 항목:

```bash
LDAP_URI="ldaps://ldap01.example.com:636"
LDAP_BASE_DN="dc=example,dc=com"
LDAP_BIND_DN="uid=cdpadmin,ou=Services,dc=example,dc=com"
LDAP_BIND_PW_FILE="/etc/dirsrv/.cdpadmin.pw"      # 개행 없이 저장, 0600
LDAP_TLS_CACERT="/etc/pki/ca-trust/source/anchors/389ds-ca.pem"
LDAP_USER_BASE="ou=People,dc=example,dc=com"
LDAP_GROUP_BASE="ou=Groups,dc=example,dc=com"
LDAP_DEFAULT_GROUP="cdpusers"
LDAP_UID_MIN="20000"
LDAP_GID_MIN="20000"
```

패스워드 파일 생성:

```bash
printf '%s' 'ChangeMe#2024' | sudo tee /etc/dirsrv/.cdpadmin.pw > /dev/null
sudo chmod 600 /etc/dirsrv/.cdpadmin.pw
```

* `LDAP_BIND_PW_FILE`, `LDAP_BIND_PW` 를 모두 비워두면 실행 시 터미널에서 입력받습니다.
* 다른 경로의 설정 파일을 쓰려면 `LDAP_ENV_FILE=/path/to/prod.env ./ldap-add-user.sh ...` 형태로 실행합니다.
* 모든 스크립트는 `--dry-run` 을 지원하며, 실제 변경 없이 적용될 LDIF 를 출력합니다.

### 8.2 사용자 추가 — `ldap-add-user.sh`

`inetOrgPerson + posixAccount + shadowAccount` 엔트리를 생성하고, `uidNumber` 를 자동 할당한 뒤 패스워드를 설정합니다.
1차 그룹과 추가 그룹은 없으면 자동 생성됩니다(`--no-create-group` 으로 비활성화).

```bash
# 대화형(패스워드는 화면에 표시되지 않음)
./ldap-add-user.sh -u hong -f 길동 -l 홍 -m hong@example.com

# 추가 그룹 지정 + 랜덤 패스워드 발급
./ldap-add-user.sh -u kimcs -f 철수 -l 김 -G cdpusers,analysts --random

# 서비스 계정 (uidNumber 고정, 로그인 셸 없음)
./ldap-add-user.sh -u svc_nifi -c "NiFi Service" -i 21000 -s /sbin/nologin --random

# 적용 전 LDIF 확인
./ldap-add-user.sh -u test01 --random --dry-run
```

| 옵션 | 설명 |
|---|---|
| `-u, --uid` | 계정명 (필수) |
| `-c/-f/-l/-m` | cn / givenName / sn / mail |
| `-i, --uid-number` | uidNumber 직접 지정 (기본: 자동 할당) |
| `-g, --group` | 1차 그룹 (기본 `LDAP_DEFAULT_GROUP`) |
| `-G, --groups` | 추가 그룹 CSV (`memberUid` 등록) |
| `-H/-s` | 홈 디렉터리 / 로그인 셸 |
| `-p / --password-file / --random` | 패스워드 지정 방식 |
| `--via-modify` | TLS 없는 연결에서 패스워드 설정 ([8.6](#86-보안-연결-없이-패스워드를-설정해야-할-때)) |
| `--dry-run` | LDIF 만 출력 |

### 8.3 사용자 삭제 — `ldap-delete-user.sh`

기본 동작은 **모든 그룹의 `memberUid` 정리 → 사용자 엔트리 삭제** 입니다.
데이터 소유권 문제 때문에 퇴사자 처리에는 삭제보다 **`--disable`(계정 잠금)** 을 권장합니다.

```bash
./ldap-delete-user.sh -u hong                # 확인 프롬프트 후 삭제
./ldap-delete-user.sh -u hong -y             # 확인 없이 삭제
./ldap-delete-user.sh -u hong --disable -y   # 잠금 (nsAccountLock: true)
./ldap-delete-user.sh -u hong --enable       # 잠금 해제
./ldap-delete-user.sh -u hong -y --purge-group  # 동명의 빈 그룹까지 정리
```

> **uidNumber 재사용 주의**: 스크립트는 "현재 등록된 최대 uidNumber + 1" 을 할당합니다.
> 따라서 가장 마지막 사용자를 삭제하면 **다음에 만드는 계정이 같은 uidNumber 를 받게 되어**
> HDFS 등에 남아 있는 이전 사용자의 파일에 접근할 수 있습니다.
> 퇴사자는 `--disable` 로 잠그거나, 삭제 시 `-i` 로 uidNumber 를 명시적으로 관리하십시오.

### 8.4 패스워드 변경 — `ldap-change-password.sh`

`ldappasswd`(RFC 3062 확장 조작)를 사용하므로 서버의 `passwordStorageScheme` 에 맞춰 해시가 저장되고,
패스워드 정책(히스토리·복잡도)도 정상적으로 적용됩니다.

```bash
./ldap-change-password.sh -u hong                # 관리자 재설정 (대화형)
./ldap-change-password.sh -u hong --random       # 임시 패스워드 발급 후 출력
./ldap-change-password.sh -u hong --self         # 사용자 본인이 현재 패스워드로 변경
./ldap-change-password.sh -u hong --unlock       # 로그인 실패로 잠긴 계정 해제
```

`--self` 모드는 `ldif/03-aci.ldif` 의 "self password change" ACI 가 적용되어 있어야 동작합니다.
LDAPS 를 쓸 수 없는 환경이라면 [8.6](#86-보안-연결-없이-패스워드를-설정해야-할-때) 의 `--via-modify` 등을 참고하십시오.

### 8.5 자주 쓰는 조회

```bash
source scripts/ldap.env
export LDAPTLS_CACERT="$LDAP_TLS_CACERT"

# 사용자 목록
ldapsearch -LLL -H "$LDAP_URI" -x -D "$LDAP_BIND_DN" -y "$LDAP_BIND_PW_FILE" \
  -b "$LDAP_USER_BASE" "(objectClass=posixAccount)" uid uidNumber gidNumber

# 특정 사용자의 그룹
ldapsearch -LLL -H "$LDAP_URI" -x -D "$LDAP_BIND_DN" -y "$LDAP_BIND_PW_FILE" \
  -b "$LDAP_GROUP_BASE" "(memberUid=hong)" cn gidNumber

# 인증 확인
ldapwhoami -H "$LDAP_URI" -x -D "uid=hong,$LDAP_USER_BASE" -W
```

### 8.6 보안 연결 없이 패스워드를 설정해야 할 때

389 DS 가 보안 연결을 요구하는 것은 **Password Modify 확장 조작(RFC 3062, `ldappasswd`)** 뿐입니다.
`userPassword` 속성을 직접 수정하는 일반 modify 조작에는 이 제한이 없습니다. 따라서 아래 네 가지 방법이 있습니다.

| 방법 | TLS 필요 | 패스워드 평문 노출 | 패스워드 정책 적용 | 용도 |
|---|---|---|---|---|
| ① LDAPI (유닉스 소켓) | 불필요 | 없음(로컬 소켓) | 적용 | **서버 로컬 작업 시 권장** |
| ② STARTTLS (389 포트) | 인증서 필요 | 없음 | 적용 | 636 포트를 못 여는 경우 |
| ③ `userPassword` 직접 modify | 불필요 | **있음** | 적용(일반 계정 바인드 시) | TLS 가 아예 없는 환경 |
| ④ 사전 해시(`pwdhash`) 주입 | 불필요 | 없음 | **미적용** | 자동화/일괄 등록 |

#### ① LDAPI — 서버에 접속해 로컬 소켓으로 처리 (권장)

로컬 유닉스 소켓 연결은 서버가 보안 연결로 취급하므로 TLS 없이도 `ldappasswd` 가 그대로 동작합니다.

```bash
SOCK="ldapi://%2Frun%2Fslapd-cdp.socket"        # /run/slapd-<인스턴스>.socket, '/' 는 %2F 로 인코딩

# root 자동 바인드(EXTERNAL) — 패스워드 입력조차 필요 없음
sudo ldappasswd -H "$SOCK" -Y EXTERNAL -s 'NewPassw0rd#2024' "uid=hong,ou=People,dc=example,dc=com"

# 또는 일반 simple 바인드
sudo ldappasswd -H "$SOCK" -x -D "uid=cdpadmin,ou=Services,dc=example,dc=com" -W \
  -s 'NewPassw0rd#2024' "uid=hong,ou=People,dc=example,dc=com"
```

스크립트에서 쓰려면 `ldap.env` 의 URI 만 바꾸면 됩니다(옵션 변경 불필요).

```bash
LDAP_URI="ldapi://%2Frun%2Fslapd-cdp.socket"
```

#### ② STARTTLS — 389 포트에서 TLS 협상

```bash
ldappasswd -H ldap://ldap01.example.com:389 -ZZ -x \
  -D "uid=cdpadmin,ou=Services,dc=example,dc=com" -W \
  -s 'NewPassw0rd#2024' "uid=hong,ou=People,dc=example,dc=com"
```

#### ③ `userPassword` 직접 modify — 스크립트의 `--via-modify`

TLS 가 전혀 구성되지 않은 환경에서 원격으로 처리해야 할 때 사용합니다.
서버가 `passwordStorageScheme`(PBKDF2-SHA512) 로 해싱해 저장하므로 저장 형태는 `ldappasswd` 와 동일합니다.

```bash
./ldap-change-password.sh -u hong --via-modify
./ldap-add-user.sh -u newuser --random --via-modify

# 스크립트 없이 직접 수행할 경우
printf 'dn: uid=hong,ou=People,dc=example,dc=com\nchangetype: modify\nreplace: userPassword\nuserPassword: NewPassw0rd#2024\n' \
  | ldapmodify -H ldap://ldap01.example.com:389 -x \
      -D "uid=cdpadmin,ou=Services,dc=example,dc=com" -W
```

> * **패스워드가 네트워크에 평문으로 흐릅니다.** 신뢰된 관리 네트워크에서만, 임시 수단으로 사용하십시오.
> * `cn=Directory Manager` 로 바인드하면 **패스워드 정책이 적용되지 않습니다**
>   (`passwordMinLength=12` 인 상태에서도 6자 패스워드가 그대로 등록됨). 정책을 적용하려면
>   `uid=cdpadmin` 같은 일반 관리 계정으로 바인드하십시오. 일반 계정이면
>   `invalid password syntax - password must be at least 12 characters long` 로 정상 거부됩니다.

#### ④ 사전 해시 주입 — 평문을 네트워크에 흘리지 않기

패스워드를 미리 해싱해서 전송하므로 TLS 없이도 평문이 노출되지 않습니다.

```bash
# 1) 서버에서 해시 값 주입을 허용 (기본값 off)
sudo dsconf cdp config replace nsslapd-allow-hashed-passwords=on

# 2) 해시 생성 (인스턴스 설정의 스키마/솔트 사용)
HASH=$(sudo pwdhash -D /etc/dirsrv/slapd-cdp -s PBKDF2-SHA512 'NewPassw0rd#2024')

# 3) 주입
printf 'dn: uid=hong,ou=People,dc=example,dc=com\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n' "$HASH" \
  | ldapmodify -H ldap://ldap01.example.com:389 -x \
      -D "uid=cdpadmin,ou=Services,dc=example,dc=com" -W
```

> * `nsslapd-allow-hashed-passwords` 가 **off 인 상태에서 해시를 넣으면 그 해시 문자열 자체를 평문 패스워드로 간주해
>   다시 해싱**합니다. 조작은 성공하지만 사용자는 로그인할 수 없게 되므로 반드시 먼저 켜야 합니다.
> * 사전 해시 값은 **패스워드 정책(길이·복잡도·히스토리)을 우회**합니다. 정책 검증은 스크립트나 발급 절차에서 담당해야 합니다.

---

## 9. 클러스터 호스트 SSSD 연동 (필수)

CDP 는 HDFS/YARN 이 OS 레벨에서 사용자·그룹을 해석합니다(`hadoop.security.group.mapping` 기본값
`ShellBasedUnixGroupsMapping`). **모든 클러스터 호스트에서 `id <사용자>` 가 동작하지 않으면**
Ranger 정책 평가, YARN 잡 제출, HDFS 권한 검사가 실패합니다.

### 9.1 설치 및 설정 (모든 CDP 호스트)

```bash
sudo dnf install -y sssd sssd-ldap oddjob-mkhomedir openldap-clients
sudo cp 389ds-ca.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust extract
```

`/etc/sssd/sssd.conf` (권한 `0600`, 소유자 `root`):

```ini
[sssd]
config_file_version = 2
services = nss, pam
domains = example.com

[nss]
filter_groups = root
filter_users = root
homedir_substring = /home

[pam]
offline_credentials_expiration = 2

[domain/example.com]
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap

ldap_uri = ldaps://ldap01.example.com:636
ldap_search_base = dc=example,dc=com
ldap_user_search_base = ou=People,dc=example,dc=com
ldap_group_search_base = ou=Groups,dc=example,dc=com
ldap_schema = rfc2307

ldap_default_bind_dn = uid=cdpbind,ou=Services,dc=example,dc=com
ldap_default_authtok = ChangeMe#2024
ldap_tls_cacert = /etc/pki/ca-trust/source/anchors/389ds-ca.pem
ldap_tls_reqcert = demand

cache_credentials = true
enumerate = false
ldap_id_use_start_tls = false
override_shell = /bin/bash
```

```bash
sudo chmod 600 /etc/sssd/sssd.conf
sudo authselect select sssd with-mkhomedir --force   # RHEL 8/9
sudo systemctl enable --now oddjobd sssd
sudo systemctl restart sssd
```

> `ldap_default_authtok` 평문 저장이 부담스럽다면 `sss_obfuscate` 로 난독화하거나
> (`ldap_default_authtok_type = obfuscated_password`), 익명 읽기 ACI 를 유지하고 바인드 계정을 생략할 수 있습니다.

### 9.2 검증

```bash
id hong
getent passwd hong
getent group cdpusers
sudo -u hong hdfs dfs -ls /user/hong
```

### 9.3 계정 변경 반영

```bash
sudo sss_cache -E              # 전체 캐시 무효화
sudo systemctl restart sssd    # 필요 시
```

> 클러스터 규모가 크면 Ansible/Salt 등으로 `sssd.conf` 를 일괄 배포하고,
> **신규 호스트 추가 시 SSSD 구성이 누락되지 않도록** 호스트 준비 체크리스트에 포함시키십시오.

---

## 10. Cloudera CDP 컴포넌트 연동

아래 설정은 모두 **Cloudera Manager UI** 에서 수행합니다. 각 항목 적용 후 해당 서비스를 재시작해야 합니다.

### 10.1 Cloudera Manager 외부 인증

`Administration → Settings → External Authentication`

| 설정 | 값 |
|---|---|
| Authentication Backend Order | `Cloudera Manager 먼저, 그다음 외부` (락아웃 방지) |
| External Authentication Type | `LDAP` |
| LDAP URL | `ldaps://ldap01.example.com:636` |
| LDAP Bind User Distinguished Name | `uid=cdpbind,ou=Services,dc=example,dc=com` |
| LDAP Bind Password | (cdpbind 패스워드) |
| LDAP User Search Base | `ou=People,dc=example,dc=com` |
| LDAP User Search Filter | `(&(objectClass=posixAccount)(uid={0}))` |
| LDAP Group Search Base | `ou=Groups,dc=example,dc=com` |
| LDAP Group Search Filter | `(&(objectClass=posixGroup)(memberUid={1}))` |

* `{0}` = 사용자 DN, `{1}` = 사용자명(uid) 로 치환됩니다.
* 검색 방식 대신 DN 패턴을 쓰려면 `LDAP Distinguished Name Pattern` 에 `uid={0},ou=People,dc=example,dc=com` 을 지정합니다.
* LDAPS 를 사용하려면 CM 서버 JDK 트러스트스토어에 CA 를 등록해야 합니다.

```bash
sudo keytool -importcert -noprompt -alias 389ds-ca \
  -file /etc/pki/ca-trust/source/anchors/389ds-ca.pem \
  -keystore /var/lib/cloudera-scm-server/certs/cm-auth-truststore.jks \
  -storepass <트러스트스토어_패스워드>
# Administration → Settings → Security → "Cloudera Manager TLS/SSL Certificate Trust Store File" 에 경로 지정
sudo systemctl restart cloudera-scm-server
```

권한 매핑: `Administration → Users & Roles → LDAP/PAM Groups` 에서 `cdpadmins` → **Full Administrator**,
`cdpusers` → **Read-Only** 등으로 매핑합니다.

> **락아웃 주의**: 외부 인증 설정 직후에도 로컬 `admin` 계정으로 로그인할 수 있도록
> Backend Order 를 `Cloudera Manager 먼저`로 두고, 그룹 매핑이 정상 동작하는 것을 확인한 뒤 정책을 강화하십시오.

### 10.2 Ranger Usersync

`Ranger → Configuration → Ranger Usersync`

| 속성 | 값 |
|---|---|
| `ranger.usersync.source.impl.class` | `org.apache.ranger.ldapusersync.process.LdapUserGroupBuilder` |
| `ranger.usersync.ldap.url` | `ldaps://ldap01.example.com:636` |
| `ranger.usersync.ldap.binddn` | `uid=cdpbind,ou=Services,dc=example,dc=com` |
| `ranger.usersync.ldap.ldapbindpassword` | (cdpbind 패스워드) |
| `ranger.usersync.ldap.searchBase` | `dc=example,dc=com` |
| `ranger.usersync.ldap.user.searchbase` | `ou=People,dc=example,dc=com` |
| `ranger.usersync.ldap.user.searchfilter` | `(objectClass=posixAccount)` |
| `ranger.usersync.ldap.user.objectclass` | `posixAccount` |
| `ranger.usersync.ldap.user.nameattribute` | `uid` |
| `ranger.usersync.ldap.user.groupnameattribute` | `memberof` (미사용 시 공란) |
| `ranger.usersync.group.searchenabled` | `true` |
| `ranger.usersync.group.searchbase` | `ou=Groups,dc=example,dc=com` |
| `ranger.usersync.group.searchfilter` | `(objectClass=posixGroup)` |
| `ranger.usersync.group.objectclass` | `posixGroup` |
| `ranger.usersync.group.nameattribute` | `cn` |
| `ranger.usersync.group.memberattributename` | `memberUid` |
| `ranger.usersync.group.based.role.assignment.rules` | (선택) `&ROLE_SYS_ADMIN:g:cdpadmins` |
| `ranger.usersync.sleeptimeinmillisbetweensynccycle` | `3600000` (1시간) |
| `ranger.usersync.ldap.deltasync` | `true` |

동기화 결과는 Ranger Admin UI `Settings → Users/Groups` 에서 확인하고, 로그는
`/var/log/ranger/usersync/usersync.log` 를 참고합니다.

### 10.3 Ranger Admin LDAP 인증

`Ranger → Configuration → Ranger Admin`

| 속성 | 값 |
|---|---|
| `ranger.authentication.method` | `LDAP` |
| `ranger.ldap.url` | `ldaps://ldap01.example.com:636` |
| `ranger.ldap.user.dnpattern` | `uid={0},ou=People,dc=example,dc=com` |
| `ranger.ldap.base.dn` | `dc=example,dc=com` |
| `ranger.ldap.bind.dn` | `uid=cdpbind,ou=Services,dc=example,dc=com` |
| `ranger.ldap.bind.password` | (cdpbind 패스워드) |
| `ranger.ldap.group.searchbase` | `ou=Groups,dc=example,dc=com` |
| `ranger.ldap.group.searchfilter` | `(memberUid={1})` |
| `ranger.ldap.group.roleattribute` | `cn` |

### 10.4 Hue

`Hue → Configuration → Hue Service Advanced Configuration Snippet (Safety Valve) for hue_safety_valve.ini`

```ini
[desktop]
[[ldap]]
ldap_url=ldaps://ldap01.example.com:636
ldap_cert=/etc/pki/ca-trust/source/anchors/389ds-ca.pem
use_start_tls=false
search_bind_authentication=true
create_users_on_login=true
sync_groups_on_login=true
base_dn="dc=example,dc=com"
bind_dn="uid=cdpbind,ou=Services,dc=example,dc=com"
bind_password=ChangeMe#2024

[[[users]]]
user_filter="objectClass=posixAccount"
user_name_attr=uid

[[[groups]]]
group_filter="objectClass=posixGroup"
group_name_attr=cn
group_member_attr=memberUid
```

> `bind_password` 평문 대신 `bind_password_script=/opt/cloudera/security/ldap/hue_bind_pw.sh` 사용을 권장합니다.

### 10.5 Hive (HiveServer2)

`Hive on Tez / Hive → Configuration`

| 속성 | 값 |
|---|---|
| `hive.server2.authentication` | `LDAP` |
| `hive.server2.authentication.ldap.url` | `ldaps://ldap01.example.com:636` |
| `hive.server2.authentication.ldap.baseDN` | `ou=People,dc=example,dc=com` |
| `hive.server2.authentication.ldap.userDNPattern` | `uid=%s,ou=People,dc=example,dc=com` |
| `hive.server2.authentication.ldap.groupDNPattern` | `cn=%s,ou=Groups,dc=example,dc=com` |
| `hive.server2.authentication.ldap.groupFilter` | (선택) `cdpusers,analysts` |
| `hive.server2.authentication.ldap.guidKey` | `uid` |
| `hive.server2.authentication.ldap.groupMembershipKey` | `memberUid` |

접속 확인:

```bash
beeline -u "jdbc:hive2://hs2.example.com:10000/default;ssl=true" -n hong -p '<패스워드>'
```

> Kerberos 를 함께 사용하는 클러스터에서는 `hive.server2.authentication=KERBEROS` 가 우선이며,
> LDAP 인증은 별도의 HS2 인스턴스(예: JDBC/ODBC 전용) 또는 Knox 경유로 구성하는 것이 일반적입니다.

### 10.6 Impala

`Impala → Configuration`

| 설정 | 값 |
|---|---|
| Enable LDAP Authentication (`enable_ldap_auth`) | 체크 |
| LDAP URL (`ldap_uri`) | `ldaps://ldap01.example.com:636` |
| LDAP Bind Pattern (`ldap_bind_pattern`) | `uid=#UID,ou=People,dc=example,dc=com` |
| LDAP CA Certificate (`ldap_ca_certificate`) | `/etc/pki/ca-trust/source/anchors/389ds-ca.pem` |

`#UID` 는 로그인 사용자명으로 치환됩니다.

### 10.7 Knox

`Knox → Configuration → Knox Simplified Topology Management` 또는 토폴로지 Advanced Snippet:

```xml
<provider>
  <role>authentication</role>
  <name>ShiroProvider</name>
  <enabled>true</enabled>
  <param><name>sessionTimeout</name><value>30</value></param>
  <param><name>main.ldapContextFactory</name>
         <value>org.apache.knox.gateway.shirorealm.KnoxLdapContextFactory</value></param>
  <param><name>main.ldapRealm</name>
         <value>org.apache.knox.gateway.shirorealm.KnoxLdapRealm</value></param>
  <param><name>main.ldapRealm.contextFactory</name><value>$ldapContextFactory</value></param>
  <param><name>main.ldapRealm.contextFactory.url</name>
         <value>ldaps://ldap01.example.com:636</value></param>
  <param><name>main.ldapRealm.contextFactory.authenticationMechanism</name><value>simple</value></param>
  <param><name>main.ldapRealm.userDnTemplate</name>
         <value>uid={0},ou=People,dc=example,dc=com</value></param>
  <param><name>main.ldapRealm.authorizationEnabled</name><value>true</value></param>
  <param><name>main.ldapRealm.searchBase</name><value>ou=Groups,dc=example,dc=com</value></param>
  <param><name>main.ldapRealm.groupObjectClass</name><value>posixGroup</value></param>
  <param><name>main.ldapRealm.memberAttribute</name><value>memberUid</value></param>
  <param><name>main.ldapRealm.memberAttributeValueTemplate</name><value>{0}</value></param>
  <param><name>urls./**</name><value>authcBasic</value></param>
</provider>
```

Knox 게이트웨이의 JVM 트러스트스토어(`/var/lib/knox/gateway/data/security/keystores/gateway-client-trust.jks`)에
389 DS CA 를 등록해야 LDAPS 가 동작합니다.

---

## 11. 검증 절차

### 11.1 전체 흐름 점검

```bash
# 1) 계정 생성
cd scripts && ./ldap-add-user.sh -u testuser -f 테스트 -l 사용자 -G cdpusers --random

# 2) LDAP 인증
ldapwhoami -H ldaps://ldap01.example.com:636 -x \
  -D "uid=testuser,ou=People,dc=example,dc=com" -W
# → dn: uid=testuser,ou=people,dc=example,dc=com

# 3) OS 계정 해석 (모든 클러스터 호스트)
id testuser && getent group cdpusers

# 4) Cloudera Manager 로그인 (LDAP 자격증명)
# 5) Hue / Beeline / Impala-shell 로그인
impala-shell -i coordinator.example.com:21050 --ssl -l -u testuser
beeline -u "jdbc:hive2://hs2.example.com:10000/default;ssl=true" -n testuser -p '<패스워드>'

# 6) 패스워드 변경 후 재인증
./ldap-change-password.sh -u testuser --self

# 7) 정리
./ldap-delete-user.sh -u testuser -y
```

### 11.2 패스워드 검증

특정 계정(`akuser`)의 패스워드가 정상 동작하는지 확인하는 순서입니다.
`scripts/ldap.env` 를 읽어 변수로 사용합니다.

```bash
source scripts/ldap.env
export LDAPTLS_CACERT="$LDAP_TLS_CACERT"
USER=akuser
```

#### ① 바인드 확인 — 가장 확실한 방법

```bash
ldapwhoami -H "$LDAP_URI" -x -D "uid=$USER,$LDAP_USER_BASE" -W; echo "rc=$?"
# 성공 → dn: uid=akuser,ou=people,dc=example,dc=com  /  rc=0

# 패스워드 만료·유예 횟수까지 확인하려면 password policy 컨트롤 사용
ldapwhoami -H "$LDAP_URI" -x -D "uid=$USER,$LDAP_USER_BASE" -W -e ppolicy
```

| 결과 | 의미 | 조치 |
|---|---|---|
| `dn: uid=...` (rc=0) | 정상 | — |
| `Invalid credentials (49)` | 패스워드 불일치 또는 미설정 | ④ 로 저장 여부 확인 후 재설정 |
| `Invalid credentials (49)` + `Exceed password retry limit` | 로그인 실패 누적 잠금 | `./ldap-change-password.sh -u $USER --unlock` |
| `Server is unwilling to perform (53)` + `Account inactivated` | `nsAccountLock` 잠금 | `./ldap-delete-user.sh -u $USER --enable` |
| `Confidentiality required (13)` | 평문 연결에서 패스워드 조작 시도 | [8.6](#86-보안-연결-없이-패스워드를-설정해야-할-때) 참고 |

> 바인드는 되는데 `ldapsearch` 결과가 비어 있는 것은 정상일 수 있습니다.
> 일반 사용자에게는 읽기 ACI 가 없기 때문이며, **인증 확인은 `ldapwhoami` 로 판단**하십시오.

#### ② 계정 상태 한눈에 보기 (LDAP 서버에서)

```bash
sudo dsidm cdp -b "dc=example,dc=com" account entry-status "uid=$USER,ou=People,dc=example,dc=com"
```

```
Entry State: activated                               ← 정상
Entry State: directly locked through nsAccountLock    ← 잠김
```

#### ③ 잠금 · 만료 속성 확인 (관리자 바인드)

```bash
ldapsearch -LLL -H "$LDAP_URI" -x -D "$LDAP_BIND_DN" -y "$LDAP_BIND_PW_FILE" \
  -b "uid=$USER,$LDAP_USER_BASE" -s base \
  nsAccountLock passwordRetryCount accountUnlockTime passwordExpirationTime pwdReset
```

`dn:` 줄만 나오고 값이 하나도 없으면 정상입니다. 값이 보이면 잠금 또는 만료 상태입니다.

#### ④ 패스워드가 실제로 저장되었는지 확인

```bash
ldapsearch -LLL -H "$LDAP_URI" -x -D "$LDAP_BIND_DN" -y "$LDAP_BIND_PW_FILE" \
  -b "uid=$USER,$LDAP_USER_BASE" -s base userPassword \
  | sed -n 's/^userPassword:: //p' | base64 -d | head -c 16; echo
```

* `{PBKDF2-SHA512}` 로 시작 → 정상 저장
* 아무것도 출력되지 않음 → 패스워드 미설정 (계정만 생성된 상태)
* 해시 문자열이 다시 해싱된 형태 → [8.6 ④](#86-보안-연결-없이-패스워드를-설정해야-할-때) 의 `nsslapd-allow-hashed-passwords` 함정

#### ⑤ 서버 로그로 실패 원인 확인

```bash
sudo grep -B1 -A2 "$USER" /var/log/dirsrv/slapd-cdp/access | tail -20   # BIND 후 err= 값
sudo tail -50 /var/log/dirsrv/slapd-cdp/errors
```

#### ⑥ 클러스터 호스트(SSSD) 및 CDP 컴포넌트

```bash
id $USER && getent passwd $USER
sudo sssctl user-checks $USER -s sshd -a auth          # PAM 인증까지 검사
beeline -u "jdbc:hive2://hs2.example.com:10000/default;ssl=true" -n $USER -p '<패스워드>'
impala-shell -i coordinator.example.com:21050 --ssl -l -u $USER
```

#### 패스워드 설정이 거부되는 경우

```
Constraint violation (19)
additional info: invalid password syntax - password based off of user entry
```

389 DS 의 trivial-words 검사는 **패스워드에 계정명(`uid`)·`cn`·`sn`·`mail` 등 엔트리 값이 포함되면 거부**합니다
(`passwordMinTokenLength` 이상 길이의 토큰이 일치할 때). 예를 들어 `akuser` 계정에 `AkUser#Passw0rd` 는 사용할 수 없으며,
계정 정보와 무관한 문자열을 사용해야 합니다. 그 밖의 `Constraint violation (19)` 은 길이·복잡도·히스토리 정책 위반입니다.

```bash
sudo dsconf cdp config get passwordMinLength passwordMinDigits passwordMinSpecials \
  passwordInHistory passwordMinTokenLength
```

체크리스트

- [ ] `ldapwhoami` 로 LDAPS 바인드 성공
- [ ] `dsidm account entry-status` 결과가 `activated`, 잠금·만료 속성 없음
- [ ] 모든 클러스터 호스트에서 `id <사용자>` 성공
- [ ] Cloudera Manager LDAP 로그인 및 그룹 → 역할 매핑 확인
- [ ] Ranger Usersync 로 사용자/그룹 동기화 확인
- [ ] Hue / Hive / Impala / Knox 로그인 확인
- [ ] 계정 삭제 후 `sss_cache -E` 및 Ranger 반영 확인

---

## 12. 운영 · 백업 · 트러블슈팅

### 12.1 백업 / 복구

```bash
# 온라인 백업 (DB)
sudo dsconf cdp backup create           # → /var/lib/dirsrv/slapd-cdp/bak/

# LDIF 내보내기 (논리 백업, 권장)
sudo dsconf cdp backend export userroot -l /var/lib/dirsrv/slapd-cdp/ldif/userroot-$(date +%F).ldif

# 복구 (서비스 중지 필요)
sudo dsctl cdp stop
sudo dsctl cdp ldif2db userroot /var/lib/dirsrv/slapd-cdp/ldif/userroot-2024-01-01.ldif
sudo dsctl cdp start

# 설정 백업
sudo tar czf /backup/dirsrv-config-$(date +%F).tgz /etc/dirsrv/slapd-cdp
```

일 1회 LDIF 내보내기 + 설정 디렉터리 백업을 cron 에 등록하는 것을 권장합니다.

### 12.2 로그

| 로그 | 경로 |
|---|---|
| 접근 로그 | `/var/log/dirsrv/slapd-cdp/access` |
| 오류 로그 | `/var/log/dirsrv/slapd-cdp/errors` |
| 감사 로그 | `/var/log/dirsrv/slapd-cdp/audit` (`nsslapd-auditlog-logging-enabled=on`) |

```bash
sudo dsconf cdp config replace nsslapd-auditlog-logging-enabled=on
sudo logconv.pl /var/log/dirsrv/slapd-cdp/access   # 접근 로그 통계
```

### 12.3 자주 발생하는 문제

| 증상 | 원인 / 조치 |
|---|---|
| `ldap_bind: Invalid credentials (49)` | 바인드 DN/패스워드 오류. `errors` 로그에서 실제 DN 확인. 계정 잠금이면 `ldap-change-password.sh --unlock` |
| `ldap_start_tls: Connect error (-11)` | CA 미신뢰 또는 인증서 CN/SAN 불일치. `LDAPTLS_CACERT` 확인, `openssl s_client` 로 검증 |
| CM 로그인은 되는데 권한 없음 | 그룹 검색 필터 오류. `(&(objectClass=posixGroup)(memberUid={1}))` 및 LDAP/PAM 그룹 매핑 확인 |
| `id <사용자>` 실패 | SSSD 미구성/캐시. `sss_cache -E`, `/var/log/sssd/` 확인 |
| YARN 잡이 `user not found` 로 실패 | 일부 호스트만 SSSD 구성됨. **모든** NodeManager 호스트 확인 |
| Ranger 정책이 그룹에 적용되지 않음 | Usersync 미완료 또는 `memberattributename` 오설정. `usersync.log` 확인 |
| `Confidentiality required (13)` (패스워드 변경 시) | 평문 `ldap://` 연결. 389 DS 는 패스워드 변경에 보안 연결을 요구하므로 `ldaps://` 로 접속 |
| `Constraint violation (19)` (패스워드 변경 시) | 패스워드 정책(길이/복잡도/히스토리) 위반. `dsconf cdp config get passwordMinLength ...` 로 정책 확인 |
| `Insufficient access (50)` | ACI 부족. `cdpadmin` 권한(`ldif/03-aci.ldif`) 확인 |
| 서버 기동 실패 + `No valid configurations can be accessed` | `dse.ldif` 손상/0바이트. [12.4](#124-인스턴스가-기동되지-않을-때--no-valid-configurations-can-be-accessed) 참조 |

### 12.4 인스턴스가 기동되지 않을 때 — `No valid configurations can be accessed`

```
- INFO  - dse_check_file - The config /etc/dirsrv/slapd-cdp/dse.ldif has zero length. Attempting restore ...
- ERR   - dse_check_file - The backup file /etc/dirsrv/slapd-cdp/dse.ldif.bak has zero length, refusing to restore it.
- ERR   - slapd_bootstrap_config - No valid configurations can be accessed! You must restore /etc/dirsrv/slapd-cdp/dse.ldif from backup!
- EMERG - main - The configuration files in directory /etc/dirsrv/slapd-cdp could not be read or were not found.
```

설정 파일 `dse.ldif` 가 **없거나 크기가 0** 이고, 폴백 대상인 `dse.ldif.bak` 도 사용할 수 없다는 뜻입니다.
서버는 0바이트 `dse.ldif` 를 자동으로 삭제하므로, 오류 발생 후에는 파일 자체가 보이지 않을 수 있습니다.

**1) 원인 확인**

```bash
INST=cdp        # 인스턴스명
ls -l /etc/dirsrv/slapd-$INST/dse.ldif*      # dse.ldif / .bak / .startOK 크기 확인
df -h /etc /var/lib/dirsrv                   # 디스크 풀 → 쓰기 중 0바이트로 잘리는 대표 원인
ls -ld /etc/dirsrv/slapd-$INST               # 소유자 dirsrv:dirsrv, 권한 확인
tail -50 /var/log/dirsrv/slapd-$INST/errors
```

| 원인 | 확인 방법 |
|---|---|
| 인스턴스명 오타 / 잘못된 경로 | `ls /etc/dirsrv/` 로 실제 `slapd-*` 디렉터리명 확인 |
| `dscreate` 가 중간에 실패 | 설정 디렉터리는 있는데 `dse.ldif` 가 없음 → 인스턴스 재생성 |
| 디스크 풀 / 비정상 종료 | `df -h`, `dmesg` 확인 후 공간 확보 |
| 권한·소유자 변경 | `chown -R dirsrv:dirsrv /etc/dirsrv/slapd-$INST` |
| SELinux 라벨 손상 | `restorecon -Rv /etc/dirsrv /var/lib/dirsrv` |

**2) 복구 — 최근 정상 기동 시점의 설정으로 되돌리기**

```bash
sudo systemctl stop dirsrv@$INST 2>/dev/null
cd /etc/dirsrv/slapd-$INST
sudo cp -a dse.ldif.startOK dse.ldif      # .bak 이 정상이면 dse.ldif.bak 사용
sudo chown dirsrv:dirsrv dse.ldif && sudo chmod 600 dse.ldif
sudo systemctl start dirsrv@$INST
```

| 파일 | 내용 |
|---|---|
| `dse.ldif` | 현재 설정 (서버가 주기적으로 기록) |
| `dse.ldif.bak` | 직전 설정 백업 |
| `dse.ldif.startOK` | **마지막으로 정상 기동했을 때의 설정** — 가장 안전한 복구본 |

**3) 복구 후 반드시 확인 — 기동 이후 변경한 설정은 되돌아갑니다**

`dse.ldif.startOK` 는 "마지막 기동 시점"의 스냅샷이므로, 그 뒤 `dsconf` 등으로 변경한
**백엔드(suffix) 정의, 패스워드 정책, 인덱스, 플러그인 설정이 사라집니다.**
백엔드 정의가 없어지면 검색이 `No such object (32)` 로 실패하지만,
**데이터베이스 파일은 그대로 남아 있으므로** 백엔드만 다시 정의하면 데이터가 복구됩니다.

```bash
# 백엔드가 사라졌는지 확인
sudo dsconf $INST backend suffix list

# 기존 DB 디렉터리(/var/lib/dirsrv/slapd-$INST/db/userroot)를 그대로 사용해 재정의
#   → --create-suffix 는 붙이지 말 것 (기존 엔트리를 그대로 인식)
sudo dsconf $INST backend create --suffix "dc=example,dc=com" --be-name userroot

# 엔트리 복구 확인
ldapsearch -LLL -H ldaps://ldap01.example.com:636 -x -D "cn=Directory Manager" -W \
  -b "dc=example,dc=com" "(objectClass=posixAccount)" dn

# 이후 7장의 패스워드 정책 / 인덱스 설정을 다시 적용
```

`dse.ldif*` 가 모두 손상된 경우에는 [12.1 백업/복구](#121-백업--복구) 의 설정 백업(`/etc/dirsrv/slapd-$INST`)을 복원하거나,
인스턴스를 재생성한 뒤 LDIF 백업을 `ldif2db` 로 적재하십시오. 이 사고를 막으려면 설정 디렉터리 백업을 **일 단위로 반드시** 수행해야 합니다.

### 12.5 기타 디버깅

```bash
# ACI 디버깅 (로그 레벨 128: ACL 처리)
sudo dsconf cdp config replace nsslapd-errorlog-level=128
sudo tail -f /var/log/dirsrv/slapd-cdp/errors
sudo dsconf cdp config replace nsslapd-errorlog-level=0     # 확인 후 원복
```

### 12.6 이중화 (선택)

운영 환경에서는 LDAP 단일 장애점을 피하기 위해 2대 이상으로 다중 마스터 복제를 구성하고,
CDP 쪽에는 `ldaps://ldap01:636 ldaps://ldap02:636` 처럼 두 URL 을 지정하거나 로드밸런서 VIP 를 사용합니다.

```bash
# supplier(양쪽 노드에서 실행, replica-id 는 서로 다르게)
sudo dsconf cdp replication enable --suffix "dc=example,dc=com" \
  --role supplier --replica-id 1 --bind-dn "cn=replication manager,cn=config" --bind-passwd '...'
sudo dsconf cdp repl-agmt create --suffix "dc=example,dc=com" \
  --host ldap02.example.com --port 636 --conn-protocol LDAPS \
  --bind-dn "cn=replication manager,cn=config" --bind-passwd '...' --bind-method SIMPLE ldap01-to-ldap02
sudo dsconf cdp repl-agmt init --suffix "dc=example,dc=com" ldap01-to-ldap02
```

---

## 13. 보안 체크리스트

- [ ] LDAPS(636) 또는 STARTTLS 사용, TLS 1.2 이상 강제
- [ ] `nsslapd-require-secure-binds=on` 으로 평문 바인드 차단
- [ ] 익명 읽기 ACI 제거 (`ldif/03-aci.ldif` 참조)
- [ ] `cn=Directory Manager` 는 초기 구축·복구 용도로만 사용, 일상 작업은 `cdpadmin`
- [ ] 컴포넌트별 바인드 계정은 **읽기 전용**(`cdpbind`)
- [ ] `passwordStorageScheme=PBKDF2-SHA512`, 복잡도·히스토리·잠금 정책 적용
- [ ] `scripts/ldap.env`, 패스워드 파일은 `0600`, git 커밋 금지(`.gitignore` 적용됨)
- [ ] 스크립트의 `-p/--password` 옵션은 `ps` 노출 위험이 있으므로 운영에서는 `--password-file`/대화형 사용
- [ ] 감사 로그 활성화 및 정기 백업(LDIF + 설정 디렉터리)
- [ ] 퇴사자 처리는 삭제 대신 `--disable`(uidNumber 재사용에 따른 데이터 접근 방지)

---

## 참고 자료

- [389 Directory Server Documentation](https://www.port389.org/docs/389ds/documentation.html)
- [Red Hat Directory Server Administration Guide](https://access.redhat.com/documentation/en-us/red_hat_directory_server/)
- [Cloudera – Configuring External Authentication and Authorization for Cloudera Manager](https://docs.cloudera.com/cdp-private-cloud-base/latest/security-authentication/topics/cm-security-external-auth.html)
- [Cloudera – Ranger Usersync](https://docs.cloudera.com/cdp-private-cloud-base/latest/security-ranger-authentication-unix-ldap-ad/topics/security-ranger-usersync.html)
- [SSSD – sssd-ldap(5)](https://www.mankier.com/5/sssd-ldap)
