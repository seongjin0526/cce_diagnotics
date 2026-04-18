# CCE 취약점 진단 스크립트

주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026)와 클라우드 취약점 점검 가이드(2024)를 기반으로 한 자동화 진단 스크립트 모음입니다.
저장소는 `PDF -> JSON -> Excel -> 플랫폼별 진단 스크립트` 흐름으로 구성되어 있으며, Codex 기준의 반복 검증 하네스를 포함합니다.

21개 애플리케이션에 대해 **총 475개 CCE 항목**을 점검하며, 결과를 JSON 파일로 출력합니다.

## 진단 대상 및 항목 수

| 유형 | 대상 | 항목 수 | 스크립트 |
|---|---|---|---|
| OS | Linux | 71 | `linux_cce_check.sh` |
| OS | Windows | 68 | `scripts/windows_cce_check.ps1` |
| 가상화 | KVM | 16 | `scripts/kvm_cce_check.sh` |
| 가상화 | Xenserver | 42 | `scripts/xenserver_cce_check.sh` |
| 가상화 | ESXi | 39 | `scripts/esxi_cce_check.sh` |
| DB | MySQL | 18 | `scripts/mysql_cce_check.sh` |
| DB | MSSQL | 18 | `scripts/mssql_cce_check.sh` |
| DB | PostgreSQL | 22 | `scripts/postgresql_cce_check.sh` |
| DB | Redis | 8 | `scripts/redis_cce_check.sh` |
| DB | Elasticsearch | 10 | `scripts/elasticsearch_cce_check.sh` |
| DB | MongoDB | 9 | `scripts/mongodb_cce_check.sh` |
| 웹서버 | Apache | 21 | `scripts/apache_cce_check.sh` |
| 웹서버 | Nginx | 21 | `scripts/nginx_cce_check.sh` |
| 웹서버 | Tomcat | 27 | `scripts/tomcat_cce_check.sh` |
| 컨테이너 | Docker | 32 | `scripts/docker_cce_check.sh` |
| 컨테이너 | K8s Master | 17 | `scripts/k8s_master_cce_check.sh` |
| 컨테이너 | K8s Worker | 7 | `scripts/k8s_worker_cce_check.sh` |
| 애플리케이션 | PHP | 6 | `scripts/php_cce_check.sh` |
| 애플리케이션 | Node.js | 7 | `scripts/nodejs_cce_check.sh` |
| 애플리케이션 | Hadoop | 9 | `scripts/hadoop_cce_check.sh` |
| 애플리케이션 | Ceph | 7 | `scripts/ceph_cce_check.sh` |

---

## 사전 요구사항

- **Linux/Unix 스크립트**: root 권한 (sudo) 필요
- **Windows 스크립트**: 관리자 권한으로 PowerShell 실행 필요
- **DB 스크립트**: 해당 DB 클라이언트가 설치되어 있어야 함 (mysql, psql, redis-cli 등)
- **ESXi 스크립트**: ESXi 쉘에서 직접 실행 (BusyBox ash 호환)

---

## 실행 방법

### 공통 사항

- 모든 스크립트는 결과를 **JSON 파일**로 출력합니다.
- 출력 파일명을 지정하지 않으면 `cce_check_result_<플랫폼>_<호스트명>_<날짜시간>.json` 형태로 자동 생성됩니다.
- 판정 결과는 `양호`, `취약`, `N/A`, `수동점검` 4가지입니다.

---

### 1. Linux

```bash
sudo bash linux_cce_check.sh [출력파일.json]
```

**예시:**
```bash
# 기본 실행 (파일명 자동 생성)
sudo bash linux_cce_check.sh

# 파일명 지정
sudo bash linux_cce_check.sh result_linux.json
```

---

### 2. Windows

```powershell
.\scripts\windows_cce_check.ps1 [-OutputFile <경로>]
```

**예시:**
```powershell
# 관리자 권한 PowerShell에서 실행
.\scripts\windows_cce_check.ps1

# 파일명 지정
.\scripts\windows_cce_check.ps1 -OutputFile C:\result_windows.json
```

> Windows 스크립트는 `#Requires -RunAsAdministrator`가 포함되어 있어 관리자 권한이 아니면 실행이 거부됩니다.

---

### 3. 가상화 (KVM, Xenserver, ESXi)

```bash
# KVM 호스트에서 실행
sudo bash scripts/kvm_cce_check.sh [출력파일.json]

# Xenserver 호스트에서 실행
sudo bash scripts/xenserver_cce_check.sh [출력파일.json]

# ESXi 호스트에서 실행 (ESXi 쉘)
sh scripts/esxi_cce_check.sh [출력파일.json]
```

**예시:**
```bash
sudo bash scripts/kvm_cce_check.sh result_kvm.json
sudo bash scripts/xenserver_cce_check.sh result_xen.json
sh scripts/esxi_cce_check.sh result_esxi.json
```

> ESXi는 BusyBox 기반이므로 `sh`로 실행합니다. bash 배열 대신 임시파일을 사용하도록 구현되어 있습니다.

---

### 4. 데이터베이스 (MySQL, MSSQL, PostgreSQL, Redis, MongoDB)

DB 스크립트는 접속 정보를 옵션으로 받습니다.

| 옵션 | 설명 | 기본값 |
|---|---|---|
| `-h` | 호스트 주소 | `localhost` |
| `-P` | 포트 번호 | DB별 기본 포트 |
| `-u` | 사용자명 | DB별 기본 계정 |
| `-p` | 비밀번호 | (없음) |

**기본 포트 및 계정:**

| DB | 기본 포트 | 기본 사용자 |
|---|---|---|
| MySQL | 3306 | root |
| MSSQL | 1433 | sa |
| PostgreSQL | 5432 | postgres |
| Redis | 6379 | (없음) |
| MongoDB | 27017 | (없음) |

#### MySQL

```bash
sudo bash scripts/mysql_cce_check.sh [-h 호스트] [-P 포트] [-u 사용자] [-p 비밀번호] [출력파일.json]
```

**예시:**
```bash
# 로컬 MySQL (root, 비밀번호 없음)
sudo bash scripts/mysql_cce_check.sh

# 원격 MySQL 접속
sudo bash scripts/mysql_cce_check.sh -h 192.168.1.100 -P 3306 -u admin -p MyPassword result_mysql.json
```

> `mysql` 클라이언트가 설치되어 있어야 합니다.

#### MSSQL

```bash
sudo bash scripts/mssql_cce_check.sh [-h 호스트] [-P 포트] [-u 사용자] [-p 비밀번호] [출력파일.json]
```

**예시:**
```bash
sudo bash scripts/mssql_cce_check.sh -h 10.0.0.5 -P 1433 -u sa -p 'P@ssw0rd' result_mssql.json
```

> `sqlcmd` 또는 `mssql-cli`가 설치되어 있어야 합니다.

#### PostgreSQL

```bash
sudo bash scripts/postgresql_cce_check.sh [-h 호스트] [-P 포트] [-u 사용자] [-p 비밀번호] [출력파일.json]
```

**예시:**
```bash
# 로컬 PostgreSQL
sudo bash scripts/postgresql_cce_check.sh

# 원격 접속
sudo bash scripts/postgresql_cce_check.sh -h 192.168.1.50 -P 5432 -u postgres -p secret result_pg.json
```

> `psql` 클라이언트가 설치되어 있어야 합니다.

#### Redis

```bash
sudo bash scripts/redis_cce_check.sh [-h 호스트] [-P 포트] [-p 비밀번호] [출력파일.json]
```

**예시:**
```bash
# 로컬 Redis (인증 없음)
sudo bash scripts/redis_cce_check.sh

# 비밀번호가 설정된 Redis
sudo bash scripts/redis_cce_check.sh -h 10.0.0.10 -P 6379 -p redisPassword result_redis.json
```

> `redis-cli`가 설치되어 있어야 합니다.

#### Elasticsearch

```bash
sudo bash scripts/elasticsearch_cce_check.sh [출력파일.json]
```

Elasticsearch는 REST API로 점검하며, 환경변수로 접속 URL을 지정합니다.

**예시:**
```bash
# 기본 (localhost:9200)
sudo bash scripts/elasticsearch_cce_check.sh

# 원격 Elasticsearch
ES_URL=http://192.168.1.30:9200 sudo bash scripts/elasticsearch_cce_check.sh result_es.json

# 인증이 필요한 경우
ES_URL=https://user:pass@es-host:9200 sudo bash scripts/elasticsearch_cce_check.sh
```

#### MongoDB

```bash
sudo bash scripts/mongodb_cce_check.sh [-h 호스트] [-P 포트] [-u 사용자] [-p 비밀번호] [출력파일.json]
```

**예시:**
```bash
# 로컬 MongoDB (인증 없음)
sudo bash scripts/mongodb_cce_check.sh

# 인증 사용
sudo bash scripts/mongodb_cce_check.sh -h 10.0.0.20 -P 27017 -u admin -p mongoPass result_mongo.json
```

> `mongosh` 또는 `mongo` 클라이언트가 설치되어 있어야 합니다.

---

### 5. 웹서버 (Apache, Nginx, Tomcat)

```bash
sudo bash scripts/apache_cce_check.sh [출력파일.json]
sudo bash scripts/nginx_cce_check.sh [출력파일.json]
sudo bash scripts/tomcat_cce_check.sh [출력파일.json]
```

**예시:**
```bash
sudo bash scripts/apache_cce_check.sh result_apache.json
sudo bash scripts/nginx_cce_check.sh result_nginx.json
sudo bash scripts/tomcat_cce_check.sh result_tomcat.json
```

> 스크립트가 자동으로 설정 파일 위치를 탐색합니다.
> - Apache: `/etc/httpd/conf/httpd.conf`, `/etc/apache2/apache2.conf` 등
> - Nginx: `/etc/nginx/nginx.conf` 등
> - Tomcat: `$CATALINA_HOME` 환경변수 또는 `/usr/share/tomcat*`, `/opt/tomcat*` 등

Tomcat의 경우 `CATALINA_HOME`을 명시적으로 지정할 수 있습니다:

```bash
CATALINA_HOME=/opt/tomcat9 sudo bash scripts/tomcat_cce_check.sh result_tomcat.json
```

---

### 6. 컨테이너 (Docker, Kubernetes)

```bash
# Docker 호스트에서 실행
sudo bash scripts/docker_cce_check.sh [출력파일.json]

# K8s Master 노드에서 실행
sudo bash scripts/k8s_master_cce_check.sh [출력파일.json]

# K8s Worker 노드에서 실행
sudo bash scripts/k8s_worker_cce_check.sh [출력파일.json]
```

**예시:**
```bash
sudo bash scripts/docker_cce_check.sh result_docker.json
sudo bash scripts/k8s_master_cce_check.sh result_k8s_master.json
sudo bash scripts/k8s_worker_cce_check.sh result_k8s_worker.json
```

> - Docker 스크립트는 `docker` 명령어 실행 권한이 필요합니다.
> - K8s 스크립트는 `kubectl` 명령어 및 클러스터 접근 권한이 필요합니다.
> - K8s Master는 `/etc/kubernetes/manifests/` 하위 매니페스트 파일을 점검합니다.

---

### 7. 애플리케이션 (PHP, Node.js, Hadoop, Ceph)

```bash
sudo bash scripts/php_cce_check.sh [출력파일.json]
sudo bash scripts/nodejs_cce_check.sh [출력파일.json]
sudo bash scripts/hadoop_cce_check.sh [출력파일.json]
sudo bash scripts/ceph_cce_check.sh [출력파일.json]
```

**예시:**
```bash
sudo bash scripts/php_cce_check.sh result_php.json
sudo bash scripts/nodejs_cce_check.sh result_nodejs.json
sudo bash scripts/hadoop_cce_check.sh result_hadoop.json
sudo bash scripts/ceph_cce_check.sh result_ceph.json
```

> - Hadoop: `$HADOOP_CONF_DIR` 환경변수로 설정 디렉토리 지정 가능 (기본: `/etc/hadoop/conf`)
> - Ceph: `$CEPH_CONF` 환경변수로 설정 파일 지정 가능 (기본: `/etc/ceph/ceph.conf`)

---

## 자동 탐지 기능 (Pre-flight Detection)

각 스크립트는 실행 시 자동으로 대상 애플리케이션의 설치 여부를 확인하고 바이너리/설정 파일 경로를 탐지합니다.

### 탐지 방식

모든 스크립트의 `detect_app()` 함수가 아래 순서로 탐지를 수행합니다:

1. **바이너리 탐지**: `command -v`로 실행 파일 존재 여부 확인
2. **프로세스 탐지**: `ps -ef`로 실행 중인 프로세스에서 경로/설정 추출
3. **공통 경로 탐색**: 알려진 설치 경로를 순회하며 설정 파일 탐색
4. **패키지 매니저 확인**: `dpkg -l` / `rpm -qa`로 패키지 설치 여부 확인
5. **설정 파일 확정**: 발견된 경로를 전역 변수에 저장

### 탐지 결과

| 상태 | 동작 |
|---|---|
| 앱 발견 | 탐지된 경로를 전역 변수에 저장하고 정상 진행 |
| 앱 미발견 | 경고 메시지 출력 후 진단 계속 진행 (일부 항목 N/A 처리) |

### 앱별 탐지 변수

| 앱 | 주요 전역 변수 |
|---|---|
| MySQL | `MYSQL_BIN`, `MYSQLD_BIN`, `MYSQL_CONF` |
| MSSQL | `SQLCMD_BIN`, `MSSQL_CONF` |
| PostgreSQL | `PSQL_BIN`, `PG_DATA`, `PG_CONF`, `PG_HBA` |
| Redis | `REDIS_CLI`, `REDIS_CONF` |
| Elasticsearch | `ES_CONF`, `ES_URL` |
| MongoDB | `MONGO_BIN`, `MONGOD_CONF` |
| Apache | `APACHE_BIN`, `APACHE_CONF`, `APACHE_CONF_DIR` |
| Nginx | `NGINX_BIN`, `NGINX_CONF` |
| Tomcat | `CATALINA_HOME` |
| Docker | `DOCKER_BIN`, `DOCKER_CONF` |
| K8s Master | `KUBECTL_BIN`, `K8S_MANIFEST_DIR` |
| K8s Worker | `KUBECTL_BIN`, `KUBELET_CONF` |
| KVM | `VIRSH_BIN`, `LIBVIRT_CONF` |
| Xenserver | `XE_BIN` |
| ESXi | `ESXCLI_BIN` |
| PHP | `PHP_BIN`, `PHP_INI` |
| Node.js | `NODE_BIN`, `NPM_BIN` |
| Hadoop | `HADOOP_BIN`, `HADOOP_CONF_DIR` |
| Ceph | `CEPH_BIN`, `CEPH_CONF` |

> Windows는 OS 자체를 진단하므로 별도 앱 탐지가 필요하지 않습니다.

---

## 결과 JSON 구조

```json
{
  "scan_info": {
    "hostname": "server01",
    "os": "Ubuntu 24.04 LTS",
    "kernel": "6.6.87",
    "ip": "192.168.1.10",
    "scan_date": "2026-02-19 23:00:00",
    "platform": "Linux",
    "guide_sources": [
      "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)",
      "클라우드 취약점 점검 가이드 (2024)"
    ]
  },
  "summary": {
    "total": 71,
    "양호": 35,
    "취약": 11,
    "N/A": 16,
    "수동점검": 9
  },
  "results": [
    {
      "code": "ISMS-U-01",
      "category": "계정 관리",
      "title": "root 계정 원격 접속 제한",
      "importance": "상",
      "status": "양호",
      "detail": "SSH PermitRootLogin=no. Telnet 서비스 비활성화.",
      "source": "공통",
      "command": "grep -i '^PermitRootLogin' /etc/ssh/sshd_config",
      "current_state": "PermitRootLogin=no; Telnet=inactive",
      "remediation": "/etc/ssh/sshd_config 파일에서 PermitRootLogin no 설정"
    }
  ]
}
```

### 결과 필드 설명

| 필드 | 설명 |
|---|---|
| `code` | 항목 번호 (예: ISMS-U-01, CSAP-Docker-01, ISMS-W-03) |
| `category` | 항목 분류 (계정 관리, 보안 설정 등) |
| `title` | 항목명 |
| `importance` | 중요도 (상/중/하 또는 -) |
| `status` | 판정 결과: `양호`, `취약`, `N/A`, `수동점검` |
| `detail` | 판단 근거 상세 설명 |
| `source` | 출처 (기반시설, 클라우드, 통합, 공통) |
| `command` | 실제 수행한 점검 명령어 |
| `current_state` | 명령어 실행 결과 (현재 시스템 상태) |
| `remediation` | 조치 방법 |

> `command`와 `current_state`를 통해 개발자가 조치 후 동일 명령어로 재확인할 수 있습니다.

---

## Codex 작업 흐름

### 기본 재생성 순서

```bash
python3 extract_cce.py
python3 dedup_excel.py
python3 generate_scripts.py
python3 tools/codex_harness.py
```

- `extract_cce.py`: 원본 PDF에서 `cloud_items.json`, `main_items.json` 생성
- `dedup_excel.py`: 플랫폼 필터링과 중복 제거를 적용해 `진단항목통합.xlsx` 생성
- `generate_scripts.py`: Excel 데이터를 기반으로 `scripts/` 하위 진단 스크립트 생성
- `tools/codex_harness.py`: Python/JSON/Shell 문법, 절대경로, 레거시 AI 흔적을 점검

### 참고 사항

- `generate_excel.py`는 비교용으로 남겨둔 기존 Excel 생성 경로이며, 기본 재생성은 `dedup_excel.py`를 우선 사용합니다.
- `linux_cce_check.sh`는 수동 관리 기준 스크립트이고, `scripts/` 하위 파일은 생성기 중심으로 관리하는 것이 안전합니다.
- 경로 하드코딩은 `project_paths.py`에서 통합 관리합니다.

---

## 대시보드 하네스

Flask 기반 대시보드 하네스를 추가했습니다. 주요 기능은 아래와 같습니다.

- 호스트 등록 후 `local` 또는 `ssh` 방식으로 애플리케이션 탐지
- 탐지된 애플리케이션 기준으로 기존 CCE 진단 스크립트 원격 실행
- 탐지/진단 요청 시 백그라운드 큐로 넘기고 상태를 자동 새로고침으로 추적
- 호스트별 실행 지원 매트릭스로 현재 하네스에서 실행 가능한 스크립트 범위 표시
- 탐지 시 앱별 설정 파일/설치 경로를 같이 수집하고 호스트별로 저장
- 호스트 상세 화면에서 자동 탐지 경로와 수동 오버라이드를 함께 관리
- 결과별 원본 판정, 최종 판정, 수행 명령, 현재 상태, 조치방법 조회
- 일반사용자 예외 요청, 보안담당자 예외 승인 및 최종 판정
- 결과 필터링 후 Excel 다운로드
- 통제 카탈로그에서 항목, 진단방법, 조치방법, 프레임워크 태그 조회

### 실행

```bash
python3 run_dashboard.py init-db
python3 run_dashboard.py create-user security security123! security
python3 run_dashboard.py create-user operator operator123! user
python3 run_dashboard.py serve --host 0.0.0.0 --port 5001
```

기본 URL은 `http://127.0.0.1:5001`입니다.

### 현재 지원 범위

- 현재 대시보드 운영 범위는 Linux/Unix POSIX 호스트 우선입니다.
- 원격 탐지/실행은 SSH 키 기반 POSIX 호스트를 우선 지원합니다.
- 앱별 경로값은 `자동 탐지 -> 저장 -> 수동 오버라이드` 순서로 적용되며, 진단 실행 시 수동값이 우선합니다.
- Windows PowerShell 원격 실행은 저장소 자산만 유지하고 있고, 대시보드 운영 경로에서는 아직 제외했습니다.
- `공공CSAP`, `ISMS-P` 표시는 현재 저장소의 기존 출처 값을 기반으로 한 초기 매핑입니다. 실제 심사 기준용으로 사용하려면 내부 기준서에 맞춘 매핑 보정이 필요합니다.

### Docker 테스트 랩

컨테이너로 재현 가능한 Linux 대상은 `docker/test-lab/` 아래 compose 랩으로 검증할 수 있습니다.

```bash
docker compose -f docker/test-lab/compose.yml --profile common up -d
docker/test-lab/run_check.sh nginx-lab Nginx
```

- 대상별 랩 모드 표: `docker/test-lab/targets.md`
- 사용법: `docker/test-lab/README.md`
- 하이퍼바이저, Windows, 일부 분산 스택은 컨테이너 대신 VM/물리 장비 테스트 호스트로 분리합니다.

---

## 스크립트 재생성

`진단항목통합.xlsx`의 데이터가 변경된 경우, 스크립트를 재생성할 수 있습니다.

```bash
pip install openpyxl
python3 generate_scripts.py
```

`scripts/` 디렉토리에 20개 스크립트가 새로 생성됩니다.

변경 검증은 아래 하네스로 수행합니다.

```bash
python3 tools/codex_harness.py
```

---

## 프로젝트 구조

```
├── AGENTS.md                    # Codex용 저장소 작업 가이드
├── dashboard/                   # Flask 대시보드 앱
├── linux_cce_check.sh          # Linux 진단 스크립트 (수동 작성)
├── project_paths.py            # 저장소 상대 경로 상수
├── run_dashboard.py            # 대시보드 실행 / DB 초기화 / 사용자 생성
├── tools/
│   └── codex_harness.py        # Codex 검증 하네스
├── generate_scripts.py         # 스크립트 자동 생성기
├── 진단항목통합.xlsx            # 475개 CCE 항목 데이터 소스
├── extract_cce.py              # PDF → JSON 추출기
├── generate_excel.py           # 기존 Excel 생성기
├── dedup_excel.py              # 기본 Excel 생성기 (필터링 + 중복 제거)
├── cloud_items.json            # 클라우드 가이드 추출 데이터
├── main_items.json             # 기반시설 가이드 추출 데이터
└── scripts/                    # 자동 생성된 진단 스크립트 (20개)
    ├── kvm_cce_check.sh
    ├── xenserver_cce_check.sh
    ├── esxi_cce_check.sh
    ├── mysql_cce_check.sh
    ├── mssql_cce_check.sh
    ├── postgresql_cce_check.sh
    ├── redis_cce_check.sh
    ├── elasticsearch_cce_check.sh
    ├── mongodb_cce_check.sh
    ├── apache_cce_check.sh
    ├── nginx_cce_check.sh
    ├── tomcat_cce_check.sh
    ├── docker_cce_check.sh
    ├── k8s_master_cce_check.sh
    ├── k8s_worker_cce_check.sh
    ├── php_cce_check.sh
    ├── nodejs_cce_check.sh
    ├── hadoop_cce_check.sh
    ├── ceph_cce_check.sh
    └── windows_cce_check.ps1
```

---

## 참고 문서

- 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
- 클라우드 취약점 점검 가이드 (2024)
