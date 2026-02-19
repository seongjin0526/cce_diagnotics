# CCE 취약점 진단 스크립트

주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026)와 클라우드 취약점 점검 가이드(2024)를 기반으로 한 자동화 진단 스크립트 모음입니다.
**모든 코드는 claude로만 작성했습니다.**

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
      "code": "U-01",
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
| `code` | 항목 번호 (예: U-01, CLD-Docker-01, W-03) |
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

## 스크립트 재생성

`진단항목통합.xlsx`의 데이터가 변경된 경우, 스크립트를 재생성할 수 있습니다.

```bash
pip install openpyxl
python3 generate_scripts.py
```

`scripts/` 디렉토리에 20개 스크립트가 새로 생성됩니다.

---

## 프로젝트 구조

```
├── linux_cce_check.sh          # Linux 진단 스크립트 (수동 작성)
├── generate_scripts.py         # 스크립트 자동 생성기
├── 진단항목통합.xlsx            # 475개 CCE 항목 데이터 소스
├── extract_cce.py              # PDF → JSON 추출기
├── generate_excel.py           # JSON → Excel 변환기
├── dedup_excel.py              # 중복 제거 처리기
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
