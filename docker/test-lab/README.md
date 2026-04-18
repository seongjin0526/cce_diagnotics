# Docker Test Lab

이 랩은 Linux 계열 가이드 대상을 빠르게 재현하고 스크립트를 반복 검증하기 위한 compose 기반 환경이다. 모든 대상을 무조건 컨테이너 하나로 치환하지는 않는다. 하이퍼바이저와 Windows는 별도 VM이 필요하고, 분산 스택은 `extended` 프로파일로 분리했다.

## 구성

- `common`: Apache, Nginx, Tomcat, PHP, NodeJS, MySQL(MariaDB), PostgreSQL, Redis, MongoDB, Elasticsearch
- `extended`: MSSQL, Docker(dind), K3s server/agent
- `targets.md`: 전체 대상별 랩 모드 표

## 실행

```bash
docker compose -f docker/test-lab/compose.yml --profile common up -d
```

확장 대상까지 포함하려면:

```bash
docker compose -f docker/test-lab/compose.yml --profile common --profile extended up -d
```

정리:

```bash
docker compose -f docker/test-lab/compose.yml --profile common --profile extended down -v
```

## 스크립트 검증

컨테이너 안에서 저장소의 최신 스크립트를 그대로 실행한다.

```bash
docker/test-lab/run_check.sh nginx-lab Nginx
docker/test-lab/run_check.sh mysql-lab MY-SQL
docker/test-lab/run_check.sh postgresql-lab PostgreSQL
```

데이터베이스 기본값:

- MySQL: `root` / 빈 비밀번호
- PostgreSQL: `postgres` / trust
- MSSQL: `sa` / `CceLab123!`

## 경로 변형 시나리오

이 랩은 기본 경로와 커스텀 경로를 섞어서 만든다.

- `nginx-lab`: `/opt/cce/nginx/nginx.conf`
- `php-lab`: `/opt/cce/php/php.ini`
- `mysql-lab`: `/opt/cce/mysql/my.cnf`
- `postgresql-lab`: `PGDATA=/opt/cce/postgresql/data`
- `redis-lab`: `/opt/cce/redis/redis.conf`
- `mongodb-lab`: `/opt/cce/mongodb/mongod.conf`
- `elasticsearch-lab`: `ES_PATH_CONF=/opt/cce/elasticsearch`
- `docker-lab`: `/opt/cce/docker/daemon.json`

`elasticsearch-lab`처럼 프로세스 옵션만으로는 자동 탐지가 제한될 수 있는 항목은 대시보드의 수동 오버라이드 필드로 보정하는 흐름까지 포함해 검증한다.

## 대시보드 연계

현재 대시보드는 `local` 또는 `ssh` 전송만 지원한다. 이 랩은 우선 스크립트 검증용으로 쓰고, 대시보드에서는 다음 둘 중 하나로 연결한다.

1. 별도 Linux VM/호스트에 애플리케이션을 설치해 `ssh` 호스트로 등록
2. 컨테이너 내부에 SSH를 추가한 별도 래퍼 이미지를 만들어 테스트 호스트로 등록

경로 관련 검증은 대시보드 `호스트 상세 > 앱 경로 / 설정 오버라이드`에서 자동탐지값 저장과 수동 오버라이드 저장까지 같이 확인하면 된다.
