# CCE Test Lab Coverage

이 디렉터리는 가이드 대상 전체를 한 번에 정리하기 위한 테스트 랩 기준표다.

| 대상 | 랩 모드 | 비고 |
| --- | --- | --- |
| Linux | host/local | 기본 OS 점검은 대시보드 호스트 또는 별도 Linux VM에서 수행 |
| Apache | compose | 웹 프로파일 |
| Nginx | compose | 웹 프로파일, 커스텀 설정 경로 예제 포함 |
| Tomcat | compose | 웹 프로파일 |
| PHP | compose | 커스텀 `php.ini` 예제 포함 |
| NodeJS | compose | 런타임 프로파일 |
| MY-SQL | compose | MariaDB 기반, 커스텀 `my.cnf` 예제 포함 |
| PostgreSQL | compose | `PGDATA` 커스텀 데이터 경로 예제 포함 |
| Redis | compose | 커스텀 `redis.conf` 예제 포함 |
| MongoDB | compose | 커스텀 `mongod.conf` 예제 포함 |
| Elasticsearch | compose | `ES_PATH_CONF` 커스텀 경로 예제 포함 |
| MS-SQL | compose-extended | Linux SQL Server 이미지, 리소스 요구량 큼 |
| Docker | compose-extended | `docker:dind`, privileged 필요 |
| K8s(Master) | compose-extended | `k3s` server, privileged 필요 |
| K8s(Worker) | compose-extended | `k3s` agent, privileged 필요 |
| Hadoop | vm-or-compose-extended | 분산 구성 특성상 단일 compose 검증은 제한적 |
| Ceph | vm-or-compose-extended | 분산 구성 특성상 단일 compose 검증은 제한적 |
| KVM | vm-only | 하이퍼바이저 기능 필요 |
| Xenserver | vm-only | 하이퍼바이저 기능 필요 |
| ESXi | vm-only | VMware 전용 환경 필요 |
| Windows | vm-only | Windows Server 필요 |

원칙:

- `compose` 대상은 `docker/test-lab/compose.yml`로 즉시 올릴 수 있게 유지한다.
- `compose-extended` 대상은 privileged, 높은 메모리, 추가 라이선스 조건이 있어 기본 프로파일에서 분리한다.
- `vm-only` 대상은 컨테이너로 대체하지 않고 별도 VM/물리 장비를 테스트 호스트로 등록한다.
