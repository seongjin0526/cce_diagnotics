#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE="$ROOT_DIR/docker/test-lab/compose.yml"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <service> <app-key> [script-args...]"
    exit 1
fi

service="$1"
app_key="$2"
shift 2

script_path=""
extra_args=()

case "$app_key" in
    Linux) script_path="/workspace/linux_cce_check.sh" ;;
    Apache) script_path="/workspace/scripts/apache_cce_check.sh" ;;
    Nginx) script_path="/workspace/scripts/nginx_cce_check.sh" ;;
    Tomcat) script_path="/workspace/scripts/tomcat_cce_check.sh" ;;
    PHP) script_path="/workspace/scripts/php_cce_check.sh" ;;
    NodeJS) script_path="/workspace/scripts/nodejs_cce_check.sh" ;;
    MY-SQL)
        script_path="/workspace/scripts/mysql_cce_check.sh"
        extra_args=(-u root)
        ;;
    PostgreSQL)
        script_path="/workspace/scripts/postgresql_cce_check.sh"
        extra_args=(-u postgres)
        ;;
    Redis) script_path="/workspace/scripts/redis_cce_check.sh" ;;
    MongoDB) script_path="/workspace/scripts/mongodb_cce_check.sh" ;;
    Elasticsearch) script_path="/workspace/scripts/elasticsearch_cce_check.sh" ;;
    MS-SQL)
        script_path="/workspace/scripts/mssql_cce_check.sh"
        extra_args=(-u sa -p CceLab123!)
        ;;
    Docker) script_path="/workspace/scripts/docker_cce_check.sh" ;;
    "K8s(Master)") script_path="/workspace/scripts/k8s_master_cce_check.sh" ;;
    "K8s(Worker)") script_path="/workspace/scripts/k8s_worker_cce_check.sh" ;;
    Hadoop) script_path="/workspace/scripts/hadoop_cce_check.sh" ;;
    Ceph) script_path="/workspace/scripts/ceph_cce_check.sh" ;;
    KVM) script_path="/workspace/scripts/kvm_cce_check.sh" ;;
    Xenserver) script_path="/workspace/scripts/xenserver_cce_check.sh" ;;
    ESXi) script_path="/workspace/scripts/esxi_cce_check.sh" ;;
    *)
        echo "Unsupported app-key: $app_key"
        exit 1
        ;;
esac

build_script_command() {
    local parts=("$script_path")
    local arg
    for arg in "${extra_args[@]}" "$@"; do
        parts+=("$arg")
    done
    parts+=("/tmp/cce-result.json")

    local quoted=()
    for arg in "${parts[@]}"; do
        quoted+=("$(printf '%q' "$arg")")
    done
    printf '%s ' "${quoted[@]}"
}

script_command=$(build_script_command "$@")

docker compose -f "$COMPOSE_FILE" exec -T "$service" sh -lc \
    "set -e; rm -f /tmp/cce-result.json /tmp/cce.stdout; ${script_command}>/tmp/cce.stdout 2>&1 || true; cat /tmp/cce.stdout >&2; cat /tmp/cce-result.json"
