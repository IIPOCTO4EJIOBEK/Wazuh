#!/bin/bash
# =====================================================================
#  Восстановление индексов Wazuh из снапшота OpenSearch.
#
#  Применяется в двух случаях:
#    * потеряны данные за период (сбой хранилища, ошибочное удаление);
#    * нужно поднять архивные данные для расследования, которые уже
#      удалены политикой хранения.
#
#  Важно понимать: восстановить индекс поверх существующего нельзя —
#  OpenSearch откажется. Поэтому предлагается два режима:
#    --rename   восстановить под другим именем (restored-wazuh-alerts-*)
#               и работать с копией, не трогая рабочие данные;
#    --replace  закрыть существующий индекс и восстановить поверх.
#
#  По умолчанию — --rename. Это почти всегда правильный выбор:
#  расследование не должно менять то, что расследуется.
#
#  Использование:
#      restore-indices.sh --list
#      restore-indices.sh --snapshot <имя> --indices 'wazuh-alerts-4.x-2026.06*'
#      restore-indices.sh --snapshot <имя> --indices '...' --replace
# =====================================================================

set -uo pipefail

ENV_FILE="/etc/wazuh-backup.env"
# shellcheck source=/dev/null
[ -r "$ENV_FILE" ] && . "$ENV_FILE"

HOST="${INDEXER_ADDR:-10.5.2.81}"
PORT="${INDEXER_PORT:-9200}"
REPO="${SNAPSHOT_REPO:-wazuh-snapshots}"
USER="${INDEXER_ADMIN_USER:-admin}"
PASS="${INDEXER_ADMIN_PASS:-}"

SNAPSHOT=""
INDICES=""
MODE="rename"

api() {
    local method="$1" path="$2" body="${3:-}"
    if [ -n "$body" ]; then
        curl -sk -X "$method" -u "${USER}:${PASS}" \
             -H 'Content-Type: application/json' \
             "https://${HOST}:${PORT}${path}" -d "$body"
    else
        curl -sk -X "$method" -u "${USER}:${PASS}" "https://${HOST}:${PORT}${path}"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --list)
            echo "Снапшоты в репозитории ${REPO}:"
            api GET "/_cat/snapshots/${REPO}?v&s=start_epoch:desc&h=id,status,start_time,duration,indices"
            exit 0
            ;;
        --snapshot) SNAPSHOT="${2:-}"; shift 2 ;;
        --indices)  INDICES="${2:-}"; shift 2 ;;
        --replace)  MODE="replace"; shift ;;
        --rename)   MODE="rename"; shift ;;
        -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$PASS" ]; then
    read -rsp "Пароль ${USER}: " PASS
    echo
fi

if [ -z "$SNAPSHOT" ] || [ -z "$INDICES" ]; then
    echo "Нужно указать --snapshot и --indices. Список: $0 --list" >&2
    exit 2
fi

echo "Снапшот:  ${SNAPSHOT}"
echo "Индексы:  ${INDICES}"
echo "Режим:    ${MODE}"
echo

if [ "$MODE" = "replace" ]; then
    echo "ВНИМАНИЕ: существующие индексы будут закрыты и перезаписаны."
    printf 'Введите «да» для продолжения: '
    read -r answer
    [ "$answer" = "да" ] || { echo "Отменено."; exit 0; }

    echo "Закрываю существующие индексы..."
    api POST "/${INDICES}/_close" >/dev/null

    BODY=$(cat <<EOF
{
  "indices": "${INDICES}",
  "ignore_unavailable": true,
  "include_global_state": false,
  "include_aliases": false
}
EOF
)
else
    # Восстановление под другим именем. Реплики снимаются: копия для
    # расследования не нуждается в избыточности и не должна занимать
    # вдвое больше места на рабочем кластере.
    BODY=$(cat <<EOF
{
  "indices": "${INDICES}",
  "ignore_unavailable": true,
  "include_global_state": false,
  "include_aliases": false,
  "rename_pattern": "(.+)",
  "rename_replacement": "restored-\$1",
  "index_settings": {
    "index.number_of_replicas": 0,
    "index.blocks.read_only_allow_delete": null
  }
}
EOF
)
fi

echo "Запускаю восстановление..."
RESULT=$(api POST "/_snapshot/${REPO}/${SNAPSHOT}/_restore?wait_for_completion=false" "$BODY")
echo "$RESULT"
echo

echo "Ход восстановления (обновляется, прервать — Ctrl+C):"
while true; do
    STATE=$(api GET "/_cat/recovery?v&active_only=true&h=index,shard,stage,files_percent,bytes_percent")
    if [ -z "$(printf '%s' "$STATE" | sed -n '2p')" ]; then
        echo "Активных операций восстановления нет."
        break
    fi
    printf '%s\n' "$STATE"
    sleep 10
done

echo
echo "Проверка:"
api GET "/_cat/indices/${INDICES}?v&h=index,health,status,docs.count,store.size"
if [ "$MODE" = "rename" ]; then
    api GET "/_cat/indices/restored-*?v&h=index,health,status,docs.count,store.size"
    echo
    echo "Данные доступны в индексах restored-*."
    echo "Чтобы увидеть их в интерфейсе, создайте шаблон индекса restored-wazuh-alerts-*"
    echo "с полем времени timestamp."
    echo
    echo "После расследования удалить копию:"
    echo "  curl -k -u ${USER} -X DELETE 'https://${HOST}:${PORT}/restored-*'"
fi
