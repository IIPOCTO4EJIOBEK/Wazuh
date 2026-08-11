#!/bin/bash
# =====================================================================
#  Восстановление менеджера Wazuh из резервной копии.
#
#  Порядок восстановления после полной потери менеджера:
#
#    1. Развернуть чистый узел и поставить wazuh-manager той же версии
#       (ansible-playbook site.yml --tags manager --limit <узел>).
#    2. Восстановить конфигурацию этим скриптом.
#    3. Проверить, что агенты подключились: wazuh-control status,
#       затем /var/ossec/bin/agent_control -l
#    4. Индексы алертов восстанавливаются отдельно, из снапшота —
#       см. docs/05-backup-restore.md.
#
#  Скрипт намеренно не делает ничего необратимого без подтверждения:
#  восстановление поверх работающего узла с живыми агентами может
#  оказаться хуже самой аварии.
#
#  Использование:
#      wazuh-restore.sh --list
#      wazuh-restore.sh --from /var/backups/wazuh/wazuh-config-...tar.gz
#      wazuh-restore.sh --from <архив> --only-keys   только client.keys
# =====================================================================

set -uo pipefail

ENV_FILE="/etc/wazuh-backup.env"
OSSEC_DIR="/var/ossec"

# shellcheck source=/dev/null
[ -r "$ENV_FILE" ] && . "$ENV_FILE"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/wazuh}"

ARCHIVE=""
ONLY_KEYS=0
ASSUME_YES=0

usage() {
    sed -n '2,30p' "$0"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --list)
            echo "Доступные копии в ${BACKUP_DIR}:"
            ls -1t "${BACKUP_DIR}"/wazuh-config-*.tar.gz 2>/dev/null | while read -r f; do
                printf '  %s  %s  %s\n' \
                    "$(date -r "$f" '+%d.%m.%Y %H:%M')" \
                    "$(du -h "$f" | cut -f1)" \
                    "$f"
            done
            exit 0
            ;;
        --from)      ARCHIVE="${2:-}"; shift 2 ;;
        --only-keys) ONLY_KEYS=1; shift ;;
        --yes)       ASSUME_YES=1; shift ;;
        -h|--help)   usage 0 ;;
        *)           echo "Неизвестный параметр: $1" >&2; usage 2 ;;
    esac
done

if [ -z "$ARCHIVE" ]; then
    echo "Не указан архив. Список доступных копий: $0 --list" >&2
    exit 2
fi

if [ ! -r "$ARCHIVE" ]; then
    echo "Архив не найден или недоступен: $ARCHIVE" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# Проверки до изменений
# ---------------------------------------------------------------------
echo "Проверка архива..."

if [ -r "${ARCHIVE}.sha256" ]; then
    if sha256sum -c "${ARCHIVE}.sha256" >/dev/null 2>&1; then
        echo "  контрольная сумма совпадает"
    else
        echo "  контрольная сумма НЕ совпадает — архив повреждён" >&2
        exit 1
    fi
else
    echo "  файла контрольной суммы нет, проверяю только читаемость"
fi

if ! tar tzf "$ARCHIVE" >/dev/null 2>&1; then
    echo "  архив не читается" >&2
    exit 1
fi

CONTENTS="$(tar tzf "$ARCHIVE")"
if ! printf '%s' "$CONTENTS" | grep -q 'etc/client.keys'; then
    echo "  в архиве нет etc/client.keys — это не копия менеджера" >&2
    exit 1
fi

AGENTS_IN_BACKUP="$(tar xzf "$ARCHIVE" -O etc/client.keys 2>/dev/null | grep -c . || echo 0)"
AGENTS_NOW=0
[ -r "${OSSEC_DIR}/etc/client.keys" ] && AGENTS_NOW="$(grep -c . "${OSSEC_DIR}/etc/client.keys" || echo 0)"

echo
echo "Что будет сделано:"
echo "  архив:            ${ARCHIVE}"
echo "  агентов в копии:  ${AGENTS_IN_BACKUP}"
echo "  агентов сейчас:   ${AGENTS_NOW}"
if [ "$ONLY_KEYS" -eq 1 ]; then
    echo "  режим:            только client.keys"
else
    echo "  режим:            полная конфигурация (правила, декодеры, группы, API)"
fi
echo

# Предупреждение о самой опасной ситуации: восстановление старой копии
# поверх более полного текущего состояния.
if [ "$AGENTS_NOW" -gt "$AGENTS_IN_BACKUP" ]; then
    echo "ВНИМАНИЕ: сейчас зарегистрировано агентов больше, чем в копии."
    echo "Восстановление отключит $(( AGENTS_NOW - AGENTS_IN_BACKUP )) агентов —"
    echo "их придётся регистрировать заново."
    echo
fi

if [ "$ASSUME_YES" -ne 1 ]; then
    printf 'Продолжить? Введите «да»: '
    read -r answer
    case "$answer" in
        да|ДА|Да|yes|y) ;;
        *) echo "Отменено."; exit 0 ;;
    esac
fi

# ---------------------------------------------------------------------
# Восстановление
# ---------------------------------------------------------------------
SAFETY="${BACKUP_DIR}/pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz"
echo "Сохраняю текущее состояние в ${SAFETY}"
mkdir -p "$BACKUP_DIR"
tar czf "$SAFETY" -C "$OSSEC_DIR" etc api/configuration 2>/dev/null || true

echo "Останавливаю менеджер..."
systemctl stop wazuh-manager 2>/dev/null || "${OSSEC_DIR}/bin/wazuh-control" stop

if [ "$ONLY_KEYS" -eq 1 ]; then
    tar xzf "$ARCHIVE" -C "$OSSEC_DIR" etc/client.keys
    echo "Восстановлен client.keys"
else
    tar xzf "$ARCHIVE" -C "$OSSEC_DIR"
    echo "Восстановлена конфигурация"

    # База состояния лежит в архиве отдельным каталогом db/
    if printf '%s' "$CONTENTS" | grep -q '^db/'; then
        mkdir -p "${OSSEC_DIR}/queue/db"
        tar xzf "$ARCHIVE" -C "${OSSEC_DIR}/queue" --strip-components=0 db 2>/dev/null || true
        echo "Восстановлено состояние агентов"
    fi
fi

echo "Восстанавливаю права..."
chown -R root:wazuh "${OSSEC_DIR}/etc"
chmod 660 "${OSSEC_DIR}/etc/ossec.conf" 2>/dev/null || true
chmod 640 "${OSSEC_DIR}/etc/client.keys" 2>/dev/null || true
chown root:wazuh "${OSSEC_DIR}/etc/client.keys" 2>/dev/null || true
chown -R wazuh:wazuh "${OSSEC_DIR}/queue/db" 2>/dev/null || true
chown -R wazuh:wazuh "${OSSEC_DIR}/etc/shared" 2>/dev/null || true

echo "Проверяю конфигурацию..."
if ! "${OSSEC_DIR}/bin/wazuh-analysisd" -t; then
    echo "Конфигурация не проходит проверку. Менеджер не запущен." >&2
    echo "Вернуть как было: tar xzf ${SAFETY} -C ${OSSEC_DIR}" >&2
    exit 1
fi

echo "Запускаю менеджер..."
systemctl start wazuh-manager 2>/dev/null || "${OSSEC_DIR}/bin/wazuh-control" start

sleep 10
echo
echo "Состояние служб:"
"${OSSEC_DIR}/bin/wazuh-control" status

echo
echo "Дальше:"
echo "  1. Дождаться подключения агентов:  ${OSSEC_DIR}/bin/agent_control -l"
echo "  2. Проверить кластер:              ${OSSEC_DIR}/bin/cluster_control -l"
echo "  3. Если восстанавливали master — worker подтянет правила сам."
echo "  4. Индексы алертов восстанавливаются из снапшота отдельно:"
echo "     см. docs/05-backup-restore.md"
echo
echo "Копия состояния до восстановления: ${SAFETY}"
