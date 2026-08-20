#!/bin/bash
# =====================================================================
#  Резервное копирование менеджера Wazuh.
#
#  Что копируется и почему именно это:
#
#    client.keys            без него восстановленный менеджер не примет
#                           ни одного агента — все триста придётся
#                           регистрировать заново. Килобайты объёма,
#                           дни работы при потере.
#    etc/ (правила, декодеры, ossec.conf, списки, authd.pass)
#                           труд, который нигде больше не хранится,
#                           кроме git-репозитория этого проекта.
#    queue/agents-timestamp, queue/db
#                           состояние агентов и групп: после потери
#                           агенты считаются новыми и теряют историю.
#    api/configuration      настройки и пользователи Wazuh API.
#    active-response/bin    собственные скрипты реагирования.
#
#  Что НЕ копируется:
#    сами алерты — они в индексере, у них свои снапшоты (политика
#    wazuh-daily). Дублировать их здесь означало бы хранить одно и то
#    же дважды и путать сроки хранения.
#
#  Скрипт также проверяет свежесть снапшота индексера: резервная копия
#  конфигурации без резервной копии данных — половина восстановления.
#
#  Запуск:
#      wazuh-backup.sh                копия + выгрузка за пределы площадки
#      wazuh-backup.sh --dry-run      проверить, ничего не делая
#      wazuh-backup.sh --offsite-only только выгрузка готовых копий
#
#  Результат каждого запуска попадает в журнал в формате, который
#  разбирает декодер wazuh-backup и правила 100440–100443: неудачное
#  копирование само становится инцидентом.
# =====================================================================

set -uo pipefail

ENV_FILE="/etc/wazuh-backup.env"
OSSEC_DIR="/var/ossec"
STAMP="$(date +%Y%m%d-%H%M%S)"

DRY_RUN=0
OFFSITE_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)      DRY_RUN=1 ;;
        --offsite-only) OFFSITE_ONLY=1 ;;
        -h|--help)
            sed -n '2,45p' "$0"
            exit 0
            ;;
        *)
            echo "Неизвестный параметр: $arg" >&2
            exit 2
            ;;
    esac
done

# shellcheck source=/dev/null
[ -r "$ENV_FILE" ] && . "$ENV_FILE"

BACKUP_DIR="${BACKUP_DIR:-/var/backups/wazuh}"
KEEP_DAYS="${KEEP_DAYS:-60}"
NODE_NAME="${NODE_NAME:-$(hostname -s)}"
NODE_TYPE="${NODE_TYPE:-worker}"
OFFSITE_ENABLED="${OFFSITE_ENABLED:-no}"
OFFSITE_REMOTE="${OFFSITE_REMOTE:-}"

ARCHIVE="${BACKUP_DIR}/wazuh-config-${NODE_NAME}-${STAMP}.tar.gz"

# ---------------------------------------------------------------------
# Журналирование в формате декодера wazuh-backup
# ---------------------------------------------------------------------
report() {
    local job="$1" target="$2" status="$3" size="${4:-0}"
    echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-backup: job=${job} target=${target} status=${status} size=${size}"
}

info() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') [ИНФО] $*"
}

fail() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') [ОШИБКА] $*" >&2
}

# ---------------------------------------------------------------------
# Копия конфигурации
# ---------------------------------------------------------------------
backup_config() {
    local paths=(
        "etc/client.keys"
        "etc/ossec.conf"
        "etc/local_internal_options.conf"
        "etc/internal_options.conf"
        "etc/authd.pass"
        "etc/rules"
        "etc/decoders"
        "etc/lists"
        "etc/shared"
        "etc/sslmanager.cert"
        "etc/sslmanager.key"
        "api/configuration"
        "active-response/bin"
        "queue/agents-timestamp"
    )

    local existing=()
    for p in "${paths[@]}"; do
        [ -e "${OSSEC_DIR}/${p}" ] && existing+=("$p")
    done

    if [ ${#existing[@]} -eq 0 ]; then
        fail "не найдено ни одного файла для копирования — это не узел Wazuh?"
        report config local error 0
        return 1
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        info "проверка: в копию попали бы ${#existing[@]} путей, архив ${ARCHIVE}"
        return 0
    fi

    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    # База состояния агентов копируется отдельно: её нельзя брать
    # на ходу, sqlite может оказаться в несогласованном состоянии.
    local tmpdir
    tmpdir="$(mktemp -d)"
    if [ -d "${OSSEC_DIR}/queue/db" ]; then
        mkdir -p "${tmpdir}/db"
        for db in "${OSSEC_DIR}"/queue/db/*.db; do
            [ -e "$db" ] || continue
            if command -v sqlite3 >/dev/null 2>&1; then
                sqlite3 "$db" ".backup '${tmpdir}/db/$(basename "$db")'" 2>/dev/null \
                    || cp -a "$db" "${tmpdir}/db/" 2>/dev/null
            else
                cp -a "$db" "${tmpdir}/db/" 2>/dev/null
            fi
        done
    fi

    if tar czf "$ARCHIVE" \
            -C "$OSSEC_DIR" "${existing[@]}" \
            -C "$tmpdir" $( [ -d "${tmpdir}/db" ] && echo db ) 2>/dev/null; then
        chmod 600 "$ARCHIVE"
        rm -rf "$tmpdir"
    else
        fail "не удалось создать архив ${ARCHIVE}"
        rm -rf "$tmpdir"
        report config local error 0
        return 1
    fi

    # Проверка целостности: непроверенный архив — это не копия,
    # а надежда на копию.
    if ! tar tzf "$ARCHIVE" >/dev/null 2>&1; then
        fail "архив ${ARCHIVE} повреждён"
        rm -f "$ARCHIVE"
        report config local error 0
        return 1
    fi

    local size
    size="$(du -h "$ARCHIVE" | cut -f1)"
    info "создан ${ARCHIVE} (${size})"
    report config local ok "$size"

    # Контрольная сумма — чтобы при восстановлении убедиться, что
    # архив доехал целым.
    sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"

    find "$BACKUP_DIR" -name 'wazuh-config-*.tar.gz*' -mtime "+${KEEP_DAYS}" -delete
    return 0
}

# ---------------------------------------------------------------------
# Выгрузка за пределы площадки
# ---------------------------------------------------------------------
offsite() {
    if [ "$OFFSITE_ENABLED" != "yes" ] || [ -z "$OFFSITE_REMOTE" ]; then
        info "выгрузка за пределы площадки отключена"
        return 0
    fi

    if ! command -v rclone >/dev/null 2>&1; then
        fail "rclone не установлен — копии остаются только на этом узле"
        report offsite "$OFFSITE_REMOTE" error 0
        return 1
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        info "проверка: выгрузка ${BACKUP_DIR} в ${OFFSITE_REMOTE}"
        rclone --config-not-found-ok lsd "${OFFSITE_REMOTE%%:*}:" >/dev/null 2>&1 \
            && info "удалённое хранилище доступно" \
            || fail "удалённое хранилище недоступно — проверить настройку rclone"
        return 0
    fi

    if rclone copy "$BACKUP_DIR" "${OFFSITE_REMOTE}/${NODE_NAME}" \
            --include 'wazuh-config-*' --transfers 2 --retries 3 2>&1; then
        local size
        size="$(du -sh "$BACKUP_DIR" | cut -f1)"
        info "копии выгружены в ${OFFSITE_REMOTE}/${NODE_NAME}"
        report offsite "$OFFSITE_REMOTE" ok "$size"
    else
        fail "выгрузка в ${OFFSITE_REMOTE} не удалась"
        report offsite "$OFFSITE_REMOTE" error 0
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------
# Свежесть снапшота индексера
#
# Проверяется отсюда намеренно: скрипт резервного копирования — то
# место, куда смотрят, когда нужно восстановиться. Если снапшотов нет,
# узнать об этом надо раньше, чем в момент восстановления.
# ---------------------------------------------------------------------
check_snapshots() {
    [ -n "${INDEXER_ADDR:-}" ] || return 0
    command -v curl >/dev/null 2>&1 || return 0

    local response last age
    response="$(curl -sk --max-time 30 \
        -u "${INDEXER_USER:-admin}:${INDEXER_PASS:-}" \
        "https://${INDEXER_ADDR}:${INDEXER_PORT:-9200}/_snapshot/${SNAPSHOT_REPO:-wazuh-snapshots}/_all?ignore_unavailable=true" 2>/dev/null)"

    if [ -z "$response" ]; then
        fail "индексер не ответил — свежесть снапшотов не проверена"
        report snapshot-check "${SNAPSHOT_REPO:-wazuh-snapshots}" error 0
        return 1
    fi

    last="$(printf '%s' "$response" | grep -o '"end_time_in_millis":[0-9]*' | tail -1 | cut -d: -f2)"
    if [ -z "$last" ]; then
        fail "в репозитории ${SNAPSHOT_REPO:-wazuh-snapshots} нет ни одного снапшота"
        report snapshot-check "${SNAPSHOT_REPO:-wazuh-snapshots}" error 0
        return 1
    fi

    age=$(( ( $(date +%s) - last / 1000 ) / 3600 ))
    if [ "$age" -gt 36 ]; then
        fail "последний снапшот индексера сделан ${age} часов назад"
        report snapshot-check "${SNAPSHOT_REPO:-wazuh-snapshots}" error "${age}h"
        return 1
    fi

    info "последний снапшот индексера: ${age} ч назад"
    report snapshot-check "${SNAPSHOT_REPO:-wazuh-snapshots}" ok "${age}h"
    return 0
}

# ---------------------------------------------------------------------
main() {
    local rc=0

    info "узел ${NODE_NAME} (${NODE_TYPE})"

    if [ "$OFFSITE_ONLY" -eq 0 ]; then
        backup_config || rc=1
    fi

    offsite || rc=1

    if [ "$OFFSITE_ONLY" -eq 0 ]; then
        check_snapshots || rc=1
    fi

    if [ "$rc" -eq 0 ]; then
        info "резервное копирование завершено"
    else
        fail "резервное копирование завершено с ошибками"
    fi
    return $rc
}

main
