#!/bin/bash
# =====================================================================
#  Проверка состояния платформы Wazuh.
#
#  Запускается с любого узла, где есть доступ к менеджеру и индексеру.
#  Ничего не меняет — только читает и показывает.
#
#  Используется в трёх случаях:
#    * приёмка после установки;
#    * еженедельный регламентный осмотр;
#    * первое, что выполняется при разборе жалобы «SIEM не работает».
#
#  Код возврата:
#    0 — всё в порядке
#    1 — есть предупреждения
#    2 — есть отказы, требующие вмешательства
#
#  Использование:
#      ./healthcheck.sh                    интерактивно, спросит пароль
#      WAZUH_PASS=... ./healthcheck.sh     без диалога, для cron
# =====================================================================

set -uo pipefail

INDEXERS=("10.5.2.81" "10.5.2.82" "10.5.2.83")
MANAGERS=("10.5.2.85" "10.5.2.86")
DASHBOARDS=("10.5.2.88" "10.5.2.89")
LOADBALANCERS=("10.5.2.92" "10.5.2.93")
VIP_AGENTS="10.5.2.90"
VIP_DASHBOARD="10.5.2.91"
SNAPSHOT_REPO="wazuh-snapshots"

INDEXER_USER="${INDEXER_USER:-admin}"
WAZUH_API_USER="${WAZUH_API_USER:-wazuh}"

WARN=0
FAIL=0

C_OK=$'\033[0;32m'
C_WARN=$'\033[0;33m'
C_ERR=$'\033[0;31m'
C_OFF=$'\033[0m'
[ -t 1 ] || { C_OK=""; C_WARN=""; C_ERR=""; C_OFF=""; }

ok()   { printf '  %sОК%s      %s\n' "$C_OK" "$C_OFF" "$1"; }
warn() { printf '  %sВНИМАНИЕ%s %s\n' "$C_WARN" "$C_OFF" "$1"; WARN=$((WARN+1)); }
err()  { printf '  %sОТКАЗ%s   %s\n' "$C_ERR" "$C_OFF" "$1"; FAIL=$((FAIL+1)); }
section() { printf '\n== %s\n' "$1"; }

if [ -z "${WAZUH_PASS:-}" ]; then
    read -rsp "Пароль ${INDEXER_USER} (индексер и API): " WAZUH_PASS
    echo
fi

# ---------------------------------------------------------------------
section "Доступность узлов"
# ---------------------------------------------------------------------
check_port() {
    local host="$1" port="$2" name="$3"
    if timeout 3 bash -c "</dev/tcp/${host}/${port}" 2>/dev/null; then
        ok "${name} ${host}:${port}"
        return 0
    fi
    err "${name} ${host}:${port} не отвечает"
    return 1
}

for h in "${INDEXERS[@]}";      do check_port "$h" 9200  "индексер"; done
for h in "${MANAGERS[@]}";      do check_port "$h" 1514  "менеджер"; done
for h in "${MANAGERS[@]}";      do check_port "$h" 55000 "API"; done
for h in "${DASHBOARDS[@]}";    do check_port "$h" 443   "дашборд"; done
for h in "${LOADBALANCERS[@]}"; do check_port "$h" 8404  "балансировщик"; done

section "Виртуальные адреса"
check_port "$VIP_AGENTS" 1514 "VIP приёма агентов"
check_port "$VIP_AGENTS" 1515 "VIP регистрации"
check_port "$VIP_DASHBOARD" 443 "VIP дашборда"

# ---------------------------------------------------------------------
section "Кластер индексера"
# ---------------------------------------------------------------------
IDX="${INDEXERS[0]}"
HEALTH=$(curl -sk --max-time 15 -u "${INDEXER_USER}:${WAZUH_PASS}" \
         "https://${IDX}:9200/_cluster/health" 2>/dev/null)

if [ -z "$HEALTH" ]; then
    err "индексер не ответил на запрос состояния"
else
    STATUS=$(printf '%s' "$HEALTH" | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')
    NODES=$(printf '%s' "$HEALTH" | sed -n 's/.*"number_of_nodes":\([0-9]*\).*/\1/p')
    UNASSIGNED=$(printf '%s' "$HEALTH" | sed -n 's/.*"unassigned_shards":\([0-9]*\).*/\1/p')

    case "$STATUS" in
        green)  ok "состояние кластера: green" ;;
        yellow) warn "состояние кластера: yellow — реплики не размещены, избыточности нет" ;;
        red)    err "состояние кластера: red — часть данных недоступна" ;;
        *)      err "состояние кластера не определено" ;;
    esac

    if [ "${NODES:-0}" -eq "${#INDEXERS[@]}" ]; then
        ok "узлов в кластере: ${NODES} из ${#INDEXERS[@]}"
    else
        err "узлов в кластере: ${NODES:-0} из ${#INDEXERS[@]} — потеря узла"
    fi

    [ "${UNASSIGNED:-0}" -eq 0 ] \
        && ok "нераспределённых шардов нет" \
        || warn "нераспределённых шардов: ${UNASSIGNED}"

    # Место на дисках: заполнение выше 85 процентов останавливает запись.
    DISK=$(curl -sk --max-time 15 -u "${INDEXER_USER}:${WAZUH_PASS}" \
           "https://${IDX}:9200/_cat/allocation?h=node,disk.percent" 2>/dev/null)
    while read -r node pct; do
        [ -z "${pct:-}" ] && continue
        if [ "$pct" -ge 85 ]; then
            err "диск узла ${node} заполнен на ${pct}% — запись будет остановлена"
        elif [ "$pct" -ge 75 ]; then
            warn "диск узла ${node} заполнен на ${pct}%"
        else
            ok "диск узла ${node}: ${pct}%"
        fi
    done <<< "$DISK"
fi

# ---------------------------------------------------------------------
section "Поток событий"
# ---------------------------------------------------------------------
COUNT=$(curl -sk --max-time 20 -u "${INDEXER_USER}:${WAZUH_PASS}" \
        -H 'Content-Type: application/json' \
        "https://${IDX}:9200/wazuh-alerts-*/_count" \
        -d '{"query":{"range":{"@timestamp":{"gte":"now-1h"}}}}' 2>/dev/null \
        | sed -n 's/.*"count":\([0-9]*\).*/\1/p')

if [ -z "$COUNT" ]; then
    err "не удалось получить число алертов за час"
elif [ "$COUNT" -eq 0 ]; then
    err "за последний час не сохранено ни одного алерта — проверить filebeat на менеджерах"
elif [ "$COUNT" -lt 10 ]; then
    warn "за последний час всего ${COUNT} алертов — подозрительно мало"
else
    ok "алертов за последний час: ${COUNT}"
fi

# ---------------------------------------------------------------------
section "Кластер менеджеров и агенты"
# ---------------------------------------------------------------------
TOKEN=$(curl -sk --max-time 15 -u "${WAZUH_API_USER}:${WAZUH_PASS}" -X POST \
        "https://${MANAGERS[0]}:55000/security/user/authenticate?raw=true" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    warn "не удалось получить токен Wazuh API (пароль API может отличаться от пароля индексера)"
else
    NODES=$(curl -sk --max-time 15 -H "Authorization: Bearer ${TOKEN}" \
            "https://${MANAGERS[0]}:55000/cluster/nodes" 2>/dev/null \
            | grep -o '"type"' | wc -l)
    if [ "$NODES" -eq "${#MANAGERS[@]}" ]; then
        ok "узлов в кластере менеджеров: ${NODES}"
    else
        err "узлов в кластере менеджеров: ${NODES} из ${#MANAGERS[@]}"
    fi

    SUM=$(curl -sk --max-time 15 -H "Authorization: Bearer ${TOKEN}" \
          "https://${MANAGERS[0]}:55000/agents/summary/status" 2>/dev/null)
    A=$(printf '%s' "$SUM" | sed -n 's/.*"active":\([0-9]*\).*/\1/p')
    D=$(printf '%s' "$SUM" | sed -n 's/.*"disconnected":\([0-9]*\).*/\1/p')
    N=$(printf '%s' "$SUM" | sed -n 's/.*"never_connected":\([0-9]*\).*/\1/p')
    T=$(printf '%s' "$SUM" | sed -n 's/.*"total":\([0-9]*\).*/\1/p')

    if [ -n "${T:-}" ] && [ "${T:-0}" -gt 0 ]; then
        ok "агентов активно: ${A:-0} из ${T}"
        [ "${D:-0}" -gt 0 ] && warn "отключено агентов: ${D}"
        [ "${N:-0}" -gt 0 ] && warn "ни разу не подключались: ${N}"
        LIMIT=$(( T * 5 / 100 ))
        [ "${D:-0}" -gt "$LIMIT" ] && err "отключено более 5% агентов"
    else
        warn "не удалось получить сводку по агентам"
    fi
fi

# ---------------------------------------------------------------------
section "Резервное копирование"
# ---------------------------------------------------------------------
SNAPS=$(curl -sk --max-time 30 -u "${INDEXER_USER}:${WAZUH_PASS}" \
        "https://${IDX}:9200/_snapshot/${SNAPSHOT_REPO}/_all?ignore_unavailable=true" 2>/dev/null)
LAST=$(printf '%s' "$SNAPS" | grep -o '"end_time_in_millis":[0-9]*' | tail -1 | cut -d: -f2)

if [ -z "$LAST" ]; then
    err "в репозитории ${SNAPSHOT_REPO} нет снапшотов"
else
    AGE=$(( ( $(date +%s) - LAST / 1000 ) / 3600 ))
    if [ "$AGE" -le 26 ]; then
        ok "последний снапшот сделан ${AGE} ч назад"
    elif [ "$AGE" -le 48 ]; then
        warn "последний снапшот сделан ${AGE} ч назад"
    else
        err "последний снапшот сделан ${AGE} ч назад — резервного копирования фактически нет"
    fi

    FAILED=$(printf '%s' "$SNAPS" | grep -c '"state":"FAILED"')
    [ "$FAILED" -gt 0 ] && warn "снапшотов со статусом FAILED: ${FAILED}"
fi

# ---------------------------------------------------------------------
printf '\n=====================================================\n'
if [ "$FAIL" -gt 0 ]; then
    printf '%sОтказов: %d, предупреждений: %d%s\n' "$C_ERR" "$FAIL" "$WARN" "$C_OFF"
    printf 'Порядок разбора: docs/11-troubleshooting.md\n'
    exit 2
elif [ "$WARN" -gt 0 ]; then
    printf '%sПредупреждений: %d, отказов нет%s\n' "$C_WARN" "$WARN" "$C_OFF"
    exit 1
else
    printf '%sПлатформа в порядке%s\n' "$C_OK" "$C_OFF"
    exit 0
fi
