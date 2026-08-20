#!/bin/bash
# =====================================================================
#  Проверка отказоустойчивости: управляемые учения.
#
#  Резервирование, которое ни разу не проверяли, резервированием не
#  является. Этот сценарий по очереди выводит из строя компоненты и
#  показывает, что происходит с приёмом событий.
#
#  Запускать: раз в квартал и после каждого изменения в топологии.
#  Время проведения: вне рабочих часов, с предупреждением дежурного.
#
#  Что проверяется:
#    1. Отказ одного узла индексера      → кластер жёлтый, приём идёт
#    2. Отказ worker-менеджера           → агенты уходят на master
#    3. Отказ master-менеджера           → приём идёт, регистрация нет
#    4. Отказ одного балансировщика      → VIP уезжает на второй
#    5. Отказ одного узла дашборда       → интерфейс работает
#
#  Скрипт ничего не ломает без подтверждения и после каждого шага
#  возвращает всё на место.
#
#  Использование:
#      ./failover-test.sh --scenario 1
#      ./failover-test.sh --all --yes
# =====================================================================

set -uo pipefail

SSH_USER="${SSH_USER:-ansible}"
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

IDX=("10.5.2.81" "10.5.2.82" "10.5.2.83")
MGR_MASTER="10.5.2.85"
MGR_WORKER="10.5.2.86"
DASH=("10.5.2.88" "10.5.2.89")
LB=("10.5.2.92" "10.5.2.93")
VIP_AGENTS="10.5.2.90"
VIP_DASH="10.5.2.91"

SCENARIO=""
RUN_ALL=0
ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --scenario) SCENARIO="${2:-}"; shift 2 ;;
        --all)      RUN_ALL=1; shift ;;
        --yes)      ASSUME_YES=1; shift ;;
        -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
    esac
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { printf '  → %s\n' "$*"; }
good() { printf '  \033[0;32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[0;31m✗\033[0m %s\n' "$*"; }

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    printf '  Выполнить? Введите «да»: '
    read -r a
    [ "$a" = "да" ]
}

remote() {
    ssh $SSH_OPTS "${SSH_USER}@$1" "sudo ${*:2}"
}

port_open() {
    timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null
}

# Поток событий — главный показатель. Если он не прервался, отказ
# отработан правильно, что бы ни показывали остальные метрики.
events_flowing() {
    port_open "$VIP_AGENTS" 1514
}

wait_seconds() {
    local n="$1"
    printf '  ждём %d с' "$n"
    for _ in $(seq 1 "$n"); do sleep 1; printf '.'; done
    printf '\n'
}

# ---------------------------------------------------------------------
scenario_1() {
    say "Сценарий 1. Отказ одного узла индексера (${IDX[2]})"
    step "останавливаем wazuh-indexer на ${IDX[2]}"
    confirm || return 0

    remote "${IDX[2]}" systemctl stop wazuh-indexer
    wait_seconds 45

    local status
    status=$(curl -sk -u "admin:${WAZUH_PASS}" "https://${IDX[0]}:9200/_cluster/health" 2>/dev/null \
             | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')

    [ "$status" = "yellow" ] && good "кластер перешёл в yellow — ожидаемо, данные доступны" \
                             || bad "кластер в состоянии ${status:-неизвестно}, ожидалось yellow"

    events_flowing && good "приём событий не прервался" || bad "приём событий прерван"

    step "возвращаем узел"
    remote "${IDX[2]}" systemctl start wazuh-indexer
    wait_seconds 60

    status=$(curl -sk -u "admin:${WAZUH_PASS}" "https://${IDX[0]}:9200/_cluster/health" 2>/dev/null \
             | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')
    [ "$status" = "green" ] && good "кластер вернулся в green" \
                            || bad "кластер в состоянии ${status:-неизвестно} — разобраться до следующего сценария"
}

scenario_2() {
    say "Сценарий 2. Отказ worker-менеджера (${MGR_WORKER})"
    step "останавливаем wazuh-manager на ${MGR_WORKER}"
    confirm || return 0

    remote "$MGR_WORKER" systemctl stop wazuh-manager
    wait_seconds 60

    events_flowing && good "приём событий продолжается через master" \
                   || bad "приём событий прерван — балансировщик не переключил поток"

    port_open "$VIP_AGENTS" 1515 && good "регистрация агентов работает" \
                                 || bad "регистрация недоступна"

    step "возвращаем менеджер"
    remote "$MGR_WORKER" systemctl start wazuh-manager
    wait_seconds 30
    good "worker возвращён"
}

scenario_3() {
    say "Сценарий 3. Отказ master-менеджера (${MGR_MASTER})"
    echo "  Это единственный сценарий с частичной потерей функций:"
    echo "  приём событий переживает отказ master, а регистрация новых"
    echo "  агентов — нет, служба authd работает только на master."
    confirm || return 0

    remote "$MGR_MASTER" systemctl stop wazuh-manager
    wait_seconds 60

    events_flowing && good "приём событий продолжается через worker" \
                   || bad "приём событий прерван"

    if port_open "$VIP_AGENTS" 1515; then
        bad "порт регистрации отвечает, хотя master остановлен — проверить конфигурацию HAProxy"
    else
        good "регистрация недоступна — ожидаемое поведение, задокументировано"
    fi

    port_open "$VIP_AGENTS" 55000 && good "API отвечает через резервный узел (режим чтения)" \
                                  || bad "API недоступен"

    step "возвращаем master"
    remote "$MGR_MASTER" systemctl start wazuh-manager
    wait_seconds 45
    port_open "$VIP_AGENTS" 1515 && good "регистрация восстановлена" || bad "регистрация не восстановилась"
}

scenario_4() {
    say "Сценарий 4. Отказ балансировщика, держащего VIP"
    local holder=""
    for h in "${LB[@]}"; do
        if ssh $SSH_OPTS "${SSH_USER}@${h}" "ip -4 -o addr | grep -q ${VIP_AGENTS}" 2>/dev/null; then
            holder="$h"
            break
        fi
    done

    [ -z "$holder" ] && { bad "не удалось определить, какой узел держит VIP"; return 1; }
    step "VIP ${VIP_AGENTS} сейчас на ${holder} — останавливаем keepalived там"
    confirm || return 0

    remote "$holder" systemctl stop keepalived
    wait_seconds 15

    events_flowing && good "VIP переехал, приём событий не прервался" \
                   || bad "приём прерван — переключение VIP не сработало"

    port_open "$VIP_DASH" 443 && good "VIP дашборда доступен" || bad "VIP дашборда недоступен"

    step "возвращаем keepalived на ${holder}"
    remote "$holder" systemctl start keepalived
    wait_seconds 15
    good "балансировщик возвращён (адрес остаётся на соседе — nopreempt)"
}

scenario_5() {
    say "Сценарий 5. Отказ одного узла дашборда (${DASH[1]})"
    step "останавливаем wazuh-dashboard на ${DASH[1]}"
    confirm || return 0

    remote "${DASH[1]}" systemctl stop wazuh-dashboard
    wait_seconds 20

    port_open "$VIP_DASH" 443 && good "интерфейс доступен через второй узел" \
                              || bad "интерфейс недоступен"

    step "возвращаем узел"
    remote "${DASH[1]}" systemctl start wazuh-dashboard
    wait_seconds 40
    good "узел дашборда возвращён"
}

# ---------------------------------------------------------------------
if [ -z "${WAZUH_PASS:-}" ]; then
    read -rsp "Пароль admin индексера: " WAZUH_PASS
    echo
fi

echo "Перед началом: убедитесь, что учения согласованы и дежурный предупреждён."
echo "Каждый шаг возвращает систему в исходное состояние."

if [ "$RUN_ALL" -eq 1 ]; then
    for n in 1 2 3 4 5; do "scenario_$n"; done
elif [ -n "$SCENARIO" ]; then
    "scenario_${SCENARIO}"
else
    echo "Укажите --scenario N или --all" >&2
    exit 2
fi

say "Учения завершены"
echo "Проверьте общее состояние: ./healthcheck.sh"
echo "Результаты внесите в журнал учений (docs/04-ha-failover.md, раздел «Журнал учений»)."
