#!/bin/bash
# =====================================================================
#  Установка агента Wazuh на Linux-узел.
#
#  Штатный способ раскатки — Ansible (playbooks/agents-linux.yml).
#  Этот скрипт нужен там, где Ansible не дотягивается: узлы вне
#  инвентаря, машины подрядчиков, разовая установка руками.
#
#  Идемпотентен: на уже настроенном узле ничего не меняет.
#
#  Использование:
#      sudo ./install-wazuh-agent.sh --password 'пароль'
#      sudo ./install-wazuh-agent.sh --password 'пароль' --groups 'default,linux,dmz'
#
#  Группы, если не указаны, определяются по установленным службам.
# =====================================================================

set -uo pipefail

MANAGER="10.5.2.90"
VERSION="4.14.7"
GROUPS=""
PASSWORD=""
FORCE=0

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "[$(date '+%H:%M:%S')] ОШИБКА: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --manager)  MANAGER="${2:-}"; shift 2 ;;
        --password) PASSWORD="${2:-}"; shift 2 ;;
        --groups)   GROUPS="${2:-}"; shift 2 ;;
        --version)  VERSION="${2:-}"; shift 2 ;;
        --force)    FORCE=1; shift ;;
        -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
        *) fail "неизвестный параметр: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "нужны права root"

# ---------------------------------------------------------------------
# Определение групп по установленным службам.
# От группы зависит, какие журналы будет читать агент, поэтому лучше
# определить её автоматически, чем поставить всем default и потом
# годами не понимать, почему в SIEM нет журналов nginx.
# ---------------------------------------------------------------------
detect_groups() {
    local g="default,linux"

    if [ -d /home/bitrix/www ]; then
        g="${g},bitrix-web"
    fi
    if systemctl is-enabled haproxy >/dev/null 2>&1 || [ -f /etc/haproxy/haproxy.cfg ]; then
        g="${g},dmz"
    fi
    if systemctl is-enabled nginx >/dev/null 2>&1 && [ -d /data/nginx ]; then
        g="${g},dmz"
    fi
    if systemctl is-enabled mysql >/dev/null 2>&1 || systemctl is-enabled mariadb >/dev/null 2>&1; then
        g="${g},database"
    fi

    echo "$g"
}

# ---------------------------------------------------------------------
if [ -x /var/ossec/bin/wazuh-control ] && [ "$FORCE" -eq 0 ]; then
    installed="$(cat /var/ossec/etc/VERSION 2>/dev/null | tr -d 'v' | tr -d '\n')"
    if [ "$installed" = "$VERSION" ]; then
        log "агент версии ${VERSION} уже установлен, выхожу"
        exit 0
    fi
    log "установлена версия ${installed:-неизвестна}, требуется ${VERSION} — обновляю"
fi

[ -n "$PASSWORD" ] || fail "не указан пароль регистрации (--password)"

[ -n "$GROUPS" ] || GROUPS="$(detect_groups)"
log "группы агента: ${GROUPS}"

# --- Репозиторий ------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    log "настраиваю репозиторий (apt)"
    apt-get install -y curl gnupg apt-transport-https >/dev/null
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq

    log "устанавливаю агент ${VERSION}"
    WAZUH_MANAGER="$MANAGER" \
    WAZUH_REGISTRATION_SERVER="$MANAGER" \
    WAZUH_REGISTRATION_PASSWORD="$PASSWORD" \
    WAZUH_AGENT_NAME="$(hostname -s)" \
    WAZUH_AGENT_GROUP="$GROUPS" \
    WAZUH_PROTOCOL="tcp" \
    apt-get install -y "wazuh-agent=${VERSION}-1" || fail "установка не удалась"

    apt-mark hold wazuh-agent >/dev/null

elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PKG=$(command -v dnf || command -v yum)
    log "настраиваю репозиторий (rpm)"
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

    log "устанавливаю агент ${VERSION}"
    WAZUH_MANAGER="$MANAGER" \
    WAZUH_REGISTRATION_SERVER="$MANAGER" \
    WAZUH_REGISTRATION_PASSWORD="$PASSWORD" \
    WAZUH_AGENT_NAME="$(hostname -s)" \
    WAZUH_AGENT_GROUP="$GROUPS" \
    WAZUH_PROTOCOL="tcp" \
    "$PKG" install -y "wazuh-agent-${VERSION}" || fail "установка не удалась"

else
    fail "не найден поддерживаемый пакетный менеджер (apt/dnf/yum)"
fi

# --- Запуск -----------------------------------------------------------
systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null 2>&1
systemctl restart wazuh-agent

log "жду подключения к менеджеру..."
connected=0
for _ in $(seq 1 24); do
    sleep 5
    if grep -q "Connected to the server" /var/ossec/logs/ossec.log 2>/dev/null; then
        connected=1
        break
    fi
    if grep -qE "Invalid password|Unable to add agent" /var/ossec/logs/ossec.log 2>/dev/null; then
        fail "регистрация отклонена менеджером: неверный пароль или имя занято"
    fi
done

if [ "$connected" -eq 1 ]; then
    log "агент подключён к ${MANAGER}"
    log "идентификатор агента: $(cut -d' ' -f1 /var/ossec/etc/client.keys 2>/dev/null | head -1)"
    exit 0
fi

log "агент установлен, но подключение за 2 минуты не подтверждено"
log "проверить: доступность ${MANAGER}:1514 и ${MANAGER}:1515, журнал /var/ossec/logs/ossec.log"
exit 1
