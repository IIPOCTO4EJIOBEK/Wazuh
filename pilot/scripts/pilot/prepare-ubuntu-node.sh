#!/bin/bash
# =====================================================================
#  Подготовка чистой Ubuntu 24.04 к развёртыванию Wazuh.
#
#  Делает всё, что должно быть сделано до запуска Ansible:
#    разметка и монтирование отдельных томов по UUID,
#    имя узла, синхронизация времени,
#    учётная запись ansible с ключом и sudo без пароля,
#    обновление пакетов.
#
#  Идемпотентен: повторный запуск на подготовленной машине ничего не
#  ломает и не переразмечает диски.
#
#  ЗАПУСКАТЬ НА САМОЙ МАШИНЕ, от root:
#
#      ./prepare-ubuntu-node.sh \
#          --indexer-disk /dev/sdb \
#          --ossec-disk   /dev/sdc \
#          --ssh-key      "ssh-ed25519 AAAA... ansible@mgmt" \
#          --hostname     wazuh-pilot \
#          --ntp          10.0.2.10
#
#  Ключ можно передать файлом:  --ssh-key-file /tmp/ansible.pub
#
#  Форматирование дисков необратимо, поэтому скрипт отказывается
#  трогать диск, на котором уже есть файловая система или разделы.
#  Осознанная переразметка — с ключом --force.
# =====================================================================

set -uo pipefail

INDEXER_DISK=""
OSSEC_DISK=""
SSH_KEY=""
SSH_KEY_FILE=""
NODE_NAME="wazuh-pilot"
NTP_SERVER=""
ANSIBLE_USER="ansible"
FORCE=0
SKIP_UPGRADE=0

INDEXER_MOUNT="/var/lib/wazuh-indexer"
OSSEC_MOUNT="/var/ossec"

C_OK=$'\033[0;32m'; C_WARN=$'\033[0;33m'; C_ERR=$'\033[0;31m'; C_OFF=$'\033[0m'
[ -t 1 ] || { C_OK=""; C_WARN=""; C_ERR=""; C_OFF=""; }

ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_OFF" "$1"; }
die()  { printf '\n%sОШИБКА:%s %s\n' "$C_ERR" "$C_OFF" "$1" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

usage() { sed -n '2,32p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --indexer-disk) INDEXER_DISK="${2:-}"; shift 2 ;;
        --ossec-disk)   OSSEC_DISK="${2:-}";   shift 2 ;;
        --ssh-key)      SSH_KEY="${2:-}";      shift 2 ;;
        --ssh-key-file) SSH_KEY_FILE="${2:-}"; shift 2 ;;
        --hostname)     NODE_NAME="${2:-}";    shift 2 ;;
        --ntp)          NTP_SERVER="${2:-}";   shift 2 ;;
        --user)         ANSIBLE_USER="${2:-}"; shift 2 ;;
        --force)        FORCE=1; shift ;;
        --skip-upgrade) SKIP_UPGRADE=1; shift ;;
        -h|--help)      usage 0 ;;
        *) echo "Неизвестный параметр: $1" >&2; usage 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "нужны права root"

[ -n "$INDEXER_DISK" ] || die "не указан --indexer-disk (том 250 ГБ под индексы)"
[ -n "$OSSEC_DISK" ]   || die "не указан --ossec-disk (том 100 ГБ под менеджер)"

if [ -z "$SSH_KEY" ] && [ -n "$SSH_KEY_FILE" ]; then
    [ -r "$SSH_KEY_FILE" ] || die "файл ключа недоступен: $SSH_KEY_FILE"
    SSH_KEY="$(cat "$SSH_KEY_FILE")"
fi
[ -n "$SSH_KEY" ] || die "не указан открытый ключ (--ssh-key или --ssh-key-file)"

case "$SSH_KEY" in
    ssh-rsa\ *|ssh-ed25519\ *|ecdsa-sha2-*) : ;;
    *) die "строка не похожа на открытый ключ SSH" ;;
esac

# ---------------------------------------------------------------------
step "1. Проверка дисков"
# ---------------------------------------------------------------------
root_disk="$(lsblk -no PKNAME "$(findmnt -no SOURCE /)" 2>/dev/null | head -1)"

check_disk() {
    local dev="$1" label="$2"

    [ -b "$dev" ] || die "$dev не является блочным устройством"

    local name; name="$(basename "$dev")"
    if [ -n "$root_disk" ] && [ "$name" = "$root_disk" ]; then
        die "$dev — системный диск. Отказываюсь размечать."
    fi

    if findmnt -S "$dev" >/dev/null 2>&1; then
        local mp; mp="$(findmnt -no TARGET -S "$dev" | head -1)"
        if [ "$mp" = "$label" ]; then
            ok "$dev уже смонтирован в $label"
            return 1        # уже готов, размечать не надо
        fi
        die "$dev смонтирован в $mp — не тот том"
    fi

    local fstype; fstype="$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)"
    local parts;  parts="$(lsblk -no NAME "$dev" | tail -n +2 | wc -l)"

    if { [ -n "$fstype" ] || [ "$parts" -gt 0 ]; } && [ "$FORCE" -eq 0 ]; then
        die "на $dev уже есть данные (тип: ${fstype:-разделы}). Проверьте диск; осознанная переразметка — с --force"
    fi

    local size; size="$(lsblk -bdno SIZE "$dev")"
    ok "$dev готов к разметке ($(numfmt --to=iec "$size"))"
    return 0
}

need_format_indexer=0; check_disk "$INDEXER_DISK" "$INDEXER_MOUNT" && need_format_indexer=1
need_format_ossec=0;   check_disk "$OSSEC_DISK"   "$OSSEC_MOUNT"   && need_format_ossec=1

# ---------------------------------------------------------------------
step "2. Разметка и монтирование"
# ---------------------------------------------------------------------
if ! command -v mkfs.xfs >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq xfsprogs >/dev/null
fi

mount_by_uuid() {
    local dev="$1" mp="$2" do_format="$3"

    if [ "$do_format" -eq 1 ]; then
        mkfs.xfs -f -q "$dev" || die "не удалось создать файловую систему на $dev"
        ok "файловая система создана на $dev"
    fi

    mkdir -p "$mp"

    local uuid; uuid="$(blkid -o value -s UUID "$dev")"
    [ -n "$uuid" ] || die "не удалось получить UUID для $dev"

    # Монтирование по UUID, а не по имени: sdb и sdc могут поменяться
    # местами после перезагрузки, и данные окажутся не на своём месте.
    sed -i "\|[[:space:]]${mp}[[:space:]]|d" /etc/fstab
    echo "UUID=${uuid}  ${mp}  xfs  defaults,noatime  0 2" >> /etc/fstab

    mountpoint -q "$mp" || mount "$mp" || die "не удалось смонтировать $mp"
    ok "$mp смонтирован (UUID=${uuid})"
}

mount_by_uuid "$INDEXER_DISK" "$INDEXER_MOUNT" "$need_format_indexer"
mount_by_uuid "$OSSEC_DISK"   "$OSSEC_MOUNT"   "$need_format_ossec"

# Проверка, что после перезагрузки всё встанет на место
mount -a || die "/etc/fstab содержит ошибку — исправьте до перезагрузки"
ok "/etc/fstab проверен командой mount -a"

# ---------------------------------------------------------------------
step "3. Имя узла"
# ---------------------------------------------------------------------
if [ "$(hostnamectl --static)" != "$NODE_NAME" ]; then
    hostnamectl set-hostname "$NODE_NAME"
    ok "имя узла: $NODE_NAME"
else
    ok "имя узла уже $NODE_NAME"
fi

if ! grep -qE "^127\.0\.1\.1[[:space:]]+${NODE_NAME}\b" /etc/hosts; then
    sed -i '/^127\.0\.1\.1/d' /etc/hosts
    echo "127.0.1.1 ${NODE_NAME}" >> /etc/hosts
    ok "запись в /etc/hosts добавлена"
fi

# ---------------------------------------------------------------------
step "4. Синхронизация времени"
# ---------------------------------------------------------------------
# Расхождение часов ломает корреляцию: подбор пароля и последующий вход
# окажутся в журнале в обратном порядке.
if ! dpkg -s chrony >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq chrony >/dev/null
    ok "chrony установлен"
fi

if [ -n "$NTP_SERVER" ]; then
    cat > /etc/chrony/conf.d/wazuh.conf <<EOF
# Тот же источник времени, что у контроллеров домена.
# Управляется prepare-ubuntu-node.sh
server ${NTP_SERVER} iburst prefer
EOF
    ok "источник времени: ${NTP_SERVER}"
fi

timedatectl set-timezone Europe/Moscow
systemctl enable --now chrony >/dev/null 2>&1
systemctl restart chrony

printf '  ждём синхронизации'
for _ in $(seq 1 30); do
    [ "$(timedatectl show -p NTPSynchronized --value)" = "yes" ] && break
    printf '.'; sleep 2
done
printf '\n'

if [ "$(timedatectl show -p NTPSynchronized --value)" = "yes" ]; then
    ok "время синхронизировано: $(date '+%d.%m.%Y %H:%M:%S %Z')"
else
    warn "синхронизация не подтвердилась за минуту — проверьте доступность источника"
    chronyc sources 2>/dev/null | head -5
fi

# ---------------------------------------------------------------------
step "5. Учётная запись для Ansible"
# ---------------------------------------------------------------------
if ! id "$ANSIBLE_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$ANSIBLE_USER"
    ok "учётная запись $ANSIBLE_USER создана"
else
    ok "учётная запись $ANSIBLE_USER уже есть"
fi

home="$(getent passwd "$ANSIBLE_USER" | cut -d: -f6)"
install -d -m 0700 -o "$ANSIBLE_USER" -g "$ANSIBLE_USER" "$home/.ssh"
touch "$home/.ssh/authorized_keys"

if ! grep -qxF "$SSH_KEY" "$home/.ssh/authorized_keys"; then
    echo "$SSH_KEY" >> "$home/.ssh/authorized_keys"
    ok "ключ добавлен"
else
    ok "ключ уже добавлен"
fi
chmod 0600 "$home/.ssh/authorized_keys"
chown "$ANSIBLE_USER:$ANSIBLE_USER" "$home/.ssh/authorized_keys"

cat > "/etc/sudoers.d/90-${ANSIBLE_USER}" <<EOF
${ANSIBLE_USER} ALL=(ALL) NOPASSWD:ALL
EOF
chmod 0440 "/etc/sudoers.d/90-${ANSIBLE_USER}"

visudo -c -q -f "/etc/sudoers.d/90-${ANSIBLE_USER}" \
    || die "файл sudoers не прошёл проверку"
ok "sudo без пароля настроен"

# ---------------------------------------------------------------------
step "6. Обновление пакетов"
# ---------------------------------------------------------------------
if [ "$SKIP_UPGRADE" -eq 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq >/dev/null
    ok "пакеты обновлены"
    [ -f /var/run/reboot-required ] && warn "требуется перезагрузка — выполните её до установки Wazuh"
else
    warn "обновление пропущено по ключу --skip-upgrade"
fi

# ---------------------------------------------------------------------
step "Итог"
# ---------------------------------------------------------------------
echo
df -h "$INDEXER_MOUNT" "$OSSEC_MOUNT" / | sed 's/^/  /'
echo
printf '  Имя узла:   %s\n' "$(hostnamectl --static)"
printf '  Адреса:     %s\n' "$(hostname -I | xargs)"
printf '  Время:      %s (синхронизировано: %s)\n' \
       "$(date '+%d.%m.%Y %H:%M:%S')" "$(timedatectl show -p NTPSynchronized --value)"
echo
echo "  Проверить с управляющей машины:"
printf '      ssh %s@%s sudo -n true && echo ДОСТУП ЕСТЬ\n' \
       "$ANSIBLE_USER" "$(hostname -I | awk '{print $1}')"
echo
echo "  Дальше — развёртывание:"
echo "      ansible-playbook -i inventory/pilot/hosts.yml site.yml --ask-vault-pass"
echo
