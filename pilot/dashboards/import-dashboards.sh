#!/bin/bash
# =====================================================================
#  Загрузка сохранённых объектов на дашборд Wazuh.
#
#  Обычно это делает Ansible (тег saved-objects). Скрипт нужен для
#  ручной загрузки: после правки build_saved_objects.py, при переносе
#  на другой стенд или при восстановлении дашборда из копии.
#
#  Использование:
#      ./import-dashboards.sh [адрес] [пользователь]
#
#  Пример:
#      ./import-dashboards.sh wazuh.ahprostory.ru admin
#
#  Пароль спрашивается в диалоге и в истории команд не остаётся.
# =====================================================================

set -euo pipefail

HOST="${1:-wazuh.ahprostory.ru}"
USER="${2:-admin}"
FILE="$(dirname "$0")/ahp-soc-dashboards.ndjson"
PORT="${DASHBOARD_PORT:-443}"

if [ ! -r "$FILE" ]; then
    echo "Не найден $FILE. Сначала выполните: python3 build_saved_objects.py" >&2
    exit 1
fi

# Проверка, что файл собран корректно: импорт битого ndjson оставляет
# дашборд в наполовину обновлённом состоянии.
if ! python3 -c "
import json,sys
for line in open('$FILE', encoding='utf-8'):
    if line.strip():
        json.loads(line)
" 2>/dev/null; then
    echo "Файл $FILE содержит некорректный JSON. Импорт отменён." >&2
    exit 1
fi

read -rsp "Пароль $USER: " PASSWORD
echo

echo "Импорт в https://${HOST}:${PORT} ..."

RESPONSE=$(curl -sk \
    -X POST "https://${HOST}:${PORT}/api/saved_objects/_import?overwrite=true" \
    -u "${USER}:${PASSWORD}" \
    -H "osd-xsrf: true" \
    --form "file=@${FILE}")

unset PASSWORD

SUCCESS=$(printf '%s' "$RESPONSE" | python3 -c "
import json,sys
try:
    data = json.load(sys.stdin)
except ValueError:
    print('parse-error'); sys.exit()
print('ok' if data.get('success') else 'fail')
print(data.get('successCount', 0))
for err in data.get('errors', [])[:10]:
    print('  ошибка:', err.get('id'), err.get('error', {}).get('type'))
")

STATUS=$(printf '%s' "$SUCCESS" | head -1)
COUNT=$(printf '%s' "$SUCCESS" | sed -n 2p)

case "$STATUS" in
    ok)
        echo "Импортировано объектов: $COUNT"
        echo
        echo "Дашборды доступны здесь:"
        echo "  https://${HOST}/app/dashboards"
        echo "    AH Prostory — обзор SOC"
        echo "    AH Prostory — инфраструктура и реагирование"
        echo "    AH Prostory — уязвимости"
        ;;
    fail)
        echo "Импорт завершился с ошибками:" >&2
        printf '%s\n' "$SUCCESS" | tail -n +3 >&2
        exit 1
        ;;
    *)
        echo "Неожиданный ответ сервера:" >&2
        printf '%s\n' "$RESPONSE" | head -c 500 >&2
        exit 1
        ;;
esac
