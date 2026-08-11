#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 Создание заявки в ServiceDesk Plus по алерту Wazuh.

 Запускается wazuh-integratord: он передаёт путь к файлу с алертом
 первым аргументом. Порог уровня задан в ossec.conf (<level>), здесь
 проверяется повторно — на случай ручного запуска.

 Почему заявка, а не письмо: в компании уже работает ServiceDesk Plus
 (support.uk-n.ru), в нём ведётся учёт работ и есть сроки реакции.
 Инцидент безопасности, оформленный письмом, не имеет ни владельца,
 ни срока, и теряется вместе с письмом.

 Защита от лавины заявок: одинаковые алерты (одно правило + один узел)
 в течение окна подавления не создают новую заявку, а дописываются
 комментарием к уже открытой. Без этого одна атака перебором создаёт
 сотню заявок и хоронит очередь поддержки.

 Проверка вручную:
     /var/ossec/integrations/custom-servicedesk /tmp/alert.json
=====================================================================
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ENV_FILE = "/var/ossec/etc/integrations.env"
STATE_FILE = "/var/ossec/var/run/servicedesk-dedup.json"
LOG_FILE = "/var/ossec/logs/integrations.log"

# Окно подавления повторов, секунды
DEDUP_WINDOW = 3600

# Соответствие уровня Wazuh и приоритета заявки
PRIORITY_MAP = {
    15: "Критический",
    14: "Высокий",
    13: "Высокий",
    12: "Средний",
}


def log(message):
    stamp = time.strftime("%Y/%m/%d %H:%M:%S")
    line = "{} custom-servicedesk: {}\n".format(stamp, message)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        sys.stderr.write(line)


def read_env(path=ENV_FILE):
    """Разбор файла вида KEY="value" без запуска shell."""
    env = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    except OSError as error:
        log("не прочитан {}: {}".format(path, error))
    return env


def load_alert(path):
    with open(path, encoding="utf-8") as handle:
        content = handle.read().strip()
    # integratord может передать несколько строк JSON
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise ValueError("в файле нет JSON алерта")


def dedup_key(alert):
    rule_id = alert.get("rule", {}).get("id", "0")
    agent = alert.get("agent", {}).get("name", "manager")
    return "{}::{}".format(rule_id, agent)


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_state(state):
    now = time.time()
    # Чистим просроченные записи, чтобы файл не рос бесконечно
    state = {k: v for k, v in state.items() if now - v.get("time", 0) < DEDUP_WINDOW * 4}
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
    except OSError as error:
        log("не сохранено состояние подавления повторов: {}".format(error))


def build_description(alert, dashboard_url):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    lines = [
        "Инцидент зафиксирован системой Wazuh.",
        "",
        "Правило:        {} (уровень {})".format(rule.get("id", "?"), rule.get("level", "?")),
        "Описание:       {}".format(rule.get("description", "")),
        "Узел:           {} ({})".format(agent.get("name", "менеджер"), agent.get("ip", "-")),
        "Время события:  {}".format(alert.get("timestamp", "")),
        "Менеджер:       {}".format(alert.get("manager", {}).get("name", "")),
    ]

    if data.get("srcip"):
        lines.append("Источник:       {}".format(data["srcip"]))
    if data.get("dstuser"):
        lines.append("Учётная запись: {}".format(data["dstuser"]))
    if alert.get("syscheck", {}).get("path"):
        lines.append("Файл:           {}".format(alert["syscheck"]["path"]))

    mitre = rule.get("mitre", {})
    if mitre.get("id"):
        lines.append("MITRE ATT&CK:   {}".format(", ".join(mitre["id"])))
    if rule.get("groups"):
        lines.append("Группы правил:  {}".format(", ".join(rule["groups"])))

    lines += [
        "",
        "Исходное событие:",
        (alert.get("full_log") or "(событие без текстового представления)")[:1500],
        "",
        "Открыть в дашборде: {}/app/wazuh#/overview".format(dashboard_url.rstrip("/")),
        "",
        "Заявка создана автоматически интеграцией Wazuh → ServiceDesk Plus.",
    ]
    return "\n".join(lines)


def sdp_request(env, method, path, payload=None):
    url = "{}/api/v3/{}".format(env.get("SDP_URL", "").rstrip("/"), path.lstrip("/"))
    headers = {
        "authtoken": env.get("SDP_AUTHTOKEN", ""),
        "Accept": "application/vnd.manageengine.sdp.v3+json",
    }

    body = None
    if payload is not None:
        data = urllib.parse.urlencode({"input_data": json.dumps(payload, ensure_ascii=False)})
        body = data.encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    context = None
    if env.get("SDP_VERIFY_TLS", "no").lower() not in ("yes", "true", "1"):
        # Внутренний УЦ компании; проверка отключается осознанно и
        # только для внутреннего адреса support.uk-n.ru
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=30, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


def create_request(env, alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = int(rule.get("level", 0))

    subject = "[Wazuh {}] {} — {}".format(
        level,
        rule.get("description", "инцидент безопасности")[:120],
        agent.get("name", "менеджер"),
    )

    payload = {
        "request": {
            "subject": subject,
            "description": build_description(alert, env.get("DASHBOARD_URL", "")),
            "priority": {"name": PRIORITY_MAP.get(level, "Средний")},
            "group": {"name": env.get("SDP_TECHNICIAN_GROUP", "")},
            "category": {"name": "Информационная безопасность"},
            "status": {"name": "Open"},
        }
    }

    template = env.get("SDP_REQUEST_TEMPLATE", "")
    if template:
        payload["request"]["template"] = {"name": template}

    return sdp_request(env, "POST", "requests", payload)


def add_note(env, request_id, alert):
    rule = alert.get("rule", {})
    payload = {
        "request_note": {
            "description": "Повтор того же события в {}: правило {}, узел {}.".format(
                alert.get("timestamp", ""),
                rule.get("id", "?"),
                alert.get("agent", {}).get("name", "менеджер"),
            ),
            "show_to_requester": False,
            "notify_technician": False,
        }
    }
    return sdp_request(env, "POST", "requests/{}/notes".format(request_id), payload)


def main():
    if len(sys.argv) < 2:
        log("не передан путь к файлу алерта")
        return 1

    env = read_env()
    if not env.get("SDP_URL") or not env.get("SDP_AUTHTOKEN"):
        log("не заданы SDP_URL или SDP_AUTHTOKEN — заявка не создана")
        return 1

    try:
        alert = load_alert(sys.argv[1])
    except (OSError, ValueError) as error:
        log("не разобран алерт: {}".format(error))
        return 1

    level = int(alert.get("rule", {}).get("level", 0))
    min_level = int(env.get("SDP_MIN_LEVEL", 12))
    if level < min_level:
        return 0

    key = dedup_key(alert)
    state = load_state()
    now = time.time()
    previous = state.get(key)

    try:
        if previous and now - previous.get("time", 0) < DEDUP_WINDOW and previous.get("request_id"):
            add_note(env, previous["request_id"], alert)
            log("повтор {} добавлен комментарием в заявку {}".format(key, previous["request_id"]))
            # Время не обновляем: окно подавления считается от первой
            # заявки, иначе непрерывная атака никогда не создаст вторую.
            return 0

        result = create_request(env, alert)
        request_id = str(result.get("request", {}).get("id", ""))
        if not request_id:
            log("ServiceDesk Plus не вернул номер заявки: {}".format(result)[:500])
            return 1

        state[key] = {"time": now, "request_id": request_id}
        save_state(state)
        log("создана заявка {} по правилу {} на узле {}".format(
            request_id,
            alert.get("rule", {}).get("id", "?"),
            alert.get("agent", {}).get("name", "менеджер"),
        ))
        return 0

    except urllib.error.HTTPError as error:
        log("ServiceDesk Plus вернул {}: {}".format(error.code, error.read()[:300]))
        return 1
    except (urllib.error.URLError, OSError, ValueError) as error:
        log("ошибка обращения к ServiceDesk Plus: {}".format(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
