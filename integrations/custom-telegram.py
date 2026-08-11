#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 Отправка алерта Wazuh в Telegram.

 Быстрый канал для дежурного: заявка в ServiceDesk Plus фиксирует
 инцидент и его сроки, а сообщение в Telegram сокращает время до
 первого взгляда человека. Одно другое не заменяет.

 Ограничение частоты — не меньше, чем в ServiceDesk: чат, в который
 за минуту прилетело двести сообщений, дежурный выключает, и дальше
 он не видит ничего.
=====================================================================
"""

import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ENV_FILE = "/var/ossec/etc/integrations.env"
LOG_FILE = "/var/ossec/logs/integrations.log"
RATE_FILE = "/var/ossec/var/run/telegram-rate.json"

# Не более указанного числа сообщений за окно
RATE_LIMIT = 12
RATE_WINDOW = 300

LEVEL_ICON = {15: "\U0001F534", 14: "\U0001F534", 13: "\U0001F7E0",
              12: "\U0001F7E0", 11: "\U0001F7E1", 10: "\U0001F7E1"}


def log(message):
    stamp = time.strftime("%Y/%m/%d %H:%M:%S")
    line = "{} custom-telegram: {}\n".format(stamp, message)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        sys.stderr.write(line)


def read_env(path=ENV_FILE):
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


def rate_ok():
    now = time.time()
    try:
        with open(RATE_FILE, encoding="utf-8") as handle:
            stamps = [t for t in json.load(handle) if now - t < RATE_WINDOW]
    except (OSError, ValueError):
        stamps = []

    if len(stamps) >= RATE_LIMIT:
        return False

    stamps.append(now)
    try:
        with open(RATE_FILE, "w", encoding="utf-8") as handle:
            json.dump(stamps, handle)
    except OSError:
        pass
    return True


def escape(text):
    """Экранирование под parse_mode=HTML."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build_message(alert, dashboard_url):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    level = int(rule.get("level", 0))

    parts = [
        "{} <b>Wazuh: уровень {}</b>".format(LEVEL_ICON.get(level, "\U0001F535"), level),
        "<b>{}</b>".format(escape(rule.get("description", "событие"))),
        "",
        "Узел: <code>{}</code>".format(escape(agent.get("name", "менеджер"))),
        "Правило: <code>{}</code>".format(escape(rule.get("id", "?"))),
        "Время: {}".format(escape(alert.get("timestamp", ""))),
    ]

    if data.get("srcip"):
        parts.append("Источник: <code>{}</code>".format(escape(data["srcip"])))
    if data.get("dstuser"):
        parts.append("Учётная запись: <code>{}</code>".format(escape(data["dstuser"])))
    if alert.get("syscheck", {}).get("path"):
        parts.append("Файл: <code>{}</code>".format(escape(alert["syscheck"]["path"])))

    full_log = alert.get("full_log")
    if full_log:
        parts += ["", "<pre>{}</pre>".format(escape(full_log[:600]))]

    if dashboard_url:
        parts += ["", '<a href="{}/app/wazuh#/overview">Открыть в дашборде</a>'.format(
            dashboard_url.rstrip("/"))]

    return "\n".join(parts)


def main():
    if len(sys.argv) < 2:
        log("не передан путь к файлу алерта")
        return 1

    env = read_env()
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = env.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        # Интеграция включена, но бот не выдан — молчим, это штатно.
        return 0

    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            content = handle.read().strip()
        alert = next(json.loads(line) for line in content.splitlines() if line.strip().startswith("{"))
    except (OSError, ValueError, StopIteration) as error:
        log("не разобран алерт: {}".format(error))
        return 1

    level = int(alert.get("rule", {}).get("level", 0))
    if level < int(env.get("TELEGRAM_MIN_LEVEL", 10)):
        return 0

    if not rate_ok():
        log("превышен предел {} сообщений за {} секунд — алерт не отправлен".format(
            RATE_LIMIT, RATE_WINDOW))
        return 0

    payload = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": build_message(alert, env.get("DASHBOARD_URL", "")),
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode("utf-8")

    url = "https://api.telegram.org/bot{}/sendMessage".format(token)
    context = ssl.create_default_context()

    try:
        request = urllib.request.Request(url, data=payload, method="POST")
        with urllib.request.urlopen(request, timeout=20, context=context) as response:
            response.read()
        return 0
    except urllib.error.HTTPError as error:
        log("Telegram вернул {}: {}".format(error.code, error.read()[:200]))
        return 1
    except (urllib.error.URLError, OSError) as error:
        log("не отправлено в Telegram: {}".format(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
