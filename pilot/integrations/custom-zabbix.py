#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 Передача алерта Wazuh в Zabbix (10.5.2.74) по протоколу trapper.

 Зачем это нужно, если оповещения уже есть в Telegram и ServiceDesk:
 в компании дежурство построено вокруг Zabbix, там настроены эскалации
 и расписание. Инцидент безопасности должен попадать в тот же поток,
 а не в отдельный, который смотрят только в рабочее время.

 Отправка идёт напрямую в сокет 10051 — zabbix_sender может
 отсутствовать, а протокол простой и стабильный.

 На стороне Zabbix нужен узел с элементом данных типа
 «Zabbix trapper» и ключом wazuh.alert — см.
 integrations/zabbix/wazuh_template.yaml
=====================================================================
"""

import json
import socket
import struct
import sys
import time

ENV_FILE = "/var/ossec/etc/integrations.env"
LOG_FILE = "/var/ossec/logs/integrations.log"
ZABBIX_PORT = 10051
ITEM_KEY = "wazuh.alert"


def log(message):
    stamp = time.strftime("%Y/%m/%d %H:%M:%S")
    line = "{} custom-zabbix: {}\n".format(stamp, message)
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


def zabbix_send(server, host, key, value, timeout=10):
    """Протокол Zabbix sender: заголовок ZBXD\\x01 + длина + JSON."""
    payload = json.dumps({
        "request": "sender data",
        "data": [{"host": host, "key": key, "value": value}],
    }, ensure_ascii=False).encode("utf-8")

    packet = b"ZBXD\x01" + struct.pack("<Q", len(payload)) + payload

    with socket.create_connection((server, ZABBIX_PORT), timeout=timeout) as sock:
        sock.sendall(packet)

        header = sock.recv(13)
        if len(header) < 13 or not header.startswith(b"ZBXD"):
            raise ValueError("неожиданный ответ сервера Zabbix")

        length = struct.unpack("<Q", header[5:13])[0]
        body = b""
        while len(body) < length:
            chunk = sock.recv(min(4096, length - len(body)))
            if not chunk:
                break
            body += chunk

    return json.loads(body.decode("utf-8"))


def main():
    if len(sys.argv) < 2:
        log("не передан путь к файлу алерта")
        return 1

    env = read_env()
    server = env.get("ZABBIX_SERVER", "")
    host = env.get("ZABBIX_HOST", "")
    if not server or not host:
        log("не заданы ZABBIX_SERVER или ZABBIX_HOST")
        return 1

    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            content = handle.read().strip()
        alert = next(json.loads(line) for line in content.splitlines() if line.strip().startswith("{"))
    except (OSError, ValueError, StopIteration) as error:
        log("не разобран алерт: {}".format(error))
        return 1

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    # Значение — одна строка: Zabbix показывает её в списке событий,
    # и она должна быть читаемой без раскрытия деталей.
    value = "[{}] {} | узел: {} | правило: {}".format(
        rule.get("level", "?"),
        rule.get("description", "событие"),
        agent.get("name", "менеджер"),
        rule.get("id", "?"),
    )

    try:
        result = zabbix_send(server, host, ITEM_KEY, value)
        info = result.get("info", "")
        if "failed: 0" not in info.replace(" ", " "):
            log("Zabbix принял не всё: {}".format(info))
        return 0
    except (socket.error, OSError, ValueError) as error:
        log("не отправлено в Zabbix: {}".format(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
