#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 Сборка сохранённых объектов для дашбордов AH Prostory.

 Почему генератор, а не готовый ndjson: файл экспорта — это несколько
 тысяч строк JSON, вложенного в JSON. Править его руками нельзя,
 сравнивать в истории изменений бессмысленно, а любая опечатка
 обнаруживается только при импорте. Здесь описание дашбордов занимает
 несколько десятков строк и читается.

 Запуск:
     python3 build_saved_objects.py
 Результат:
     ahp-soc-dashboards.ndjson

 Загрузка на стенд:
     ./import-dashboards.sh            (или Ansible, тег saved-objects)

 Идентификаторы объектов детерминированные — собраны из имени. Значит,
 повторный импорт обновляет те же объекты, а не плодит копии.
=====================================================================
"""

import hashlib
import json
import sys

OUTPUT = "ahp-soc-dashboards.ndjson"

ALERTS_PATTERN = "wazuh-alerts-*"
VULN_PATTERN = "wazuh-states-vulnerabilities-*"


def oid(name):
    """Детерминированный идентификатор объекта в формате UUID."""
    digest = hashlib.md5(("ahp-wazuh-" + name).encode("utf-8")).hexdigest()
    return "-".join([digest[0:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]])


# ---------------------------------------------------------------------
# Шаблоны индексов
# ---------------------------------------------------------------------
def field(name, field_type="string", es_type="keyword", aggregatable=True):
    return {
        "name": name,
        "type": field_type,
        "esTypes": [es_type],
        "count": 0,
        "scripted": False,
        "searchable": True,
        "aggregatable": aggregatable,
        "readFromDocValues": aggregatable,
    }


def index_pattern(title, time_field="timestamp", fields=None):
    return {
        "id": oid("index-pattern-" + title),
        "type": "index-pattern",
        "attributes": {
            "title": title,
            "timeFieldName": time_field,
            "fields": json.dumps(fields or [], ensure_ascii=False),
        },
        "references": [],
        "migrationVersion": {"index-pattern": "7.6.0"},
    }


ALERT_FIELDS = [
    field("timestamp", "date", "date", aggregatable=True),
    field("agent.name"),
    field("rule.level", "number", "integer", aggregatable=True),
    field("rule.description"),
    field("rule.groups"),
    field("rule.mitre.technique"),
    field("data.srcip", "ip", "ip", aggregatable=True),
    field("syscheck.path"),
    field("syscheck.event"),
    field("ar.action"),
    field("ar.target"),
    field("ar.result"),
    field("win.eventdata.targetUserName"),
    field("backup.job"),
    field("backup.status"),
    field("backup.target"),
]


VULN_FIELDS = [
    field("@timestamp", "date", "date", aggregatable=True),
    field("agent.name"),
    field("package.name"),
    field("vulnerability.id"),
    field("vulnerability.severity"),
]


# ---------------------------------------------------------------------
# Визуализации
# ---------------------------------------------------------------------
def visualization(name, title, vis_state, index_id, description="", query=""):
    search_source = {
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }
    return {
        "id": oid("vis-" + name),
        "type": "visualization",
        "attributes": {
            "title": title,
            "description": description,
            "visState": json.dumps(vis_state, ensure_ascii=False),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source, ensure_ascii=False)
            },
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": index_id,
            }
        ],
        "migrationVersion": {"visualization": "7.10.0"},
    }


def agg_count(agg_id="1"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": "count",
        "schema": "metric",
        "params": {},
    }


def agg_terms(agg_id, field, size, schema="segment", order_by="1"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": "terms",
        "schema": schema,
        "params": {
            "field": field,
            "orderBy": order_by,
            "order": "desc",
            "size": size,
            "otherBucket": False,
            "otherBucketLabel": "Прочее",
            "missingBucket": False,
            "missingBucketLabel": "Не задано",
        },
    }


def agg_date_histogram(agg_id="2", field="timestamp", schema="segment"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": "date_histogram",
        "schema": schema,
        "params": {
            "field": field,
            "timeRange": {"from": "now-24h", "to": "now"},
            "useNormalizedOpenSearchInterval": True,
            "scaleMetricValues": False,
            "interval": "auto",
            "drop_partials": False,
            "min_doc_count": 1,
            "extended_bounds": {},
        },
    }


def bar_params(legend=True, horizontal=False):
    mode = "normal"
    return {
        "type": "histogram",
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "left" if horizontal else "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "bottom" if horizontal else "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": mode},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Событий"},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": "histogram",
                "mode": "stacked",
                "data": {"label": "Событий", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "showCircles": True,
            }
        ],
        "addTooltip": True,
        "addLegend": legend,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
        "labels": {"show": False},
        "thresholdLine": {
            "show": False,
            "value": 10,
            "width": 1,
            "style": "full",
            "color": "#E7664C",
        },
    }


def pie_params():
    return {
        "type": "pie",
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "isDonut": True,
        "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
    }


def table_params(per_page=15):
    return {
        "perPage": per_page,
        "showPartialRows": False,
        "showMetricsAtAllLevels": False,
        "showTotal": False,
        "totalFunc": "sum",
        "percentageCol": "",
    }


def metric_params(label, font_size=48):
    return {
        "addTooltip": True,
        "addLegend": False,
        "type": "metric",
        "metric": {
            "percentageMode": False,
            "useRanges": False,
            "colorSchema": "Green to Red",
            "metricColorMode": "None",
            "colorsRange": [{"from": 0, "to": 10000}],
            "labels": {"show": True},
            "invertColors": False,
            "style": {
                "bgFill": "#000",
                "bgColor": False,
                "labelColor": False,
                "subText": label,
                "fontSize": font_size,
            },
        },
    }


# ---------------------------------------------------------------------
# Дашборды
# ---------------------------------------------------------------------
def dashboard(name, title, description, panels, time_from="now-24h", time_to="now"):
    panels_json = []
    references = []

    # Сетка дашборда — 48 колонок. Раскладка задаётся в описании панели.
    for number, panel in enumerate(panels):
        ref_name = "panel_{}".format(number)
        panels_json.append(
            {
                "version": "2.13.0",
                "gridData": {
                    "x": panel["x"],
                    "y": panel["y"],
                    "w": panel["w"],
                    "h": panel["h"],
                    "i": str(number),
                },
                "panelIndex": str(number),
                "embeddableConfig": {},
                "panelRefName": ref_name,
            }
        )
        references.append(
            {"name": ref_name, "type": "visualization", "id": panel["id"]}
        )

    return {
        "id": oid("dashboard-" + name),
        "type": "dashboard",
        "attributes": {
            "title": title,
            "description": description,
            "hits": 0,
            "timeRestore": True,
            "timeFrom": time_from,
            "timeTo": time_to,
            "refreshInterval": {"pause": False, "value": 60000},
            "optionsJSON": json.dumps(
                {"hidePanelTitles": False, "useMargins": True}, ensure_ascii=False
            ),
            "panelsJSON": json.dumps(panels_json, ensure_ascii=False),
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []},
                    ensure_ascii=False,
                )
            },
        },
        "references": references,
        "migrationVersion": {"dashboard": "7.9.3"},
    }


# =====================================================================
#  Описание содержимого
# =====================================================================
def build():
    objects = []

    alerts_ip = index_pattern(ALERTS_PATTERN, fields=ALERT_FIELDS)
    vuln_ip = index_pattern(VULN_PATTERN, time_field="@timestamp", fields=VULN_FIELDS)
    objects += [alerts_ip, vuln_ip]
    a_id = alerts_ip["id"]
    v_id = vuln_ip["id"]

    vis = {}

    # --- Обзор -------------------------------------------------------
    vis["timeline"] = visualization(
        "timeline",
        "Поток событий по уровням",
        {
            "title": "Поток событий по уровням",
            "type": "histogram",
            "aggs": [
                agg_count("1"),
                agg_date_histogram("2"),
                agg_terms("3", "rule.level", 8, schema="group"),
            ],
            "params": bar_params(),
        },
        a_id,
        "Провал на графике при живых агентах означает не тишину, "
        "а потерю событий: проверять очередь analysisd.",
    )

    vis["critical_count"] = visualization(
        "critical-count",
        "Инциденты уровня 12 и выше за период",
        {
            "title": "Инциденты уровня 12 и выше",
            "type": "metric",
            "aggs": [agg_count("1")],
            "params": metric_params("требуют реагирования"),
        },
        a_id,
        query="rule.level >= 12",
    )

    vis["top_rules"] = visualization(
        "top-rules",
        "Самые частые срабатывания",
        {
            "title": "Самые частые срабатывания",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "rule.description", 20, schema="bucket"),
                agg_terms("3", "rule.level", 1, schema="bucket"),
            ],
            "params": table_params(20),
        },
        a_id,
        "Правило в верхней строке неделями — кандидат либо на "
        "исключение, либо на устранение причины.",
    )

    vis["top_agents"] = visualization(
        "top-agents",
        "Узлы по числу событий",
        {
            "title": "Узлы по числу событий",
            "type": "pie",
            "aggs": [agg_count("1"), agg_terms("2", "agent.name", 12)],
            "params": pie_params(),
        },
        a_id,
    )

    vis["mitre"] = visualization(
        "mitre",
        "Техники MITRE ATT&CK",
        {
            "title": "Техники MITRE ATT&CK",
            "type": "histogram",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "rule.mitre.technique", 15),
            ],
            "params": bar_params(legend=False),
        },
        a_id,
        "Что именно пытались сделать, а не сколько раз сработало правило.",
    )

    vis["auth_failures"] = visualization(
        "auth-failures",
        "Отказы аутентификации по источникам",
        {
            "title": "Отказы аутентификации по источникам",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "data.srcip", 20, schema="bucket"),
                agg_terms("3", "agent.name", 3, schema="bucket"),
            ],
            "params": table_params(),
        },
        a_id,
        query="rule.groups: authentication_failed or rule.groups: authentication_failures",
    )

    # --- Инфраструктура и реагирование --------------------------------
    vis["fim_bitrix"] = visualization(
        "fim-bitrix",
        "Изменения файлов портала Bitrix",
        {
            "title": "Изменения файлов портала Bitrix",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "syscheck.path", 25, schema="bucket"),
                agg_terms("3", "syscheck.event", 3, schema="bucket"),
                agg_terms("4", "agent.name", 3, schema="bucket"),
            ],
            "params": table_params(25),
        },
        a_id,
        "Штатные правки приезжают через sync_zayavka.sh и затрагивают "
        "известные файлы. Всё остальное разбирать.",
        query='syscheck.path: "/home/bitrix/www*"',
    )

    vis["active_response"] = visualization(
        "active-response",
        "Автоматическое реагирование",
        {
            "title": "Автоматическое реагирование",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "ar.action", 10, schema="bucket"),
                agg_terms("3", "ar.target", 25, schema="bucket"),
                agg_terms("4", "ar.result", 5, schema="bucket"),
            ],
            "params": table_params(20),
        },
        a_id,
        "Строки с результатом skipped-allowlist — сработала защита от "
        "блокировки собственной инфраструктуры.",
        query="rule.groups: active_response",
    )

    vis["ad_changes"] = visualization(
        "ad-changes",
        "Изменения в Active Directory",
        {
            "title": "Изменения в Active Directory",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "rule.description", 20, schema="bucket"),
                agg_terms("3", "win.eventdata.targetUserName", 10, schema="bucket"),
            ],
            "params": table_params(20),
        },
        a_id,
        query="rule.groups: account_changed or rule.groups: privilege_escalation",
    )

    vis["storage"] = visualization(
        "storage",
        "События дисковой подсистемы и отказы служб",
        {
            "title": "События дисковой подсистемы и отказы служб",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "agent.name", 15, schema="bucket"),
                agg_terms("3", "rule.description", 10, schema="bucket"),
            ],
            "params": table_params(),
        },
        a_id,
        "Раздел заведён после отказа массива FUJITSU ETERNUS_DXL "
        "09.06.2026: тогда эти события никто не увидел вовремя.",
        query="rule.groups: hardware_error or rule.groups: storage or rule.groups: service_availability",
    )

    vis["backup_state"] = visualization(
        "backup-state",
        "Резервное копирование",
        {
            "title": "Резервное копирование",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "backup.job", 10, schema="bucket"),
                agg_terms("3", "backup.status", 5, schema="bucket"),
                agg_terms("4", "backup.target", 5, schema="bucket"),
            ],
            "params": table_params(10),
        },
        a_id,
        query="rule.groups: backup",
    )

    # --- Уязвимости ---------------------------------------------------
    vis["vuln_severity"] = visualization(
        "vuln-severity",
        "Уязвимости по критичности",
        {
            "title": "Уязвимости по критичности",
            "type": "pie",
            "aggs": [agg_count("1"), agg_terms("2", "vulnerability.severity", 6)],
            "params": pie_params(),
        },
        v_id,
    )

    vis["vuln_hosts"] = visualization(
        "vuln-hosts",
        "Узлы с критическими уязвимостями",
        {
            "title": "Узлы с критическими уязвимостями",
            "type": "table",
            "aggs": [
                agg_count("1"),
                agg_terms("2", "agent.name", 25, schema="bucket"),
                agg_terms("3", "package.name", 10, schema="bucket"),
                agg_terms("4", "vulnerability.id", 10, schema="bucket"),
            ],
            "params": table_params(25),
        },
        v_id,
        query='vulnerability.severity: "Critical" or vulnerability.severity: "High"',
    )

    objects += list(vis.values())

    # --- Раскладка дашбордов -----------------------------------------
    objects.append(
        dashboard(
            "soc-overview",
            "AH Prostory — обзор SOC",
            "Первый экран дежурного: поток событий, инциденты, требующие "
            "реагирования, самые частые срабатывания и источники отказов "
            "аутентификации.",
            [
                {"id": vis["critical_count"]["id"], "x": 0, "y": 0, "w": 12, "h": 8},
                {"id": vis["timeline"]["id"], "x": 12, "y": 0, "w": 36, "h": 16},
                {"id": vis["top_agents"]["id"], "x": 0, "y": 8, "w": 12, "h": 8},
                {"id": vis["top_rules"]["id"], "x": 0, "y": 16, "w": 24, "h": 16},
                {"id": vis["mitre"]["id"], "x": 24, "y": 16, "w": 24, "h": 16},
                {"id": vis["auth_failures"]["id"], "x": 0, "y": 32, "w": 48, "h": 15},
            ],
        )
    )

    objects.append(
        dashboard(
            "infra-response",
            "AH Prostory — инфраструктура и реагирование",
            "Целостность портала, автоматические блокировки, изменения в "
            "каталоге, отказы хранилища и состояние резервного копирования.",
            [
                {"id": vis["fim_bitrix"]["id"], "x": 0, "y": 0, "w": 24, "h": 16},
                {"id": vis["active_response"]["id"], "x": 24, "y": 0, "w": 24, "h": 16},
                {"id": vis["ad_changes"]["id"], "x": 0, "y": 16, "w": 24, "h": 16},
                {"id": vis["storage"]["id"], "x": 24, "y": 16, "w": 24, "h": 16},
                {"id": vis["backup_state"]["id"], "x": 0, "y": 32, "w": 48, "h": 12},
            ],
            time_from="now-7d",
        )
    )

    objects.append(
        dashboard(
            "vulnerabilities",
            "AH Prostory — уязвимости",
            "Что именно и на каких узлах требует обновления. Источник — "
            "инвентарь syscollector, сопоставленный с базами CVE.",
            [
                {"id": vis["vuln_severity"]["id"], "x": 0, "y": 0, "w": 16, "h": 16},
                {"id": vis["vuln_hosts"]["id"], "x": 16, "y": 0, "w": 32, "h": 16},
            ],
            time_from="now-30d",
        )
    )

    return objects


def main():
    objects = build()

    with open(OUTPUT, "w", encoding="utf-8") as handle:
        for obj in objects:
            handle.write(json.dumps(obj, ensure_ascii=False) + "\n")
        # Последняя строка экспорта — сводка; интерфейс её ожидает,
        # но не считает объектом.
        handle.write(
            json.dumps(
                {"exportedCount": len(objects), "missingRefCount": 0, "missingReferences": []},
                ensure_ascii=False,
            )
            + "\n"
        )

    counts = {}
    for obj in objects:
        counts[obj["type"]] = counts.get(obj["type"], 0) + 1

    print("Записан {}".format(OUTPUT))
    for key in sorted(counts):
        print("  {:<14} {}".format(key, counts[key]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
