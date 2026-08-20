#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 Сборка руководства по пилоту.

 Руководство содержит скрипты целиком, чтобы им можно было
 пользоваться, не открывая репозиторий. Вставлять их руками нельзя:
 отредактировали скрипт — и в руководстве осталась старая версия,
 причём заметить это можно только когда по нему кто-то пойдёт.

 Поэтому раздел «Приложение: скрипты целиком» собирается отсюда, из
 настоящих файлов, при каждом изменении.

 Запуск:
     python3 scripts/build-runbook.py

 Что делает:
     1. перечитывает скрипты из scripts/pilot/;
     2. пересобирает приложение в руководство-пилота.html;
     3. кладёт рядом версию для публикации (без обёртки документа).

 Проверка, что руководство не разошлось со скриптами:
     python3 scripts/build-runbook.py --check
=====================================================================
"""

import argparse
import html
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNBOOK = os.path.join(ROOT, "руководство-пилота.html")

BEGIN = "<!-- ПРИЛОЖЕНИЕ:НАЧАЛО -->"
END = "<!-- ПРИЛОЖЕНИЕ:КОНЕЦ -->"

# Что вкладывается в руководство и в каком порядке.
SCRIPTS = [
    {
        "path": "scripts/pilot/New-WazuhPilotVM.ps1",
        "title": "New-WazuhPilotVM.ps1",
        "where": "на pdc-hv0, в консоли от администратора",
        "what": "Создаёт виртуальную машину и снимает четыре настройки "
                "Hyper-V по умолчанию, которые мешают: динамическую "
                "память, шаблон Secure Boot, автоматические контрольные "
                "точки и синхронизацию времени от гипервизора.",
    },
    {
        "path": "scripts/pilot/prepare-ubuntu-node.sh",
        "title": "prepare-ubuntu-node.sh",
        "where": "на самой виртуальной машине, от root",
        "what": "Размечает и монтирует тома по UUID, ставит имя узла, "
                "настраивает время, заводит учётную запись для Ansible "
                "с ключом и sudo без пароля, обновляет пакеты.",
    },
    {
        "path": "scripts/pilot/Enable-AdAuditPolicy.ps1",
        "title": "Enable-AdAuditPolicy.ps1",
        "where": "на каждом контроллере домена, от администратора",
        "what": "Включает расширенный аудит, командную строку в событии "
                "4688 и запись блоков PowerShell, увеличивает журнал "
                "безопасности. Без этого события не создаются вовсе.",
    },
]


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


def build_appendix():
    parts = [
        BEGIN,
        '<section id="scripts">',
        "  <h2>Приложение: скрипты целиком</h2>",
        '  <div class="prose">',
        "    <p>",
        "      Здесь те же скрипты, что лежат в репозитории, — полностью. ",
        "      Чтобы воспользоваться: скопировать, сохранить под указанным ",
        "      именем, для файлов <code>.sh</code> добавить право на ",
        "      выполнение (<code>chmod +x</code>).",
        "    </p>",
        "    <p>",
        "      Раздел собирается из настоящих файлов скриптом ",
        "      <code>scripts/build-runbook.py</code> — расходиться с ними ",
        "      он не может.",
        "    </p>",
        "  </div>",
    ]

    for item in SCRIPTS:
        source = read(item["path"])
        lines = source.count("\n")
        parts += [
            "",
            f'  <h3 style="margin-top:28px">{html.escape(item["title"])}</h3>',
            '  <div class="prose">',
            f'    <p>{html.escape(item["what"])}</p>',
            f'    <p style="font-size:14px;color:var(--ink-3)">'
            f'Запускается {html.escape(item["where"])} · '
            f'в репозитории: <code>{html.escape(item["path"])}</code> · '
            f"{lines} строк</p>",
            "  </div>",
            f"<pre><code>{html.escape(source, quote=False)}</code></pre>",
        ]

    parts += ["</section>", END]
    return "\n".join(parts)


def inject(document, appendix):
    if BEGIN in document and END in document:
        pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
        return pattern.sub(lambda _: appendix, document)

    # Первая сборка: приложение встаёт перед подвалом
    marker = '<footer class="foot">'
    if marker not in document:
        raise SystemExit("в руководстве не найден подвал — некуда вставлять приложение")
    return document.replace(marker, appendix + "\n\n" + marker, 1)


def strip_wrapper(document):
    """Версия для публикации: без doctype, html, head и body."""
    body = re.search(r"<body>(.*)</body>", document, re.S)
    head = re.search(r"(<title>.*?</title>.*?</style>)", document, re.S)
    if not body or not head:
        raise SystemExit("не удалось разобрать документ на части")
    return head.group(1).strip() + "\n\n" + body.group(1).strip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Сборка руководства по пилоту")
    parser.add_argument("--check", action="store_true",
                        help="только проверить, что руководство совпадает со скриптами")
    parser.add_argument("--artifact", metavar="ПУТЬ",
                        help="дополнительно записать версию для публикации")
    args = parser.parse_args()

    for item in SCRIPTS:
        full = os.path.join(ROOT, item["path"])
        if not os.path.exists(full):
            raise SystemExit(f"нет файла: {item['path']}")

    document = read(os.path.basename(RUNBOOK))
    updated = inject(document, build_appendix())

    if args.check:
        if updated == document:
            print("руководство совпадает со скриптами")
            return 0
        print("руководство расходится со скриптами — выполните:", file=sys.stderr)
        print("    python3 scripts/build-runbook.py", file=sys.stderr)
        return 1

    if updated != document:
        with open(RUNBOOK, "w", encoding="utf-8") as handle:
            handle.write(updated)
        print(f"обновлено: {os.path.basename(RUNBOOK)}")
    else:
        print("изменений нет")

    if args.artifact:
        with open(args.artifact, "w", encoding="utf-8") as handle:
            handle.write(strip_wrapper(updated))
        print(f"версия для публикации: {args.artifact}")

    total = sum(read(i["path"]).count("\n") for i in SCRIPTS)
    print(f"вложено скриптов: {len(SCRIPTS)}, строк всего: {total}")
    print(f"размер руководства: {round(len(updated.encode()) / 1024, 1)} КБ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
