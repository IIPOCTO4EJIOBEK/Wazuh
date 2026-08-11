# 11. Разбор неисправностей

Порядок один и тот же: `scripts/healthcheck.sh` → раздел ниже по
симптому → журналы.

Где что лежит:

```
менеджер   /var/ossec/logs/ossec.log
           /var/ossec/logs/api.log
           /var/ossec/logs/cluster.log
           /var/ossec/logs/integrations.log
           /var/ossec/logs/active-responses.log
индексер   /var/log/wazuh-indexer/wazuh-ahp.log
filebeat   journalctl -u filebeat
дашборд    /var/log/wazuh-dashboard/dashboard.log
агент      /var/ossec/logs/ossec.log
           C:\Program Files (x86)\ossec-agent\ossec.log
```

---

## Событий нет вообще

Симптом: дашборд пуст, за час ноль алертов.

Проверять по потоку, от источника к хранилищу.

```bash
# 1. Агенты вообще подключены?
/var/ossec/bin/agent_control -l | head

# 2. Менеджер принимает и разбирает?
tail -f /var/ossec/logs/alerts/alerts.json

# 3. filebeat отдаёт в индексер?
filebeat test output
journalctl -u filebeat -n 50

# 4. Индексер принимает?
curl -k -u admin 'https://10.5.2.81:9200/_cat/indices/wazuh-alerts-*?v'
```

Где обрывается поток — там и причина.

| Обрыв | Частая причина |
|-------|----------------|
| нет агентов | балансировщик не пропускает 1514, проверить `curl http://10.5.2.92:8404/stats` |
| alerts.json пуст | analysisd не запущен или конфигурация не прошла проверку |
| filebeat не отдаёт | пароль в keystore не совпадает с паролем учётной записи `filebeat` в индексере |
| индексер не создаёт индекс | шаблон не загружен либо у роли `wazuh_writer` не хватает прав |

Восстановление учётных данных filebeat:

```bash
filebeat keystore list
printf '%s' 'ПАРОЛЬ' | filebeat keystore add password --stdin --force
systemctl restart filebeat
filebeat test output
```

---

## Событий стало заметно меньше

Симптом: провал на графике при неизменном числе активных агентов.

Это почти всегда потеря событий, а не спокойный день.

```bash
cat /var/ossec/var/run/wazuh-analysisd.state
```

Смотреть на `events_dropped` и `*_queue_usage`. Значение очереди близко
к 1 означает, что менеджер не успевает и отбрасывает события.

Что делать:

1. Найти источник шума — обычно один агент даёт основную часть потока:

```bash
curl -sk -u admin -H 'Content-Type: application/json' \
  'https://10.5.2.81:9200/wazuh-alerts-*/_search' -d '{
  "size":0,"query":{"range":{"timestamp":{"gte":"now-1h"}}},
  "aggs":{"agents":{"terms":{"field":"agent.name","size":10}}}}'
```

2. Ограничить его в конфигурации группы (`client_buffer`,
   `events_per_second`) или отфильтровать лишние события в запросе
   канала.
3. Если шума нет, а поток вырос честно — увеличить очереди в
   `local_internal_options.conf` или добавить worker-менеджер.

---

## Индексер не собирается в кластер

Симптом: `number_of_nodes: 1` на каждом узле, в журнале
`master not discovered yet`.

```bash
tail -100 /var/log/wazuh-indexer/wazuh-ahp.log
```

| Сообщение | Причина | Что делать |
|-----------|---------|-----------|
| `not match any of the configured node DNs` | subject сертификата не совпадает с `plugins.security.nodes_dn` | сравнить посимвольно, перевыпустить сертификаты |
| `master not discovered` | закрыт порт 9300 или неверный `discovery.seed_hosts` | проверить `nc -zv 10.5.2.82 9300` |
| `failed to load PKCS8 key` | ключ в формате PKCS#1 | перевыпустить с `format: pkcs8` |
| `bootstrap check failure: max virtual memory areas` | не задан `vm.max_map_count` | `sysctl -w vm.max_map_count=262144` |

Проверка subject:

```bash
openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout -subject
grep -A4 nodes_dn /etc/wazuh-indexer/opensearch.yml
```

Строки должны совпадать полностью, включая пробелы и порядок полей.

---

## Кластер в состоянии yellow

Реплики не размещены. Данные целы, избыточности нет.

```bash
curl -k -u admin 'https://10.5.2.81:9200/_cluster/allocation/explain?pretty'
```

Частые причины:

* узел индексера выключен — вернуть узел;
* диск заполнен выше 85 процентов — освободить место или уменьшить
  срок хранения;
* число реплик больше, чем узлов минус один (например, 3 реплики на
  3 узла) — исправить шаблон индексов.

Состояние `yellow` сразу после установки, когда индексов ещё нет, —
норма.

---

## Кластер в состоянии red

Часть первичных шардов недоступна: данные за какой-то период не
читаются.

```bash
curl -k -u admin 'https://10.5.2.81:9200/_cat/shards?v&h=index,shard,prirep,state,node' | grep UNASSIGNED
curl -k -u admin 'https://10.5.2.81:9200/_cluster/allocation/explain?pretty'
```

Порядок действий:

1. Вернуть выключенные узлы — чаще всего этого достаточно.
2. Если узел потерян безвозвратно, восстановить пострадавшие индексы
   из снапшота (`backup/restore-indices.sh --replace`).
3. `allocate_empty_primary` использовать только осознанно: команда
   создаёт пустой шард вместо потерянного, то есть безвозвратно теряет
   его содержимое.

---

## Агент не регистрируется

```
ERROR: Unable to add agent
ERROR: Invalid password
```

| Причина | Проверка |
|---------|----------|
| неверный пароль | сравнить `/var/ossec/etc/authd.pass` на агенте и на master |
| master недоступен | `nc -zv 10.5.2.90 1515`; при отказе master регистрация не работает — так задумано |
| имя занято | агент с таким именем есть и отключён менее часа назад |
| балансировщик шлёт на worker | `curl -s http://10.5.2.92:8404/stats \| grep enrollment` |

Освободить имя:

```bash
/var/ossec/bin/manage_agents -r <id>
```

---

## Агент подключён, событий с него нет

```bash
/var/ossec/bin/agent_control -i <id>     # версия, время последнего события
```

На агенте:

```bash
tail -50 /var/ossec/logs/ossec.log
ls -la /var/ossec/etc/shared/            # приехала ли конфигурация группы
```

Частая причина: агент состоит в группе, а файл журнала на узле лежит по
другому пути. Проверить, что путь из `agent-groups/*.conf`
действительно существует на машине.

Для Windows: события не появятся, если не включён расширенный аудит.
См. [06-agents.md](06-agents.md).

---

## Правило не срабатывает

```bash
/var/ossec/bin/wazuh-logtest
# вставить строку журнала
```

Вывод показывает, какой декодер сработал, какие поля извлёк и какое
правило подняло событие.

| Симптом | Причина |
|---------|---------|
| «No decoder matched» | нет декодера — событие не разбирается на поля |
| декодер сработал, поля пустые | ошибка в регулярном выражении декодера |
| поля есть, правило не поднялось | не совпал `if_sid`, `field` или условие частоты |
| поднялось другое правило | у чужого правила выше уровень; добавить `<overwrite>` или поднять свой уровень |

Первое, что стоит проверить в собственном правиле, — не используется ли
группировка с чередованием `(a|b)` без `type="pcre2"`. В движке
OS_Regex это работает не так, как в PCRE, и выражение молча не
совпадает. Подробности — в [07-detection-response.md](07-detection-response.md).

---

## Active response не сработал

```bash
grep ahp-ar /var/ossec/logs/active-responses.log | tail -20
```

| Результат в журнале | Что значит |
|--------------------|-----------|
| `skipped-allowlist` | адрес в списке неблокируемых — работает предохранитель |
| `denied` | защищённая группа AD либо превышен порог блокировок в час |
| `error` | смотреть комментарий в конце строки |
| записи нет вообще | скрипт не запускался |

Если записи нет:

```bash
grep -i "active response\|execd" /var/ossec/logs/ossec.log | tail -20
ls -la /var/ossec/active-response/bin/       # права должны быть 0750, владелец root:wazuh
```

Проверить скрипт напрямую:

```bash
echo '{"version":1,"command":"add","parameters":{"alert":{"rule":{"id":"5716"},"data":{"srcip":"203.0.113.10"}}}}' \
  | /var/ossec/active-response/bin/ahp-block-ip
```

---

## Дашборд не открывается

```bash
systemctl status wazuh-dashboard
tail -50 /var/log/wazuh-dashboard/dashboard.log
```

| Сообщение | Причина |
|-----------|---------|
| `Unable to connect to OpenSearch` | индексер недоступен или пароль `kibanaserver` не совпадает |
| `EACCES: permission denied 0.0.0.0:443` | не выдана возможность `cap_net_bind_service` процессу node |
| «Wazuh API не отвечает» в интерфейсе | проверить `wazuh.yml` и доступность 10.5.2.90:55000 |
| пустой экран после входа | шаблон индекса `wazuh-alerts-*` не создан — данных ещё нет |

Возврат возможности занимать порт 443:

```bash
setcap 'cap_net_bind_service=+ep' /usr/share/wazuh-dashboard/node/bin/node
systemctl restart wazuh-dashboard
```

---

## VIP не переезжает

```bash
systemctl status keepalived
journalctl -u keepalived -n 50
/etc/keepalived/check-haproxy.sh; echo "код: $?"
```

| Причина | Проверка |
|---------|----------|
| VRRP заблокирован межсетевым экраном | разрешить протокол 112 между 10.5.2.92 и .93 |
| скрипт проверки возвращает не 0 | запустить руками, смотреть, какой из трёх шагов не проходит |
| разные `virtual_router_id` | сравнить конфигурации на обоих узлах |
| оба узла держат VIP | VRRP не проходит между ними — сеть или экран |

Напоминание: включён `nopreempt`, поэтому восстановившийся узел не
забирает адрес обратно. Это не неисправность.

---

## Снапшоты не создаются

```bash
curl -k -u admin 'https://10.5.2.81:9200/_plugins/_sm/policies/wazuh-daily/_explain?pretty'
curl -k -u admin -X POST 'https://10.5.2.81:9200/_snapshot/wazuh-snapshots/_verify?pretty'
```

Самая частая причина: NFS смонтирован не на всех узлах индексера.
Снапшот пишут все узлы одновременно, и если ресурс виден только одному,
операция не завершится.

```bash
ansible wazuh_indexer -m shell -a 'mountpoint /mnt/wazuh-snapshots'
ansible wazuh_indexer -m shell -a 'touch /mnt/wazuh-snapshots/.t && rm /mnt/wazuh-snapshots/.t' --become
```

Вторая по частоте — права: каталог должен принадлежать пользователю
`wazuh-indexer` (обычно UID 1000) на стороне сервера NFS.

---

## Заявки в ServiceDesk Plus не создаются

```bash
tail -30 /var/ossec/logs/integrations.log
```

| Сообщение | Причина |
|-----------|---------|
| `не заданы SDP_URL или SDP_AUTHTOKEN` | не заполнен `vault.yml` |
| `ServiceDesk Plus вернул 401` | токен недействителен или у пользователя нет прав |
| `ServiceDesk Plus вернул 400` | не найден шаблон или группа исполнителей — сверить названия с SDP |
| `повтор ... добавлен комментарием` | это не ошибка: работает подавление повторов |
| журнал пуст | алерты не дотягивают до порога уровня 12 |

Проверка вручную — образец команды в [09-integrations.md](09-integrations.md).

---

## Куда смотреть, если ничего не помогло

```bash
# полное состояние менеджера
/var/ossec/bin/wazuh-control status
/var/ossec/bin/cluster_control -l

# что синхронизировалось между узлами кластера
tail -100 /var/ossec/logs/cluster.log

# временно включить подробную отладку (журнал растёт быстро!)
echo 'analysisd.debug=2' >> /var/ossec/etc/local_internal_options.conf
systemctl restart wazuh-manager
# после разбора обязательно вернуть 0 и перезапустить
```

Диагностический пакет для обращения в поддержку Wazuh:

```bash
/var/ossec/bin/wazuh-logtest -v
tar czf /tmp/wazuh-diag.tar.gz \
    /var/ossec/logs/ossec.log \
    /var/ossec/logs/cluster.log \
    /var/ossec/etc/ossec.conf \
    /var/ossec/var/run/*.state
```

Перед отправкой пакета наружу проверить, что в нём нет паролей:
`ossec.conf` содержит пароль учётной записи индексера.
