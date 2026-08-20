# Wazuh pilot package

Папка содержит комплект пилотного развёртывания Wazuh для стенда `wazush`
без рабочих секретов.

## Состав

- `ansible/` - роли, инвентарь пилота, шаблоны Wazuh Indexer, Manager и Dashboard.
- `rules/` - локальные правила, декодеры, списки и группы агентов.
- `dashboards/` - генератор и NDJSON сохранённых объектов OpenSearch Dashboards.
- `agents/` - скрипты установки Linux/Windows агентов.
- `integrations/` - интеграции ServiceDesk, Zabbix, Telegram и syslog.
- `backup/` - скрипты резервного копирования и восстановления.
- `docs/` и HTML-файлы - эксплуатационная документация пилота.

## Секреты

Рабочие пароли, токены, vault-файл и закрытые ключи не публикуются.
Для запуска создайте свой файл секретов на основе:

```bash
cp ansible/group_vars/vault.yml.example ansible/group_vars/vault.yml
```

Затем передайте его при запуске playbook:

```bash
cd ansible
ansible-playbook -i inventory/pilot/hosts.yml site.yml \
  -e @group_vars/all.yml \
  -e @inventory/pilot/group_vars/all.yml \
  -e @group_vars/vault.yml
```

