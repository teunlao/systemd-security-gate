# systemd-security-gate (Project Notes for Agents)

Status: MVP implemented (CLI + GitHub Action scaffold)

Этот документ — single source of truth: **что мы делаем, зачем, какие границы, и как реализовать без расползания**.
Аудитория: будущие мейнтейнеры (люди + coding agents).

---

## 1) One-line pitch

**CLI + GitHub Action**, превращающие `systemd` unit‑файлы в репозитории в **проверяемый контракт безопасности**: CI **падает**, если `systemd-analyze security` (offline) показывает “хуже порога”, с удобными отчётами (JSON/PR summary/SARIF).

---

## 2) Problem statement (что болит)

`systemd`‑сервисы часто харднятся директивами sandboxing’а (`NoNewPrivileges=`, `ProtectSystem=`, `PrivateTmp=`, …).
Практический фейл-паттерн:

- hardening добавили “когда‑то”
- потом в PR кто-то убрал/ослабил (ради дебага/совместимости/“починилось само”)
- билд проходит, сервис работает, **регрессия безопасности тихая**
- всплывает поздно (security review/инцидент/аудит)

`systemd-analyze security` уже умеет оценивать “exposure” и давать breakdown по проверкам, но это **не CI‑продукт**:
нет репо‑ориентированного discovery, offline layout, агрегирования результатов, PR UX, SARIF, allowlist/baseline.

Мы делаем узкий “quality gate”, который:

- детерминированно находит unit‑файлы в репо
- анализирует их **offline** через systemd
- валит сборку по порогу и/или policy
- выдаёт понятные, PR‑дружелюбные отчёты

---

## 3) Non-goals (не превращаемся в “всё про systemd”)

Проект НЕ должен:

- пытаться “заменить” или “улучшить” `systemd-analyze security` — он источник истины
- становиться общим линтером unit‑файлов по синтаксису/стилю/formatting
- требовать агент/daemon на хостах (никакого runtime‑мониторинга)
- анализировать реальные запущенные сервисы (v1 — **только unit‑файлы в репо**)
- гарантировать одинаковую оценку между разными версиями systemd без pinning (см. ниже)

---

## 4) Target users / use cases

ЦА: DevOps/SRE/SecOps и мейнтейнеры, которые деплоят `systemd` unit‑файлы из репозитория.

Типовые кейсы:

- “у нас 5–50 сервисов, хотим minimum hardening bar”
- “не хотим, чтобы PR ухудшал hardening”
- “хотим Code Scanning issues по security regression в unit‑файлах”
- “у нас compliance, нужен отчёт и allowlist с ревью”

---

## 5) Product shape (что именно ship’аем)

### 5.1) Компоненты v1

1) **CLI** (Go) — локально и в CI:
   - discovery unit‑файлов
   - offline‑анализ через `systemd-analyze security`
   - пороги/allowlist/отчёты

2) **GitHub Action** (container action, Linux‑only):
   - запускает CLI
   - содержит pinned systemd (важно для воспроизводимости)
   - пишет в `$GITHUB_STEP_SUMMARY`
   - опционально грузит SARIF

### 5.2) Почему container action (важно)

Версии systemd на runner’ах нестабильны, а `systemd-analyze security` меняется.
Чтобы результаты были предсказуемы:

- Action **должен** поставляться с pinned образом (например, Debian/Ubuntu) + pinned systemd ≥ минимально поддерживаемой версии.

---

## 6) What exactly gets checked (v1 contract)

### 6.1) Что проверяем

v1 — **только `.service`**.

Почему:
- `systemd-analyze security` по смыслу и UX в первую очередь про **service units**
- `.socket/.timer` сами по себе не несут sandboxing‑директив сервиса; их нужно маппить на сервис (это отдельная логика)

Discovery по `.socket/.timer` можно добавить позже, но v1 лучше честно ограничить:

- если пользователь указал `.socket/.timer`, CLI либо:
  - **warn + skip**, либо
  - **error**, если включён строгий режим (настраиваемо)

### 6.2) Offline semantics (как анализируем)

Offline‑анализ делается через временный `--root` (или `--image`) и укладку unit‑файлов под стандартные директории, например:

- `$ROOT/etc/systemd/system/<unit>.service`
- `$ROOT/etc/systemd/system/<unit>.service.d/*.conf` (drop-ins)

Затем вызываем `systemd-analyze security` по **имени юнита** (`<unit>.service`), а не по произвольному пути.

### 6.3) Порог и “падение”

CI считается проваленным, если:

- `systemd-analyze security --threshold=<T>` возвращает non‑zero для хотя бы одного checked unit, ИЛИ
- policy/allowlist‑логика CLI решила, что состояние недопустимо (см. allowlist/baseline ниже)

Ключевой принцип: **выходной код — контракт**.

---

## 7) Config surface (CLI и Action)

### 7.1) CLI (предлагаемая форма, может эволюционировать)

Команда: `ssg` (working name: “systemd security gate”)

Флаги (v1 MVP):

- `--paths <glob>` (повторяемый) — где искать unit‑файлы (по умолчанию ничего не ищем)
- `--exclude <glob|regex>` — исключения
- `--threshold <float>` — порог overall exposure (чем выше, тем хуже)
- `--policy <path>` — путь до JSON policy для `systemd-analyze` (optional)
- `--allowlist <path>` — исключения по unit/test‑id (optional)
- `--format json|md|sarif` + `--out <path>` (повторяемые) — артефакты
- `--systemd-analyze <path>` — путь до бинаря (обычно просто `systemd-analyze`)

### 7.2) GitHub Action inputs (минимум)

- `paths` (multiline)
- `exclude` (multiline)
- `threshold`
- `policy`
- `allowlist`
- `sarif` (boolean/path)
- `summary` (boolean)

---

## 8) Determinism & UX rules (важно для CI)

### 8.1) Детерминизм

- discovery результатов сортируем (path sort)
- отчёты сортируем (unit name sort; внутри unit — sort по `json_field`/`name`)
- выставляем `LC_ALL=C` при запуске `systemd-analyze`, чтобы избежать локалей в текстовом выводе
- в JSON/SARIF — только относительные пути к репо (без `/tmp/...`)

### 8.2) Diagnostics (что пользователь должен видеть)

Минимум на провале:

- какой unit (и путь в репо)
- overall exposure / threshold
- топ‑N худших проверок (по `exposure`, с `name/json_field` и коротким `description`)
- подсказки: “это можно исправить директивами X/Y” (только если это берётся из данных systemd, не придумывать)

---

## 9) Allowlist + baseline (чтобы реально внедрялось)

Проблема: в зрелых системах “идеально” сразу не будет.

Нужно поддержать механизм “мы разрешаем вот эти отклонения, но:

- список исключений ревьюится (лежит в репо)
- исключения не растут незаметно
- регрессии детектятся”

Минимум v1:

- allowlist по **unit path** + **test identifier** (например `PrivateNetwork`, `ProtectSystem`, …)
- режимы:
  - `allowlist-only`: допускаем только перечисленные исключения
  - `report`: не валим сборку по threshold (для первичного внедрения), но ошибки анализа (missing tool/parse errors) всё равно считаем фейлом

Baseline/regression (скорее v1.1/v2):
- сохранять “текущее состояние” в JSON baseline
- в PR сравнивать и не позволять ухудшение выше дельты

---

## 10) Architecture plan (как реализуем)

### 10.1) Внешний движок (systemd)

Мы НЕ парсим unit‑файлы сами для security‑оценки.
Мы:

1) строим offline root
2) запускаем `systemd-analyze security` с нужными флагами
3) парсим `--json=short` как источник данных для репортинга/allowlist/SARIF

### 10.2) Offline root builder (самая “тонкая” часть)

Нужно:

- корректно копировать `.service` и drop‑ins `.service.d/*.conf`
- гарантировать отсутствие коллизий имён (две разных `foo.service` из разных папок)
  - v1: **fail** с понятной ошибкой и подсказкой “сузьте paths / переименуйте unit / запустите по подпроектам”
- обеспечить “unit name → repo path” mapping для репортов

### 10.3) Сбор данных

Ожидаем, что JSON содержит по каждому тесту:

- идентификатор (name/json_field)
- `description`
- `exposure` (0..1) и т.п.

Вся логика “топ проблем” и SARIF ruleId строится вокруг этого идентификатора.

### 10.4) SARIF

SARIF делаем простым:

- `ruleId`: `systemd.<testId>`
- `level`: warning/error по порогам (конфигurable)
- `location`: unit‑файл в репо (line numbers отсутствуют — ok)

---

## 11) Testing strategy (обязательная для v1)

Тестировать “все версии systemd на всех дистрибутивах” нереально.
Реалистично:

1) **Интеграционные тесты** в Docker c pinned systemd:
   - фиксируем 1 базовую версию (например v256 или конкретный distro package version)
   - fixture‑юниты: `good.service`, `bad.service`, `dropin.service` (+ drop‑in)
   - утверждения:
     - bad → exit != 0 при `--threshold=T`
     - good → exit == 0
     - JSON содержит ожидаемые `testId` поля (без жёстких чисел, если они нестабильны)

2) **Golden tests** для наших отчётов:
   - SARIF/Markdown summary (снепшоты по ключевым полям)

3) (опционально) Matrix tests:
   - прогон на 2–3 версиях systemd, но ассерты только по инвариантам (exit code + наличие ключевых testId)

---

## 12) Repository layout (предложение)

Держим просто (single repo):

```
.
  cmd/ssg/                 # CLI entry
  internal/discover/       # поиск unit-файлов
  internal/offlineroot/    # сборка --root layout
  internal/systemdanalyze/ # запуск/парсинг JSON
  internal/report/         # md/json/sarif writers
  internal/allowlist/      # allowlist logic
  test/fixtures/           # unit-файлы для интеграционных тестов
  action/                  # GitHub Action metadata + container bits
  README.md
  AGENTS.md
```

---

## 13) Release philosophy

- v0.x пока UX/inputs эволюционируют
- semver, без “магических дефолтов”
- главная цель: **воспроизводимость** и **понятные ошибки**

---

## 14) Next steps (план реализации по шагам)

1) Скелет CLI (Go): `ssg scan --paths ... --threshold ...`
2) Discovery `.service` + исключения + проверка коллизий
3) Offline root builder + поддержка drop‑ins
4) Интеграция `systemd-analyze security --offline --root --json=short --threshold`
5) Markdown summary + JSON report
6) Allowlist v1 (unit + testId)
7) SARIF writer + GitHub Action (container, pinned systemd)
8) Интеграционные тесты в Docker + golden snapshots
