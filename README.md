# RuStore Monitor Bot

Бот для мониторинга отзывов, оценок и платежей приложения в RuStore с уведомлениями в Telegram и/или Matrix.

## Возможности

- **Новые отзывы** — мгновенное уведомление о новых отзывах с текстом и оценкой
- **Редактирование отзывов** — отслеживание изменённых отзывов
- **Оценки без текста** — обнаружение «тихих» оценок по изменению распределения
- **Платежи** — уведомления о новых подтверждённых платежах (покупки и подписки)
- **Статистика** — текущий средний рейтинг и распределение оценок в каждом уведомлении

## Быстрый старт

### Docker Compose (рекомендуется)

1. Клонируйте репозиторий:

```bash
git clone https://github.com/isrofilov/rustore-monitor.git
cd rustore-monitor
```

2. Скопируйте `.env.example` в `.env` и заполните переменные:

```bash
cp .env.example .env
```

3. Запустите:

```bash
docker compose up -d
```

Docker Compose автоматически подхватывает переменные из `.env` файла и прокидывает их в контейнер через секцию `environment` в `docker-compose.yml`.

### Docker (без Compose)

```bash
docker run -d \
  --name rustore-monitor \
  --restart unless-stopped \
  --env-file .env \
  -v rustore-monitor:/data \
  isrofilov/rustore-monitor:latest
```

### Запуск из исходников

```bash
git clone https://github.com/isrofilov/rustore-monitor.git
cd rustore-monitor
pip install -r requirements.txt
python -m rustore_monitor
```

## Переменные окружения

| Переменная | Обязательная | Описание |
|---|---|---|
| `RUSTORE_KEY_ID` | да | ID ключа API RuStore |
| `RUSTORE_PRIVATE_KEY` | да | Приватный RSA-ключ в формате base64 |
| `RUSTORE_PACKAGE_NAME` | да | Имя пакета приложения (например, `com.example.app`) |
| `RUSTORE_APP_ID` | да | Числовой ID приложения из консоли RuStore |
| `TELEGRAM_BOT_TOKEN` | для Telegram | Токен Telegram-бота (получить у [@BotFather](https://t.me/BotFather)) |
| `TELEGRAM_CHAT_ID` | для Telegram | ID чата для уведомлений |
| `TELEGRAM_THREAD_ID` | нет | ID темы в супергруппе |
| `TELEGRAM_DOMAIN` | нет | Домен Telegram API (по умолчанию `api.telegram.org`) |
| `MATRIX_HOMESERVER` | для Matrix | URL домашнего сервера Matrix (например, `https://matrix.org`) |
| `MATRIX_ACCESS_TOKEN` | для Matrix | Токен доступа Matrix-пользователя |
| `MATRIX_ROOM_ID` | для Matrix | ID комнаты для уведомлений (например, `!abcdef:matrix.org`) |
| `POLL_INTERVAL` | нет | Интервал опроса в секундах (по умолчанию `300`) |
| `TZ_OFFSET` | нет | Смещение часового пояса в часах (например, `3` для UTC+3). По умолчанию — `3` (МСК) |

Настройте хотя бы один канал уведомлений — Telegram (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`) и/или Matrix (`MATRIX_HOMESERVER` + `MATRIX_ACCESS_TOKEN` + `MATRIX_ROOM_ID`). Можно включить оба одновременно — уведомления уйдут в каждый. Если ни один не настроен, бот завершится с ошибкой при старте.

## Получение ключей RuStore API

1. Откройте [Консоль RuStore](https://console.rustore.ru/)
2. Перейдите в раздел **Приложения** → **API RuStore**
3. Создайте новый ключ, выбрав следующие методы:
   - Получение списка продуктов приложения
   - Получение списка подписок приложения
   - Получение рейтинга приложения
   - Получение отзывов приложения
   - Получение данных платежа
4. Скопируйте `KEY_ID` и приватный ключ
5. `APP_ID` это номер вашего приложения в RuStore. Он указан в адресе страницы приложения в консоли (например: в `.../apps/123456/...` нужное значение — `123456`).

## Как получить `TELEGRAM_CHAT_ID`

Самый простой способ — добавить бота в целевой чат и написать туда любое сообщение, затем открыть:

```
https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/getUpdates
```

В ответе найдите `"chat":{"id": ...}`. Для супергрупп ID начинается с `-100`.

Для `TELEGRAM_THREAD_ID` — отправьте сообщение в нужную тему и посмотрите `message_thread_id` в том же ответе.

## Как получить реквизиты Matrix

1. **`MATRIX_HOMESERVER`** — адрес домашнего сервера, на котором зарегистрирован бот (например, `https://matrix.org` или ваш self-hosted сервер).
2. **`MATRIX_ACCESS_TOKEN`** — токен доступа пользователя-бота. В Element: **Настройки** → **Справка и информация** → **Дополнительно** → **Access Token**. Либо через API:

   ```bash
   curl -XPOST 'https://matrix.org/_matrix/client/v3/login' \
     -d '{"type":"m.login.password","user":"BOT_USER","password":"PASSWORD"}'
   ```

   В ответе — поле `access_token`.
3. **`MATRIX_ROOM_ID`** — внутренний ID комнаты (начинается с `!`, не путать с алиасом `#room:server`). В Element: **Настройки комнаты** → **Дополнительно** → **Внутренний ID комнаты**. Бот-пользователь должен быть участником этой комнаты.

### Как вступить ботом в комнату

Бот не сможет отправлять сообщения, пока не станет участником комнаты. Варианты:

- **Через клиент** — пригласите бота в комнату (по его `@user:server`) из любого Matrix-клиента, затем примите приглашение от имени бота.
- **Через API** — вступите напрямую токеном бота. Подходит и room ID (`!...`), и алиас (`#room:server`):

  ```bash
  curl -XPOST 'https://matrix.org/_matrix/client/v3/join/!abcdef:matrix.org' \
    -H 'Authorization: Bearer MATRIX_ACCESS_TOKEN' \
    -H 'Content-Type: application/json' -d '{}'
  ```

  В ответе вернётся `{"room_id":"!abcdef:matrix.org"}` — значит бот в комнате. Если комната приватная, бота сначала нужно туда пригласить, иначе вступление вернёт ошибку `M_FORBIDDEN`.

  Если вступаете по **алиасу**, символ `#` нужно заменить на `%23` (это разделитель фрагмента в URL), остальное можно оставить как есть: `.../join/%23room:matrix.org`.

## Первый запуск

При первом запуске бот сохраняет текущее состояние (отзывы, оценки, платежи) в БД и **не отправляет** уведомления за прошлый период — чтобы не засыпать чат историей. Уведомления начнут приходить со следующей итерации.

## Хранение состояния

Бот сохраняет состояние в SQLite-базе `/data/state.db` внутри контейнера. При использовании Docker Compose данные хранятся в именованном томе `rustore-monitor` и сохраняются между перезапусками.

## Лицензия

[MIT](LICENSE)
