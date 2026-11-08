# Data dictionary — кейс 3

## Как заполнять

Четыре файла: merchants (4 колонки), employees (4), payments (7), qr_links (7).
Два образца — по merchants и payments. Остальные — заполни сам.

## Образец merchants (не трогать)

| Файл | Поле | Тип | Обяз. | Ограничение | Пример | Код ошибки |
|---|---|---|---|---|---|---|
| merchants | merchant_id | string | да | m_NNN | m_001 | — |
| merchants | name | string | да | 1–100 символов | Вкус-Сервис Тверская | — |
| merchants | status | enum | да | ACTIVE/BLOCKED/PENDING | ACTIVE | MERCHANT_BLOCKED |
| merchants | description | string | нет | 0–200 | Ресторан сети | — |

## Образец payments (не трогать)

| Файл | Поле | Тип | Обяз. | Ограничение | Пример | Код ошибки |
|---|---|---|---|---|---|---|
| payments | payment_id | string | да | p_NNNN | p_0001 | — |
| payments | amount | decimal | да | > 0, ≤ 1 000 000 | 637.00 | AMOUNT_OUT_OF_RANGE |
| payments | tip | decimal | да | ≥ 0, ≤ amount × 0.5 | 63.70 | TIP_OUT_OF_RANGE |
| payments | status | enum | да | CREATED/PENDING/SUCCESS/DECLINED/CANCELED | SUCCESS | — |
| payments | merchant_id | string | да | m_NNN | m_001 | MERCHANT_NOT_FOUND |
| payments | employee_id | string | да | e_NNN | e_001 | EMPLOYEE_NOT_FOUND |
| payments | timestamp | datetime | да | ISO 8601 | 2025-11-01T18:00:00Z | — |

## Твоя таблица — employees

| Поле | Тип | Обяз. | Ограничение | Пример | Код ошибки |
|---|---|---|---|---|---|
| employee_id | string | да | e_NNN, уникален | e_001 | — |
| merchant_id | string | да | m_NNN, ссылка на merchants.merchant_id | m_001 | MERCHANT_NOT_FOUND |
| name | string | да | 1–100 символов | Иван Петров | — |
| payment_details | string | да | только маска ****NNNN (ровно 4 последние цифры), полный номер не хранится | ****1234 | INVALID_PAYMENT_DETAILS |

## Твоя таблица — qr_links

| Поле | Тип | Обяз. | Ограничение | Пример | Код ошибки |
|---|---|---|---|---|---|
| qr_id | string | да | qr_NNN, уникален | qr_001 | — |
| merchant_id | string | да | m_NNN, ссылка на merchants.merchant_id | m_001 | MERCHANT_NOT_FOUND |
| employee_id | string | да | e_NNN, ссылка на employees.employee_id | e_001 | EMPLOYEE_NOT_FOUND |
| receipt_id | string | да | r_NNNN, уникален для мерчанта | r_1001 | — |
| nonce | string | да | одноразовый, ровно 6 hex-символов | c82561 | QR_USED |
| exp | datetime | да | ISO 8601 UTC, > now, обычно now + 24 ч | 2025-11-01T23:59:00Z | QR_EXPIRED |
| signature | string | да | HMAC-SHA256, 16 hex-символов | 68d0f361ac38c12b | INVALID_QR |

## Критерий приёмки

- [x] Все 4 файла описаны (22 колонки)
- [x] Для каждого поля указан тип и ограничение
- [x] Для полей с валидацией — код ошибки из 07_payment_emulator_template.md §7
- [x] Пример взят из реального CSV
- [x] payment_details — только маска (****NNNN)

## Подсказки

- payment_details — это реквизиты для выплат, не для оплаты.
- nonce — одноразовый, 6 hex.
- exp — время, после которого QR недействителен (обычно 24 ч).
- signature — HMAC-SHA256, 16 hex.