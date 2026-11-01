
## 1. Сущности (6)

| Сущность | Что хранит | Зачем |
|---|---|---|
| Merchant | merchant_id, name, status, description | справочник мерчантов |
| Employee | employee_id, merchant_id, name, payment_details | официанты ресторана, получатели чаевых |
| QR | qr_id, merchant_id, employee_id, receipt_id, nonce, exp, signature | одноразовая подписанная ссылка на оплату по чеку |
| Payment | payment_id, qr_id, amount, tip, status, timestamp | факт оплаты: чек плюс чаевые |
| Report | report_id, merchant_id, period, tips_total | агрегаты для отчётности |
| AuditEvent | event_id, payment_id, qr_id, action, from_status, to_status, actor, at | журнал событий для разбора |

## 2. Атрибуты

### 2.1. Merchant (образец)

| Поле | Тип | PK/FK | Обяз. | Ограничение |
|---|---|---|---|---|
| merchant_id | string | PK | да | m_NNN |
| name | string | — | да | 1–100 |
| status | enum | — | да | ACTIVE/BLOCKED/PENDING |
| description | string | — | нет | 0–200 |

### 2.2. Employee

| Поле | Тип | PK/FK | Обяз. | Ограничение |
|---|---|---|---|---|
| employee_id | string | PK | да | e_NNN |
| merchant_id | string | FK → Merchant | да | m_NNN |
| name | string | — | да | 1–100 |
| payment_details | string | — | да | только маска `****NNNN` |

### 2.3. QR

| Поле | Тип | PK/FK | Обяз. | Ограничение |
|---|---|---|---|---|
| qr_id | string | PK | да | qr_NNN |
| merchant_id | string | FK → Merchant | да | m_NNN |
| employee_id | string | FK → Employee | да | e_NNN, сотрудник этого мерчанта |
| receipt_id | string | — | да | r_NNNN, уникален для мерчанта |
| nonce | string | — | да | 6 hex, одноразовый |
| exp | datetime | — | да | ISO 8601, TTL 24 ч |
| signature | string | — | да | HMAC-SHA256, 16 hex |

### 2.4. Payment

| Поле | Тип | PK/FK | Обяз. | Ограничение |
|---|---|---|---|---|
| payment_id | string | PK | да | p_NNNN |
| qr_id | string | FK → QR | да | qr_NNN |
| amount | decimal | — | да | > 0, ≤ 1 000 000 |
| tip | decimal | — | да | ≥ 0, ≤ amount × 0.5 |
| status | enum | — | да | CREATED/PENDING/SUCCESS/DECLINED/CANCELED |
| timestamp | datetime | — | да | ISO 8601 |

### 2.5. Report

| Поле | Тип | PK/FK | Обяз. | Ограничение |
|---|---|---|---|---|
| report_id | string | PK | да | rep_NNNN |
| merchant_id | string | FK → Merchant | да | m_NNN |
| period | string | — | да | YYYY-MM |
| tips_total | decimal | — | да | ≥ 0 |

### 2.6. AuditEvent

| Поле | Тип | PK/FK | Обяз. | Ограничение |
|---|---|---|---|---|
| event_id | string | PK | да | evt_NNNN |
| payment_id | string | FK → Payment | да | p_NNNN |
| qr_id | string | — | да | qr_NNN (для разбора без обращения к Payment) |
| action | enum | — | да | payment_created / payment_confirmed / payment_declined / payment_canceled |
| from_status | enum | — | нет | пусто при создании платежа |
| to_status | enum | — | да | CREATED/PENDING/SUCCESS/DECLINED/CANCELED |
| actor | enum | — | да | system / client / officer |
| at | datetime | — | да | ISO 8601 |

## 3. Связи

| Связь | Тип | Обоснование |
|---|---|---|
| Merchant → Employee | 1:N | у ресторана много официантов, официант работает в одном ресторане |
| Merchant → QR | 1:N | ресторан создаёт много QR, каждый QR принадлежит одному ресторану |
| Employee → QR | 1:N | у официанта много QR (по одному на чек) |
| QR → Payment | 1:N | по одному QR может быть несколько попыток платежа |
| Merchant → Report | 1:N | у ресторана по одному отчёту за каждый месяц |
| Payment → AuditEvent | 1:N | каждый переход статуса платежа это отдельное событие аудита |

## 4. Диаграмма (draw.io)

Файл диаграммы: `er_diagram.png` (будет добавлен).

## 5. Критерий приёмки

- [x] 6 сущностей описаны
- [x] Для каждой сущности указаны PK/FK, типы и ограничения
- [x] Связи описаны с типом (1:N) и обоснованием
- [x] payment_details — только маска `****NNNN`
- [x] signature — HMAC-SHA256, не plain hash
- [ ] Диаграмма в draw.io с PK/FK и связями
