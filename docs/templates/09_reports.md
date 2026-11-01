# Отчётность — кейс 3

Правила подсчёта для всех отчётов:
- tips_total, avg_tip_pct, avg_tip_amount считаются только по платежам со статусом SUCCESS (чаевые, которые реально дошли);
- payments_count и success_rate считаются по всем платежам периода.

## 1. Отчёт по мерчанту (образец)

**Endpoint:** `GET /api/v1/reports/tips?merchant_id=m_001&from=2025-11-01&to=2025-11-30`

| Метрика | Формула | Пример |
|---|---|---|
| tips_total | sum(tip) | 550.00 |
| payments_count | count(payments) | 4 |
| avg_tip_pct | avg(tip / amount × 100) | 10.0 |
| success_rate | count(SUCCESS) / count(*) | 0.75 |

Пример ответа:

```json
{
  "merchant_id": "m_001",
  "period": "2025-11",
  "tips_total": 550.00,
  "payments_count": 4,
  "avg_tip_pct": 10.0,
  "success_rate": 0.75
}
```

Тот же отчёт по данным payments.csv (у m_001 шесть платежей, пять SUCCESS и один DECLINED):

```json
{
  "merchant_id": "m_001",
  "period": "2025-11",
  "tips_total": 414.85,
  "payments_count": 6,
  "avg_tip_pct": 9.0,
  "success_rate": 0.83
}
```

## 2. Отчёт по официанту

**Endpoint:** `GET /api/v1/reports/tips?employee_id=e_001&from=2025-11-01&to=2025-11-30`

| Метрика | Формула | Пример (e_001) |
|---|---|---|
| tips_total | sum(tip) по платежам SUCCESS официанта | 83.60 |
| payments_count | count(payments) официанта | 2 |
| avg_tip_amount | tips_total / count(SUCCESS) | 41.80 |
| top_day | день с максимальной суммой чаевых | 2025-11-03 |

Пример ответа:

```json
{
  "employee_id": "e_001",
  "period": "2025-11",
  "tips_total": 83.60,
  "payments_count": 2,
  "avg_tip_amount": 41.80,
  "top_day": "2025-11-03"
}
```

Расчёт: у e_001 два успешных платежа, p_0001 (чаевые 31.85, 01.11) и p_0055 (чаевые 51.75, 03.11). Сумма 83.60, среднее 41.80, лучший день 03.11.

## 3. Отчёт по дням

**Endpoint:** `GET /api/v1/reports/tips/daily?merchant_id=m_001&from=2025-11-01&to=2025-11-30`

| Метрика | Формула | Пример |
|---|---|---|
| date | — | 2025-11-01 |
| tips_total | sum(tip) за день (SUCCESS) | 245.90 |
| payments_count | count за день | 3 |
| avg_tip_pct | avg(tip / amount × 100) за день (SUCCESS) | 10.0 |

Пример ответа (по данным payments.csv для m_001):

```json
{
  "merchant_id": "m_001",
  "daily": [
    {"date": "2025-11-01", "tips_total": 245.90, "payments_count": 3, "avg_tip_pct": 10.0},
    {"date": "2025-11-03", "tips_total": 168.95, "payments_count": 3, "avg_tip_pct": 7.5}
  ]
}
```

Проверка: 01.11 три успешных платежа (31.85 + 77.40 + 136.65 = 245.90); 03.11 три платежа, из них два успешных (51.75 + 117.20 = 168.95), один DECLINED.

## 4. Критерий приёмки

- [x] Три разреза: мерчант, официант, по дням
- [x] Метрики с формулами
- [x] Примеры ответов в JSON
- [x] Данные сходятся с payments.csv
- [x] Указаны endpoint'ы
