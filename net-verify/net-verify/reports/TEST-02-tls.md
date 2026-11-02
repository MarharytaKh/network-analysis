# TEST-02: TLS рукопожатие

**Дата:** 
**Исполнитель:** 
**Файл захвата:** `captures/test02_tls.pcap`

## Цель

Померить время от ClientHello до ServerHello на https-запросах.

## Окружение

- Клиент:
- Сервер:
- Версия TLS (ожидаем):

## Процедура

1. Фильтр: `tcp port 443`
2. 15 запросов через `curl -sS -o /dev/null https://...`
3. analyzer

```
python3 analyzer.py captures/test02_tls.pcap --json reports/test02_tls.json
```

## Результаты

- ClientHello: 
- ServerHello: 
- ClientHello -> ServerHello (median / p95): 
- TCP RTT (median): 

## Выводы

- 
