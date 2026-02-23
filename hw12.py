"""
Скрипт для обработки ДЗ№12
Модуль читает .pcap файл захваченного трафика и создает
графическое представление Топ-10 IP-адресов источника
"""
import asyncio
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Фикс ошибки asyncio для Windows
asyncio.set_event_loop(asyncio.new_event_loop())

# Указываем путь к файлу дампа
PCAP_FILE = '2026-02-03-GuLoader-for-AgentTesla-style-infection-with-FTP-data-exfil.pcap'

# Извлекаем IP-адреса и DNS-запросы
capture = pyshark.FileCapture(PCAP_FILE, display_filter='ip or dns')

network_data = []

# Лимит пакетов для быстрой обработки
for pkt in capture:
    try:
        row = {
            'timestamp': pkt.sniff_time,
            'src_ip': pkt.ip.src,
            'dst_ip': pkt.ip.dst,
            'protocol': pkt.highest_layer
        }

        # Извлечение DNS артефактов
        if 'DNS' in pkt:
            row['dns_query'] = pkt.dns.qry_name

        network_data.append(row)
    except AttributeError:
        continue

capture.close()

# Создание датафрейма для анализа
df = pd.DataFrame(network_data)

# Визуализация результатов
sns.set_theme(style="whitegrid")
plt.figure(figsize=(12, 6))

# Топ-10 активных IP-адресов
top_ips = df['src_ip'].value_counts().head(10)
plot = sns.barplot(
    x=top_ips.values,
    y=top_ips.index,
    hue=top_ips.index,
    palette="mako",
    legend=False
)

plt.title('Топ-10 активных IP-адресов', fontsize=16)
plt.xlabel('Количество пакетов', fontsize=12)
plt.ylabel('IP-адрес', fontsize=12)

# Добавление подписей к барам
for i in plot.containers:
    plot.bar_label(i, padding=3)

plt.tight_layout()
plt.show()

# Сохранение результатов в CSV
df.to_csv('network_artifacts.csv', index=False)
