import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import pre_processamento

PASTA_GRAFICOS = "graficos/db-honeypot-v6-2026-04-08/multiprotocolo"

conn = sqlite3.connect(pre_processamento.PATH_ATAQUES_PROCESSADOS)
query = f"SELECT * FROM multiprotocol"
df_ataques = pd.read_sql_query(query, conn)
df_ataques["tempoInicio"] = pd.to_datetime(df_ataques["tempoInicio"], errors="coerce")
df_ataques["tempoFinal"] = pd.to_datetime(df_ataques["tempoFinal"], errors="coerce")
conn.close()

# metricas gerais

total_ataques = len(df_ataques)
ip_counts = df_ataques["ip"].value_counts()
total_ips_unicos = ip_counts.count()

# filtrar reincidentes

df_reincidentes = (
    df_ataques
    .groupby("ip")
    .filter(lambda x: len(x) > 1)
)

total_reincidentes = len(df_reincidentes)
ips_reincidentes_qtd = df_reincidentes["ip"].nunique()

porcentagem_ips_reincidentes = (
    ips_reincidentes_qtd / total_ips_unicos
) * 100

porcentagem_ataques_reincidentes = (
    total_reincidentes / total_ataques
) * 100

cols = [
    "countNTP", "countDNS", "countCLDAP", "countQOTD",
    "countCHARGEN", "countSSDP", "countMEMCACHED", "countCOAP"
]
def protocolos_ativos(row):
    return [col for col in cols if row[col] > 0]
df_reincidentes["protocolos"] = df_reincidentes.apply(protocolos_ativos, axis=1)
df_exploded = df_reincidentes.explode("protocolos")
ataques_por_protocolo = (
    df_exploded["protocolos"]
    .value_counts()
    .sort_values(ascending=False)
)

porcentagem_por_protocolo = (
    ataques_por_protocolo / total_reincidentes
) * 100

# multiprotocolo

total_multiprotocolo = ((df_ataques[cols] > 0).sum(axis=1) > 1).sum()

porcentagem_multiprotocolo = (
    total_multiprotocolo / total_ataques
) * 100

df_reincidentes = df_reincidentes.sort_values(["ip", "tempoInicio"])
df_reincidentes["multiprotocolo"] = (
    (df_reincidentes[cols] > 0).sum(axis=1) > 1
)

total_reincidentes_multiprotocolo = df_reincidentes["multiprotocolo"].sum()

porcentagem_reincidentes_multiprotocolo = (
    total_reincidentes_multiprotocolo / total_reincidentes
) * 100 if total_reincidentes > 0 else 0

# intervalo entre ataques

df_reincidentes["intervalo"] = (
    df_reincidentes["tempoInicio"] -
    df_reincidentes.groupby("ip")["tempoFinal"].shift()
)

intervalos_validos = df_reincidentes["intervalo"].dropna()

print(f"Total de ataques: {total_ataques}")
print(f"Ataques multiprotocolo: {total_multiprotocolo} ({porcentagem_multiprotocolo:.2f}%)")
print(f"Total de IPs únicos: {total_ips_unicos}")
print(f"IPs reincidentes: {ips_reincidentes_qtd} ({porcentagem_ips_reincidentes:.2f}%)")
print(f"Ataques reincidentes: {total_reincidentes} ({porcentagem_ataques_reincidentes:.2f}%)")
print(f"Ataques reincidentes multiprotocolo: {total_reincidentes_multiprotocolo} ({porcentagem_reincidentes_multiprotocolo:.2f}%)")

if not intervalos_validos.empty:
    intervalos_horas = intervalos_validos.dt.total_seconds() / 3600
    print("\n========== INTERVALO ENTRE ATAQUES REINCIDENTES ==========")
    print(f"Média (horas): {intervalos_horas.mean():.2f}")
    print(f"Mediana (horas): {intervalos_horas.median():.2f}")
    print(f"Maior intervalo (horas): {intervalos_horas.max():.2f}")
else:
    print("\nNenhum intervalo reincidente encontrado.")

print("\n========== ATAQUES REINCIDENTES POR PROTOCOLO ==========")
for protocolo, qtd in ataques_por_protocolo.items():
    print(f"{protocolo}: {qtd} ataques ({porcentagem_por_protocolo[protocolo]:.2f}%)")

# GRAFICOS

# Ataques por ip

plt.figure(figsize=(10, 6))
bins_ip = np.logspace(np.log10(ip_counts.min()), np.log10(ip_counts.max()), 50)
plt.hist(ip_counts, bins=bins_ip, edgecolor='black', alpha=0.7)
plt.yscale('log')
plt.xlabel('Quantidade de ataques', fontsize=12)
plt.ylabel('Número de IPs (log)', fontsize=12)
plt.title('Distribuição de ataques por IP', fontsize=14)
media = ip_counts.mean()
mediana = ip_counts.median()
plt.axvline(media, color='red', linestyle='--', alpha=0.7, label=f'Média: {media:.2f} ataques')
plt.axvline(mediana, color='green', linestyle='--', alpha=0.7, label=f'Mediana: {mediana:.2f} ataques')
plt.legend()
plt.grid(True, which="both", ls="-", alpha=0.2)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/ataques_por_ip.png", dpi=300)
plt.close()

# Duracao dos ataques

df_ataques["duracao_horas"] = (
    (df_ataques["tempoFinal"] - df_ataques["tempoInicio"])
    .dt.total_seconds() / 3600
)
duracoes = df_ataques["duracao_horas"].dropna()
# filtrar durações muito pequenas
duracoes = duracoes[duracoes > 1e-6]
plt.figure(figsize=(12, 6))
plt.hist(duracoes, bins=50, edgecolor='black', alpha=0.7, color='steelblue')
plt.yscale('log')
plt.xlabel('Duração do ataque (horas)', fontsize=12)
plt.ylabel('Número de ataques (log)', fontsize=12)
plt.title('Distribuição da Duração dos Ataques', fontsize=14)
# grade para melhor leitura
plt.grid(True, alpha=0.3, linestyle='--')
media = duracoes.mean()
mediana = duracoes.median()
plt.axvline(media, color='red', linestyle='--', alpha=0.7, label=f'Média: {media:.2f} horas')
plt.axvline(mediana, color='green', linestyle='--', alpha=0.7, label=f'Mediana: {mediana:.2f} horas')
plt.legend()
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/duracao_ataques_horas.png", dpi=300)
plt.close()

# Intervalo entre reincidentes
if not intervalos_validos.empty:
    intervalos_dias = intervalos_horas / 24
    intervalos_dias = intervalos_dias[intervalos_dias > 0]  # remover zeros
    plt.figure(figsize=(12, 6))
    plt.hist(intervalos_dias, bins=50, edgecolor='black', alpha=0.7, color='steelblue')
    plt.yscale('log')
    plt.xlabel('Intervalo entre ataques (dias)', fontsize=12)
    plt.ylabel('Número de ataques (log)', fontsize=12)
    plt.title('Distribuição do Intervalo entre Ataques Reincidentes', fontsize=14)
    # grade para melhor leitura
    plt.grid(True, alpha=0.3, linestyle='--') 
    media = intervalos_dias.mean()
    mediana = intervalos_dias.median()
    plt.axvline(media, color='red', linestyle='--', alpha=0.7, 
                label=f'Média: {media:.2f} dias')
    plt.axvline(mediana, color='green', linestyle='--', alpha=0.7, 
                label=f'Mediana: {mediana:.2f} dias')
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/intervalo_reincidentes_dias.png", dpi=300)
    plt.close()

# Protocolos mais utilizados em reincidentes (mais de 0.1%)

protocolos_filtrados = porcentagem_por_protocolo[porcentagem_por_protocolo > 0.1] 
plt.figure(figsize=(12, 6))
bars = plt.bar(range(len(protocolos_filtrados)), protocolos_filtrados.values)
plt.xticks(range(len(protocolos_filtrados)), 
           [p.replace('_MEMORY_DICT', '') for p in protocolos_filtrados.index], 
           rotation=45, ha='right', fontsize=10)
plt.ylabel('Porcentagem de ataques reincidentes (%)', fontsize=12)
plt.title('Distribuição de ataques reincidentes por protocolo (>0.1%)', fontsize=14)
# adicionar valores nas barras
for bar, val in zip(bars, protocolos_filtrados.values):
    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
             f'{val:.1f}%', ha='center', va='bottom', fontsize=9)
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/reincidentes_por_protocolo.png", dpi=300)
plt.close()

# Ataques por hora do dia

df_ataques["hora"] = df_ataques["tempoInicio"].dt.hour
ataques_por_hora = df_ataques.groupby("hora").size()
plt.figure(figsize=(10,6))
plt.bar(ataques_por_hora.index, ataques_por_hora.values)
plt.xlabel("Hora do dia")
plt.ylabel("Número de ataques")
plt.title("Distribuição de ataques por hora do dia")
plt.xticks(range(24))
plt.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/ataques_por_hora.png", dpi=300)
plt.close()

MIN_ATAQUES = 2
ips_100 = ip_counts[ip_counts >= MIN_ATAQUES].index
df_100 = df_reincidentes[df_reincidentes["ip"].isin(ips_100)].copy()

# Calcular CV por vitima

df_cv = (
    df_100
    .dropna(subset=["intervalo"])
    .groupby("ip")
    .agg(
        ataques=("intervalo", "count"),
        media=("intervalo", "mean"),
        desvio=("intervalo", "std")
    )
)
df_cv["cv"] = df_cv["desvio"] / df_cv["media"]
df_cv = df_cv.reset_index()

# Regularidade dos ataques por vitima

plt.figure(figsize=(10,6))
plt.scatter(
    df_cv["ataques"],
    df_cv["cv"],
    alpha=0.7
)
plt.axhline(0.8, color='red', linestyle='--', label='Limiar CV = 0.8')
plt.xlabel("Número de ataques da vítima")
plt.ylabel("Coeficiente de variação (CV)")
plt.title("Regularidade dos ataques por vítima")
plt.grid(True, alpha=0.3)
plt.legend()
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/cv_intervalos_vitimas.png", dpi=300)
plt.close()

# Distribuicao da regularidade dos ataques

plt.figure(figsize=(10,6))
plt.hist(df_cv["cv"], bins=40, edgecolor="black", alpha=0.7)
plt.axvline(0.8, color='red', linestyle='--', label='Limiar CV = 0.8')
plt.yscale('log')
plt.xlabel("Coeficiente de Variação (CV)")
plt.ylabel("Número de vítimas (log)")
plt.title("Distribuição da regularidade dos ataques")
plt.grid(True, alpha=0.3)
plt.legend()
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/distribuicao_cv_vitimas.png", dpi=300)
plt.close()

# Ataques por hora para vítimas reincidentes

df_cv_filtrado = df_cv[df_cv["cv"] <= 0.8]
top5_vitimas_regulares = df_cv_filtrado.nlargest(5, "ataques")
df_top5 = df_reincidentes[df_reincidentes["ip"].isin(top5_vitimas_regulares["ip"])]
df_top5["hora"] = df_top5["tempoInicio"].dt.hour

plt.figure(figsize=(10,6))
for ip in top5_vitimas_regulares["ip"]:
    horas = df_top5[df_top5["ip"] == ip]["hora"]
    counts = horas.value_counts().sort_index()
    plt.plot(counts.index, counts.values, marker="o", label=ip)
plt.xlabel("Hora do dia")
plt.ylabel("Número de ataques")
plt.title("Distribuição de ataques por hora (CV <= 0.8)")
plt.xticks(range(24))
plt.legend(title="IP vítima")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/reincidentes_por_hora.png", dpi=300)
plt.close()


plt.figure(figsize=(10,6))
# loop por IP
for ip in top5_vitimas_regulares["ip"]:
    df_ip = df_top5[df_top5["ip"] == ip].copy()
    df_ip = df_ip.dropna(subset=["intervalo"])
    # converte para minutos
    intervalos_minutos = (df_ip["intervalo"].dt.total_seconds() / 60)
    intervalos_minutos = (10 * (intervalos_minutos / 10).round()).astype(int) # minutos multiplos de 10
    # cria um 'histograma de linha' usando value_counts
    counts = pd.Series(intervalos_minutos).value_counts().sort_index()
    plt.plot(counts.index, counts.values, marker="o", label=ip)
plt.xlabel("Intervalo entre ataques (minutos)")
plt.ylabel("Número de ataques")
plt.title("Distribuição do intervalo entre ataques (CV <= 0.8)")
plt.grid(alpha=0.3)
plt.legend(title="IP vítima")
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/intervalo_reincidentes_minuto.png", dpi=300)
plt.close()

