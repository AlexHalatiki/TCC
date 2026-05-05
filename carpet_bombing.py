import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import pre_processamento

PASTA_GRAFICOS = "graficos/db-honeypot3-2026-04-08/carpet_bombing"

conn = sqlite3.connect(pre_processamento.PATH_ATAQUES_PROCESSADOS)
query = f"SELECT * FROM carpet_bombing"
df_ataques = pd.read_sql_query(query, conn)
df_ataques["tempoInicio"] = pd.to_datetime(df_ataques["tempoInicio"], errors="coerce")
df_ataques["tempoFinal"] = pd.to_datetime(df_ataques["tempoFinal"], errors="coerce")
conn.close()

# metricas gerais

total_ataques = len(df_ataques)
cidrs_counts = df_ataques["cidr"].value_counts()
total_cidrs_unicos = cidrs_counts.count()

total_carpet_bombing = len(df_ataques[df_ataques["ips_count"] > 1])

porcentagem_ataques_carpet_bombing = (
    total_carpet_bombing / total_ataques
) * 100

df_reincidentes = (
    df_ataques
    .groupby("cidr")
    .filter(lambda x: len(x) > 1)
)

total_reincidentes = len(df_reincidentes)
cidrs_reincidentes_qtd = df_reincidentes["cidr"].nunique()

porcentagem_cidrs_reincidentes = (
    cidrs_reincidentes_qtd / total_cidrs_unicos
) * 100

porcentagem_ataques_reincidentes = (
    total_reincidentes / total_ataques
) * 100

total_reincidentes_carpet_bombing = len(
    df_reincidentes[df_reincidentes["ips_count"] > 1]
)

porcentagem_ataques_reincidentes_carpet_bombing = (
    total_reincidentes_carpet_bombing / total_reincidentes
) * 100

df_reincidentes["intervalo"] = (
    df_reincidentes["tempoInicio"] -
    df_reincidentes.groupby("cidr")["tempoFinal"].shift()
)

intervalos_validos = df_reincidentes["intervalo"].dropna()

print(f"Total de ataques: {total_ataques}")
print(f"Ataques carpet_bombing: {total_carpet_bombing} ({porcentagem_ataques_carpet_bombing:.2f}%)")
print(f"Total de CIDRs únicos: {total_cidrs_unicos}")
print(f"CIDRs reincidentes: {cidrs_reincidentes_qtd} ({porcentagem_cidrs_reincidentes:.2f}%)")
print(f"Ataques reincidentes: {total_reincidentes} ({porcentagem_ataques_reincidentes:.2f}%)")
print(f"Ataques reincidentes carpet_bombing: {total_reincidentes_carpet_bombing} ({porcentagem_ataques_reincidentes_carpet_bombing:.2f}%)")

if not intervalos_validos.empty:
    intervalos_horas = intervalos_validos.dt.total_seconds() / 3600
    print("\n========== INTERVALO ENTRE ATAQUES REINCIDENTES ==========")
    print(f"Média (horas): {intervalos_horas.mean():.2f}")
    print(f"Mediana (horas): {intervalos_horas.median():.2f}")
    print(f"Maior intervalo (horas): {intervalos_horas.max():.2f}")
else:
    print("\nNenhum intervalo reincidente encontrado.")

print("\n========== TOP 10 CIDRS COM MAIS ATAQUES ==========")
print(cidrs_counts.head(10))

# GRAFICOS

# Ataques por bloco

plt.figure(figsize=(10, 6))
bins_cidr = np.logspace(np.log10(cidrs_counts.min()), np.log10(cidrs_counts.max()), 50)
plt.hist(cidrs_counts, bins=bins_cidr, edgecolor='black', alpha=0.7)
plt.yscale('log')
plt.xlabel('Quantidade de ataques', fontsize=12)
plt.ylabel('Número de CIDRs (log)', fontsize=12)
plt.title('Distribuição de ataques por CIDR', fontsize=14)
media = cidrs_counts.mean()
mediana = cidrs_counts.median()
plt.axvline(media, color='red', linestyle='--', alpha=0.7, label=f'Média: {media:.2f} ataques')
plt.axvline(mediana, color='green', linestyle='--', alpha=0.7, label=f'Mediana: {mediana:.2f} ataques')
plt.legend()
plt.grid(True, which="both", ls="-", alpha=0.2)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/ataques_por_cidr.png", dpi=300)
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
    intervalos_horas = intervalos_validos.dt.total_seconds() / 3600
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

MIN_ATAQUES = 20
cidrs_100 = cidrs_counts[cidrs_counts >= MIN_ATAQUES].index
df_100 = df_reincidentes[df_reincidentes["cidr"].isin(cidrs_100)].copy()

# Calcular CV por vitima

df_cv = (
    df_100
    .dropna(subset=["intervalo"])
    .groupby("cidr")
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
df_top5 = df_reincidentes[df_reincidentes["cidr"].isin(top5_vitimas_regulares["cidr"])]
df_top5["hora"] = df_top5["tempoInicio"].dt.hour

plt.figure(figsize=(10,6))
for cidr in top5_vitimas_regulares["cidr"]:
    horas = df_top5[df_top5["cidr"] == cidr]["hora"]
    counts = horas.value_counts().sort_index()
    plt.plot(counts.index, counts.values, marker="o", label=cidr)
plt.xlabel("Hora do dia")
plt.ylabel("Número de ataques")
plt.title("Distribuição de ataques por hora (CV <= 0.8)")
plt.xticks(range(24))
plt.legend(title="CIDR vítima")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/reincidentes_por_hora.png", dpi=300)
plt.close()


plt.figure(figsize=(10,6))
# loop por CIDR
for cidr in top5_vitimas_regulares["cidr"]:
    df_cidr = df_top5[df_top5["cidr"] == cidr].copy()
    df_cidr = df_cidr.dropna(subset=["intervalo"])
    # converte para minutos
    intervalos_minutos = (df_cidr["intervalo"].dt.total_seconds() / 60)
    intervalos_minutos = (10 * (intervalos_minutos / 10).round()).astype(int) # minutos multiplos de 10
    # cria um 'histograma de linha' usando value_counts
    counts = pd.Series(intervalos_minutos).value_counts().sort_index()
    plt.plot(counts.index, counts.values, marker="o", label=cidr)
plt.xlabel("Intervalo entre ataques (minutos)")
plt.ylabel("Número de ataques")
plt.title("Distribuição do intervalo entre ataques (CV <= 0.8)")
plt.grid(alpha=0.3)
plt.legend(title="CIDR vítima")
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/intervalo_reincidentes_minuto.png", dpi=300)
plt.close()