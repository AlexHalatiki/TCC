import sqlite3
import pandas as pd
import os
import matplotlib.pyplot as plt
import numpy as np


def consolidar_ataques(df_ip):
    ataques = []

    inicio_atual = None
    fim_atual = None
    count_total = 0
    tables = set()

    for row in df_ip.itertuples(index=False):
        inicio = row.tempoInicio
        fim = row.tempoFinal
        count = row.count
        table = row.table

        if inicio_atual is None:
            inicio_atual = inicio
            fim_atual = fim
            count_total = count
            tables = {table}
        else:
            if inicio <= fim_atual:
                fim_atual = max(fim_atual, fim)
                count_total += count
                tables.add(table)
            else:
                ataques.append({
                    "tempoInicio": inicio_atual,
                    "tempoFinal": fim_atual,
                    "count": count_total,
                    "table": list(tables)
                })

                inicio_atual = inicio
                fim_atual = fim
                count_total = count
                tables = {table}

    if inicio_atual is not None:
        ataques.append({
            "tempoInicio": inicio_atual,
            "tempoFinal": fim_atual,
            "count": count_total,
            "table": list(tables)
        })

    return ataques


PASTA = "db-honeypots/database-br-2025-10-17"
PASTA_GRAFICOS = "graficos"

dados_completos = []

for arquivo in os.listdir(PASTA):
    if "6" not in arquivo and arquivo.endswith(".sqlite"):
        caminho = os.path.join(PASTA, arquivo)

        conn = sqlite3.connect(caminho)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tabelas = cursor.fetchall()

        tabela_memoria = None
        for (nome_tabela,) in tabelas:
            if nome_tabela.endswith("MEMORY_DICT"):
                tabela_memoria = nome_tabela
                break
        
        if not tabela_memoria:
            print(f"{arquivo} → Tabela MEMORY_DICT não encontrada.")
            conn.close()
            exit()

        query = f"SELECT * FROM {tabela_memoria}"
        df = pd.read_sql_query(query, conn)

        df["tempoInicio"] = pd.to_datetime(df["tempoInicio"], errors="coerce")
        df["tempoFinal"] = pd.to_datetime(df["tempoFinal"], errors="coerce")
        df["table"] = tabela_memoria

        dados_completos.append(df)

        conn.close()

# juntar bases

df_raw = pd.concat(dados_completos, ignore_index=True)

# consolidar ataques (multiprotocolo)

df_raw = df_raw.sort_values(["ip", "tempoInicio"])
ataques_consolidados = []

for ip, grupo in df_raw.groupby("ip"):
    sessoes = consolidar_ataques(grupo)

    for sessao in sessoes:
        sessao["ip"] = ip

    ataques_consolidados.extend(sessoes)

df_ataques = pd.DataFrame(ataques_consolidados)

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

df_reincidentes_protocolos = df_reincidentes.explode("table")
ataques_por_protocolo = (
    df_reincidentes_protocolos["table"]
    .value_counts()
    .sort_values(ascending=False)
)

porcentagem_por_protocolo = (
    ataques_por_protocolo / total_reincidentes
) * 100

# multiprotocolo

df_reincidentes = df_reincidentes.sort_values(["ip", "tempoInicio"])
df_reincidentes["multiprotocolo"] = (
    df_reincidentes["table"].apply(lambda x: len(x) > 1)
)

total_multiprotocolo = df_reincidentes["multiprotocolo"].sum()

porcentagem_multiprotocolo = (
    total_multiprotocolo / total_reincidentes
) * 100 if total_reincidentes > 0 else 0

# intervalo entre ataques

df_reincidentes["intervalo"] = (
    df_reincidentes["tempoInicio"] -
    df_reincidentes.groupby("ip")["tempoFinal"].shift()
)

intervalos_validos = df_reincidentes["intervalo"].dropna()

print(f"Total de ataques: {total_ataques}")
print(f"Total de IPs únicos: {total_ips_unicos}")
print(f"IPs reincidentes: {ips_reincidentes_qtd} ({porcentagem_ips_reincidentes:.2f}%)")
print(f"Ataques reincidentes: {total_reincidentes} ({porcentagem_ataques_reincidentes:.2f}%)")
print(f"Ataques reincidentes multiprotocolo: {total_multiprotocolo} ({porcentagem_multiprotocolo:.2f}%)")

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
plt.xlabel('Quantidade de ataques por IP', fontsize=12)
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