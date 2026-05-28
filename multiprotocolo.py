import os
import sqlite3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

import pre_processamento

PASTA_GRAFICOS = "graficos/multiprotocolo"
os.makedirs(PASTA_GRAFICOS, exist_ok=True)

conn = sqlite3.connect(pre_processamento.PATH_ATAQUES_PROCESSADOS)
query = "SELECT * FROM multiprotocol"
df_ataques = pd.read_sql_query(query, conn)
df_ataques["tempoInicio"] = pd.to_datetime(df_ataques["tempoInicio"], errors="coerce")
df_ataques["tempoFinal"] = pd.to_datetime(df_ataques["tempoFinal"], errors="coerce")
conn.close()

# ============================================================
# MÉTRICAS GERAIS
# ============================================================

total_ataques = len(df_ataques)
ip_counts = df_ataques["ip"].value_counts()
total_ips_unicos = ip_counts.count()

cols = [
    "countNTP", "countDNS", "countCLDAP", "countQOTD",
    "countCHARGEN", "countSSDP", "countMEMCACHED", "countCOAP"
]

# Garante que colunas count inexistentes não quebrem o script
for col in cols:
    if col not in df_ataques.columns:
        df_ataques[col] = 0

if "countTotal" not in df_ataques.columns:
    df_ataques["countTotal"] = df_ataques[cols].sum(axis=1)

# Duração dos ataques

df_ataques["duracao_horas"] = (
    (df_ataques["tempoFinal"] - df_ataques["tempoInicio"])
    .dt.total_seconds() / 3600
)

# Quantidade de protocolos por ataque

df_ataques["qtd_protocolos"] = (df_ataques[cols] > 0).sum(axis=1)
df_ataques["multiprotocolo"] = df_ataques["qtd_protocolos"] > 1

# Quantidade de instâncias por ataque
# A coluna instancias vem como string separada por ; no banco.

if "instancias" in df_ataques.columns:
    df_ataques["qtd_instancias"] = df_ataques["instancias"].apply(
        lambda x: len([i for i in str(x).split(";") if i.strip()])
        if pd.notna(x) and str(x).strip() != ""
        else 0
    )
else:
    df_ataques["qtd_instancias"] = 0

df_ataques["multi_instancia"] = df_ataques["qtd_instancias"] > 1

# Filtrar reincidentes

ips_reincidentes = ip_counts[ip_counts > 1].index

df_ataques["vitima_reincidente"] = df_ataques["ip"].isin(ips_reincidentes)

df_reincidentes = (
    df_ataques[df_ataques["vitima_reincidente"]]
    .copy()
    .sort_values(["ip", "tempoInicio"])
)

total_reincidentes = len(df_reincidentes)
ips_reincidentes_qtd = df_reincidentes["ip"].nunique()

porcentagem_ips_reincidentes = (
    ips_reincidentes_qtd / total_ips_unicos
) * 100 if total_ips_unicos > 0 else 0

porcentagem_ataques_reincidentes = (
    total_reincidentes / total_ataques
) * 100 if total_ataques > 0 else 0

total_multiprotocolo = df_ataques["multiprotocolo"].sum()

porcentagem_multiprotocolo = (
    total_multiprotocolo / total_ataques
) * 100 if total_ataques > 0 else 0

total_reincidentes_multiprotocolo = df_reincidentes["multiprotocolo"].sum()

porcentagem_reincidentes_multiprotocolo = (
    total_reincidentes_multiprotocolo / total_reincidentes
) * 100 if total_reincidentes > 0 else 0

# Intervalo entre ataques reincidentes

df_reincidentes["intervalo"] = (
    df_reincidentes["tempoInicio"] -
    df_reincidentes.groupby("ip")["tempoFinal"].shift()
)

intervalos_validos = df_reincidentes["intervalo"].dropna()

# Protocolos ativos em ataques reincidentes

def protocolos_ativos(row):
    return [col for col in cols if row[col] > 0]

if not df_reincidentes.empty:
    df_reincidentes["protocolos"] = df_reincidentes.apply(protocolos_ativos, axis=1)
    df_exploded = df_reincidentes.explode("protocolos")
    ataques_por_protocolo = (
        df_exploded["protocolos"]
        .value_counts()
        .sort_values(ascending=False)
    )

    porcentagem_por_protocolo = (
        ataques_por_protocolo / total_reincidentes
    ) * 100 if total_reincidentes > 0 else pd.Series(dtype=float)
else:
    ataques_por_protocolo = pd.Series(dtype=int)
    porcentagem_por_protocolo = pd.Series(dtype=float)

# ============================================================
# PRINTS GERAIS
# ============================================================

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
    intervalos_horas = pd.Series(dtype=float)
    print("\nNenhum intervalo reincidente encontrado.")

print("\n========== ATAQUES REINCIDENTES POR PROTOCOLO ==========")
if not ataques_por_protocolo.empty:
    for protocolo, qtd in ataques_por_protocolo.items():
        print(f"{protocolo}: {qtd} ataques ({porcentagem_por_protocolo[protocolo]:.2f}%)")
else:
    print("Nenhum ataque reincidente por protocolo encontrado.")

# ============================================================
# CLASSES DE REINCIDÊNCIA POR IP
# ============================================================

bins_reincidencia = [0, 1, 5, 20, 100, float("inf")]
labels_reincidencia = ["1 ataque", "2-5 ataques", "6-20 ataques", "21-100 ataques", ">100 ataques"]

classes_reincidencia = pd.cut(
    ip_counts,
    bins=bins_reincidencia,
    labels=labels_reincidencia,
    right=True
)

dist_classes_reincidencia = (
    classes_reincidencia
    .value_counts()
    .reindex(labels_reincidencia)
)

plt.figure(figsize=(10, 6))
plt.bar(dist_classes_reincidencia.index.astype(str), dist_classes_reincidencia.values)
plt.xlabel("Classe de reincidência")
plt.ylabel("Número de IPs")
plt.title("Distribuição de IPs por classe de reincidência")
plt.yscale("log")
plt.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/classes_reincidencia_ips.png", dpi=300)
plt.close()

# ============================================================
# CONCENTRAÇÃO DOS ATAQUES NAS VÍTIMAS MAIS ATACADAS
# ============================================================

print("\n========== CONCENTRAÇÃO DOS ATAQUES POR IP ==========")

ip_counts_sorted = ip_counts.sort_values(ascending=False)
total_ataques_ips = ip_counts_sorted.sum()

if total_ataques_ips > 0 and len(ip_counts_sorted) > 0:
    for p in [0.01, 0.05, 0.10]:
        n_top = max(int(len(ip_counts_sorted) * p), 1)
        ataques_top = ip_counts_sorted.head(n_top).sum()
        perc = ataques_top / total_ataques_ips * 100
        print(f"Top {int(p * 100)}% dos IPs concentra {perc:.2f}% dos ataques")

    acumulado = ip_counts_sorted.cumsum() / total_ataques_ips * 100
    percentual_vitimas = np.arange(1, len(acumulado) + 1) / len(acumulado) * 100

    plt.figure(figsize=(10, 6))
    plt.plot(percentual_vitimas, acumulado.values)
    plt.xlabel("Percentual acumulado de IPs vítimas (%)")
    plt.ylabel("Percentual acumulado de ataques (%)")
    plt.title("Concentração dos ataques por IP vítima")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/concentracao_ataques_ips.png", dpi=300)
    plt.close()
else:
    print("Não há dados suficientes para calcular concentração de ataques.")

# ============================================================
# REINCIDENTES VS NÃO REINCIDENTES
# ============================================================

comparacao_reincidencia = df_ataques.groupby("vitima_reincidente").agg(
    ataques=("ip", "count"),
    duracao_mediana=("duracao_horas", "median"),
    duracao_media=("duracao_horas", "mean"),
    volume_mediano=("countTotal", "median"),
    volume_medio=("countTotal", "mean"),
    qtd_protocolos_media=("qtd_protocolos", "mean"),
    percentual_multiprotocolo=("multiprotocolo", "mean"),
    qtd_instancias_media=("qtd_instancias", "mean"),
    percentual_multi_instancia=("multi_instancia", "mean")
)

comparacao_reincidencia["percentual_multiprotocolo"] *= 100
comparacao_reincidencia["percentual_multi_instancia"] *= 100

print("\n========== REINCIDENTES VS NÃO REINCIDENTES - IP ==========")
print(comparacao_reincidencia)

# ============================================================
# MULTI-INSTÂNCIA EM ATAQUES REINCIDENTES
# ============================================================

if not df_reincidentes.empty:
    dist_instancias_reinc = (
        df_reincidentes["qtd_instancias"]
        .value_counts()
        .sort_index()
    )

    plt.figure(figsize=(10, 6))
    plt.bar(dist_instancias_reinc.index.astype(str), dist_instancias_reinc.values)
    plt.xlabel("Quantidade de instâncias envolvidas")
    plt.ylabel("Número de ataques reincidentes")
    plt.title("Ataques contra IPs reincidentes por quantidade de instâncias")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/reincidentes_por_qtd_instancias.png", dpi=300)
    plt.close()

    perc_multi_inst_reinc = df_reincidentes["multi_instancia"].mean() * 100
    print("\n========== MULTI-INSTÂNCIA EM ATAQUES REINCIDENTES ==========")
    print(f"Ataques contra IPs reincidentes multi-instância: {perc_multi_inst_reinc:.2f}%")
else:
    print("\nNenhum ataque reincidente para análise multi-instância.")

# ============================================================
# MULTI-INSTÂNCIA POR VÍTIMA REINCIDENTE
# ============================================================

if not df_reincidentes.empty and "instancias" in df_reincidentes.columns:
    instancias_por_ip = (
        df_reincidentes
        .groupby("ip")["instancias"]
        .apply(lambda valores: set(
            instancia.strip()
            for valor in valores
            if pd.notna(valor)
            for instancia in str(valor).split(";")
            if instancia.strip()
        ))
    )

    qtd_instancias_por_ip = instancias_por_ip.apply(len)

    dist_instancias_por_ip = (
        qtd_instancias_por_ip
        .value_counts()
        .sort_index()
    )

    plt.figure(figsize=(10, 6))
    plt.bar(dist_instancias_por_ip.index.astype(str), dist_instancias_por_ip.values)
    plt.xlabel("Quantidade de instâncias distintas")
    plt.ylabel("Número de IPs reincidentes")
    plt.title("IPs reincidentes por quantidade de instâncias observadas")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/ips_reincidentes_por_instancias_distintas.png", dpi=300)
    plt.close()

    perc_ips_multi_instancia = (qtd_instancias_por_ip > 1).mean() * 100

    print("\n========== MULTI-INSTÂNCIA POR VÍTIMA REINCIDENTE ==========")
    print(f"IPs reincidentes observados em múltiplas instâncias: {perc_ips_multi_instancia:.2f}%")
else:
    print("\nNenhum IP reincidente para análise multi-instância por vítima.")

# ============================================================
# PERSISTÊNCIA TEMPORAL DAS VÍTIMAS REINCIDENTES
# ============================================================

if not df_reincidentes.empty:
    persistencia_ip = df_reincidentes.groupby("ip").agg(
        primeira_ocorrencia=("tempoInicio", "min"),
        ultima_ocorrencia=("tempoFinal", "max"),
        ataques=("ip", "count")
    ).reset_index()

    persistencia_ip["persistencia_dias"] = (
        persistencia_ip["ultima_ocorrencia"] - persistencia_ip["primeira_ocorrencia"]
    ).dt.total_seconds() / 86400

    bins_persistencia = [-1, 1, 7, 30, float("inf")]
    labels_persistencia = ["mesmo dia", "2-7 dias", "8-30 dias", ">30 dias"]

    persistencia_ip["classe_persistencia"] = pd.cut(
        persistencia_ip["persistencia_dias"],
        bins=bins_persistencia,
        labels=labels_persistencia
    )

    dist_persistencia = (
        persistencia_ip["classe_persistencia"]
        .value_counts()
        .reindex(labels_persistencia)
    )

    plt.figure(figsize=(10, 6))
    plt.bar(dist_persistencia.index.astype(str), dist_persistencia.values)
    plt.xlabel("Persistência temporal")
    plt.ylabel("Número de IPs reincidentes")
    plt.title("Persistência temporal de IPs reincidentes")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/persistencia_ips_reincidentes.png", dpi=300)
    plt.close()
else:
    print("\nNenhum IP reincidente para análise de persistência temporal.")

# ============================================================
# MUDANÇA DE PROTOCOLO EM VÍTIMAS REINCIDENTES
# ============================================================

if not df_reincidentes.empty:
    protocolos_por_ip = (
        df_reincidentes
        .groupby("ip")[cols]
        .sum()
    )

    protocolos_por_ip["protocolos_distintos"] = (protocolos_por_ip[cols] > 0).sum(axis=1)

    dist_protocolos_vitima = (
        protocolos_por_ip["protocolos_distintos"]
        .value_counts()
        .sort_index()
    )

    plt.figure(figsize=(10, 6))
    plt.bar(dist_protocolos_vitima.index.astype(str), dist_protocolos_vitima.values)
    plt.xlabel("Quantidade de protocolos distintos")
    plt.ylabel("Número de IPs reincidentes")
    plt.title("Variação de protocolos em IPs reincidentes")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/protocolos_distintos_ips_reincidentes.png", dpi=300)
    plt.close()
else:
    print("\nNenhum IP reincidente para análise de mudança de protocolo.")

# ============================================================
# GRÁFICOS JÁ EXISTENTES
# ============================================================

# Ataques por IP

if len(ip_counts) > 0:
    plt.figure(figsize=(10, 6))

    if ip_counts.min() > 0 and ip_counts.max() > ip_counts.min():
        bins_ip = np.logspace(np.log10(ip_counts.min()), np.log10(ip_counts.max()), 50)
    else:
        bins_ip = 10

    plt.hist(ip_counts, bins=bins_ip, edgecolor="black", alpha=0.7)
    plt.yscale("log")
    plt.xlabel("Quantidade de ataques", fontsize=12)
    plt.ylabel("Número de IPs (log)", fontsize=12)
    plt.title("Distribuição de ataques por IP", fontsize=14)
    media = ip_counts.mean()
    mediana = ip_counts.median()
    plt.axvline(media, color="red", linestyle="--", alpha=0.7, label=f"Média: {media:.2f} ataques")
    plt.axvline(mediana, color="green", linestyle="--", alpha=0.7, label=f"Mediana: {mediana:.2f} ataques")
    plt.legend()
    plt.grid(True, which="both", ls="-", alpha=0.2)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/ataques_por_ip.png", dpi=300)
    plt.close()

# Duração dos ataques

duracoes = df_ataques["duracao_horas"].dropna()
duracoes = duracoes[duracoes > 1e-6]

if not duracoes.empty:
    plt.figure(figsize=(12, 6))
    plt.hist(duracoes, bins=50, edgecolor="black", alpha=0.7, color="steelblue")
    plt.yscale("log")
    plt.xlabel("Duração do ataque (horas)", fontsize=12)
    plt.ylabel("Número de ataques (log)", fontsize=12)
    plt.title("Distribuição da Duração dos Ataques", fontsize=14)
    plt.grid(True, alpha=0.3, linestyle="--")
    media = duracoes.mean()
    mediana = duracoes.median()
    plt.axvline(media, color="red", linestyle="--", alpha=0.7, label=f"Média: {media:.2f} horas")
    plt.axvline(mediana, color="green", linestyle="--", alpha=0.7, label=f"Mediana: {mediana:.2f} horas")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/duracao_ataques_horas.png", dpi=300)
    plt.close()

# Intervalo entre reincidentes

if not intervalos_validos.empty:
    intervalos_dias = intervalos_horas / 24
    intervalos_dias = intervalos_dias[intervalos_dias > 0]

    if not intervalos_dias.empty:
        plt.figure(figsize=(12, 6))
        plt.hist(intervalos_dias, bins=50, edgecolor="black", alpha=0.7, color="steelblue")
        plt.yscale("log")
        plt.xlabel("Intervalo entre ataques (dias)", fontsize=12)
        plt.ylabel("Número de ataques (log)", fontsize=12)
        plt.title("Distribuição do Intervalo entre Ataques Reincidentes", fontsize=14)
        plt.grid(True, alpha=0.3, linestyle="--")
        media = intervalos_dias.mean()
        mediana = intervalos_dias.median()
        plt.axvline(media, color="red", linestyle="--", alpha=0.7, label=f"Média: {media:.2f} dias")
        plt.axvline(mediana, color="green", linestyle="--", alpha=0.7, label=f"Mediana: {mediana:.2f} dias")
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{PASTA_GRAFICOS}/intervalo_reincidentes_dias.png", dpi=300)
        plt.close()

# Protocolos mais utilizados em reincidentes (> 0.1%)

if not porcentagem_por_protocolo.empty:
    protocolos_filtrados = porcentagem_por_protocolo[porcentagem_por_protocolo > 0.1]

    if not protocolos_filtrados.empty:
        plt.figure(figsize=(12, 6))
        bars = plt.bar(range(len(protocolos_filtrados)), protocolos_filtrados.values)
        plt.xticks(
            range(len(protocolos_filtrados)),
            [p.replace("count", "") for p in protocolos_filtrados.index],
            rotation=45,
            ha="right",
            fontsize=10
        )
        plt.ylabel("Porcentagem de ataques reincidentes (%)", fontsize=12)
        plt.title("Distribuição de ataques reincidentes por protocolo (>0.1%)", fontsize=14)

        for bar, val in zip(bars, protocolos_filtrados.values):
            plt.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f"{val:.1f}%",
                ha="center",
                va="bottom",
                fontsize=9
            )

        plt.grid(axis="y", alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{PASTA_GRAFICOS}/reincidentes_por_protocolo.png", dpi=300)
        plt.close()

# Ataques por hora do dia

df_ataques["hora"] = df_ataques["tempoInicio"].dt.hour
ataques_por_hora = df_ataques.groupby("hora").size()

plt.figure(figsize=(10, 6))
plt.bar(ataques_por_hora.index, ataques_por_hora.values)
plt.xlabel("Hora do dia")
plt.ylabel("Número de ataques")
plt.title("Distribuição de ataques por hora do dia")
plt.xticks(range(24))
plt.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/ataques_por_hora.png", dpi=300)
plt.close()

# ============================================================
# REGULARIDADE DOS ATAQUES POR VÍTIMA
# ============================================================

MIN_ATAQUES = 2
ips_100 = ip_counts[ip_counts >= MIN_ATAQUES].index
df_100 = df_reincidentes[df_reincidentes["ip"].isin(ips_100)].copy()

# Calcular CV por vítima

if not df_100.empty:
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
    df_cv = df_cv.replace([np.inf, -np.inf], np.nan).dropna(subset=["cv"]).reset_index()
else:
    df_cv = pd.DataFrame(columns=["ip", "ataques", "media", "desvio", "cv"])

# Regularidade dos ataques por vítima

if not df_cv.empty:
    plt.figure(figsize=(10, 6))
    plt.scatter(
        df_cv["ataques"],
        df_cv["cv"],
        alpha=0.7
    )
    plt.axhline(0.8, color="red", linestyle="--", label="Limiar CV = 0.8")
    plt.xlabel("Número de ataques da vítima")
    plt.ylabel("Coeficiente de variação (CV)")
    plt.title("Regularidade dos ataques por vítima")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/cv_intervalos_vitimas.png", dpi=300)
    plt.close()

    # Distribuição da regularidade dos ataques

    plt.figure(figsize=(10, 6))
    plt.hist(df_cv["cv"], bins=40, edgecolor="black", alpha=0.7)
    plt.axvline(0.8, color="red", linestyle="--", label="Limiar CV = 0.8")
    plt.yscale("log")
    plt.xlabel("Coeficiente de Variação (CV)")
    plt.ylabel("Número de vítimas (log)")
    plt.title("Distribuição da regularidade dos ataques")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/distribuicao_cv_vitimas.png", dpi=300)
    plt.close()

    # Ataques por hora para vítimas reincidentes regulares

    df_cv_filtrado = df_cv[df_cv["cv"] <= 0.8]
    top5_vitimas_regulares = df_cv_filtrado.nlargest(5, "ataques")

    if not top5_vitimas_regulares.empty:
        df_top5 = df_reincidentes[df_reincidentes["ip"].isin(top5_vitimas_regulares["ip"])].copy()
        df_top5["hora"] = df_top5["tempoInicio"].dt.hour

        plt.figure(figsize=(10, 6))
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

        # Intervalos para top 5 vítimas regulares

        plt.figure(figsize=(10, 6))
        for ip in top5_vitimas_regulares["ip"]:
            df_ip = df_top5[df_top5["ip"] == ip].copy()
            df_ip = df_ip.dropna(subset=["intervalo"])

            intervalos_minutos = df_ip["intervalo"].dt.total_seconds() / 60
            intervalos_minutos = (10 * (intervalos_minutos / 10).round()).astype(int)
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

print("\nAnálises multiprotocolo finalizadas.")