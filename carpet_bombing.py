import os
import sqlite3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

import pre_processamento

PASTA_GRAFICOS = "graficos/carpet_bombing"
os.makedirs(PASTA_GRAFICOS, exist_ok=True)

conn = sqlite3.connect(pre_processamento.PATH_ATAQUES_PROCESSADOS)
query = "SELECT * FROM carpet_bombing"
df_ataques = pd.read_sql_query(query, conn)
df_ataques["tempoInicio"] = pd.to_datetime(df_ataques["tempoInicio"], errors="coerce")
df_ataques["tempoFinal"] = pd.to_datetime(df_ataques["tempoFinal"], errors="coerce")
conn.close()

# ============================================================
# MÉTRICAS GERAIS
# ============================================================

total_ataques = len(df_ataques)
cidrs_counts = df_ataques["cidr"].value_counts()
total_cidrs_unicos = cidrs_counts.count()

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

if "ips_count" not in df_ataques.columns:
    df_ataques["ips_count"] = 1

# Duração dos ataques

df_ataques["duracao_horas"] = (
    (df_ataques["tempoFinal"] - df_ataques["tempoInicio"])
    .dt.total_seconds() / 3600
)

# Quantidade de protocolos por ataque carpet bombing

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

# Carpet bombing: ataques que atingem mais de um IP dentro do CIDR

df_ataques["carpet_bombing"] = df_ataques["ips_count"] > 1
total_carpet_bombing = df_ataques["carpet_bombing"].sum()

porcentagem_ataques_carpet_bombing = (
    total_carpet_bombing / total_ataques
) * 100 if total_ataques > 0 else 0

# Filtrar CIDRs reincidentes

cidrs_reincidentes = cidrs_counts[cidrs_counts > 1].index

df_ataques["vitima_reincidente"] = df_ataques["cidr"].isin(cidrs_reincidentes)

df_reincidentes = (
    df_ataques[df_ataques["vitima_reincidente"]]
    .copy()
    .sort_values(["cidr", "tempoInicio"])
)

total_reincidentes = len(df_reincidentes)
cidrs_reincidentes_qtd = df_reincidentes["cidr"].nunique()

porcentagem_cidrs_reincidentes = (
    cidrs_reincidentes_qtd / total_cidrs_unicos
) * 100 if total_cidrs_unicos > 0 else 0

porcentagem_ataques_reincidentes = (
    total_reincidentes / total_ataques
) * 100 if total_ataques > 0 else 0

total_reincidentes_carpet_bombing = df_reincidentes["carpet_bombing"].sum() if not df_reincidentes.empty else 0

porcentagem_ataques_reincidentes_carpet_bombing = (
    total_reincidentes_carpet_bombing / total_reincidentes
) * 100 if total_reincidentes > 0 else 0

# Intervalo entre ataques reincidentes por CIDR

df_reincidentes["intervalo"] = (
    df_reincidentes["tempoInicio"] -
    df_reincidentes.groupby("cidr")["tempoFinal"].shift()
)

intervalos_validos = df_reincidentes["intervalo"].dropna()

# ============================================================
# PRINTS GERAIS
# ============================================================

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
    intervalos_horas = pd.Series(dtype=float)
    print("\nNenhum intervalo reincidente encontrado.")

print("\n========== TOP 10 CIDRS COM MAIS ATAQUES ==========")
print(cidrs_counts.head(10))

# ============================================================
# CLASSES DE REINCIDÊNCIA POR CIDR
# ============================================================

bins_reincidencia = [0, 1, 5, 20, 100, float("inf")]
labels_reincidencia = ["1 ataque", "2-5 ataques", "6-20 ataques", "21-100 ataques", ">100 ataques"]

classes_reincidencia = pd.cut(
    cidrs_counts,
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
plt.ylabel("Número de CIDRs")
plt.title("Distribuição de CIDRs por classe de reincidência")
plt.yscale("log")
plt.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(f"{PASTA_GRAFICOS}/classes_reincidencia_cidrs.png", dpi=300)
plt.close()

# ============================================================
# CONCENTRAÇÃO DOS ATAQUES NOS CIDRS MAIS ATACADOS
# ============================================================

print("\n========== CONCENTRAÇÃO DOS ATAQUES POR CIDR ==========")

cidrs_counts_sorted = cidrs_counts.sort_values(ascending=False)
total_ataques_cidrs = cidrs_counts_sorted.sum()

if total_ataques_cidrs > 0 and len(cidrs_counts_sorted) > 0:
    for p in [0.01, 0.05, 0.10]:
        n_top = max(int(len(cidrs_counts_sorted) * p), 1)
        ataques_top = cidrs_counts_sorted.head(n_top).sum()
        perc = ataques_top / total_ataques_cidrs * 100
        print(f"Top {int(p * 100)}% dos CIDRs concentra {perc:.2f}% dos ataques")

    acumulado = cidrs_counts_sorted.cumsum() / total_ataques_cidrs * 100
    percentual_vitimas = np.arange(1, len(acumulado) + 1) / len(acumulado) * 100

    plt.figure(figsize=(10, 6))
    plt.plot(percentual_vitimas, acumulado.values)
    plt.xlabel("Percentual acumulado de CIDRs vítimas (%)")
    plt.ylabel("Percentual acumulado de ataques (%)")
    plt.title("Concentração dos ataques por CIDR vítima")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/concentracao_ataques_cidrs.png", dpi=300)
    plt.close()
else:
    print("Não há dados suficientes para calcular concentração de ataques.")

# ============================================================
# REINCIDENTES VS NÃO REINCIDENTES POR CIDR
# ============================================================

comparacao_reincidencia = df_ataques.groupby("vitima_reincidente").agg(
    ataques=("cidr", "count"),
    duracao_mediana=("duracao_horas", "median"),
    duracao_media=("duracao_horas", "mean"),
    volume_mediano=("countTotal", "median"),
    volume_medio=("countTotal", "mean"),
    ips_count_mediano=("ips_count", "median"),
    ips_count_medio=("ips_count", "mean"),
    qtd_protocolos_media=("qtd_protocolos", "mean"),
    percentual_multiprotocolo=("multiprotocolo", "mean"),
    qtd_instancias_media=("qtd_instancias", "mean"),
    percentual_multi_instancia=("multi_instancia", "mean"),
    percentual_carpet_bombing=("carpet_bombing", "mean")
)

comparacao_reincidencia["percentual_multiprotocolo"] *= 100
comparacao_reincidencia["percentual_multi_instancia"] *= 100
comparacao_reincidencia["percentual_carpet_bombing"] *= 100

print("\n========== REINCIDENTES VS NÃO REINCIDENTES - CIDR ==========")
print(comparacao_reincidencia)

# ============================================================
# MULTI-INSTÂNCIA EM ATAQUES CONTRA CIDRS REINCIDENTES
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
    plt.title("Ataques contra CIDRs reincidentes por quantidade de instâncias")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/reincidentes_por_qtd_instancias.png", dpi=300)
    plt.close()

    perc_multi_inst_reinc = df_reincidentes["multi_instancia"].mean() * 100
    print("\n========== MULTI-INSTÂNCIA EM ATAQUES REINCIDENTES ==========")
    print(f"Ataques contra CIDRs reincidentes multi-instância: {perc_multi_inst_reinc:.2f}%")
else:
    print("\nNenhum ataque reincidente para análise multi-instância.")

# ============================================================
# MULTI-INSTÂNCIA POR CIDR REINCIDENTE
# ============================================================

if not df_reincidentes.empty and "instancias" in df_reincidentes.columns:
    instancias_por_cidr = (
        df_reincidentes
        .groupby("cidr")["instancias"]
        .apply(lambda valores: set(
            instancia.strip()
            for valor in valores
            if pd.notna(valor)
            for instancia in str(valor).split(";")
            if instancia.strip()
        ))
    )

    qtd_instancias_por_cidr = instancias_por_cidr.apply(len)

    dist_instancias_por_cidr = (
        qtd_instancias_por_cidr
        .value_counts()
        .sort_index()
    )

    plt.figure(figsize=(10, 6))
    plt.bar(dist_instancias_por_cidr.index.astype(str), dist_instancias_por_cidr.values)
    plt.xlabel("Quantidade de instâncias distintas")
    plt.ylabel("Número de CIDRs reincidentes")
    plt.title("CIDRs reincidentes por quantidade de instâncias observadas")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/cidrs_reincidentes_por_instancias_distintas.png", dpi=300)
    plt.close()

    perc_cidrs_multi_instancia = (qtd_instancias_por_cidr > 1).mean() * 100

    print("\n========== MULTI-INSTÂNCIA POR CIDR REINCIDENTE ==========")
    print(f"CIDRs reincidentes observados em múltiplas instâncias: {perc_cidrs_multi_instancia:.2f}%")
else:
    print("\nNenhum CIDR reincidente para análise multi-instância por vítima.")

# ============================================================
# PERSISTÊNCIA TEMPORAL DOS CIDRS REINCIDENTES
# ============================================================

if not df_reincidentes.empty:
    persistencia_cidr = df_reincidentes.groupby("cidr").agg(
        primeira_ocorrencia=("tempoInicio", "min"),
        ultima_ocorrencia=("tempoFinal", "max"),
        ataques=("cidr", "count")
    ).reset_index()

    persistencia_cidr["persistencia_dias"] = (
        persistencia_cidr["ultima_ocorrencia"] - persistencia_cidr["primeira_ocorrencia"]
    ).dt.total_seconds() / 86400

    bins_persistencia = [-1, 1, 7, 30, float("inf")]
    labels_persistencia = ["mesmo dia", "2-7 dias", "8-30 dias", ">30 dias"]

    persistencia_cidr["classe_persistencia"] = pd.cut(
        persistencia_cidr["persistencia_dias"],
        bins=bins_persistencia,
        labels=labels_persistencia
    )

    dist_persistencia = (
        persistencia_cidr["classe_persistencia"]
        .value_counts()
        .reindex(labels_persistencia)
    )

    plt.figure(figsize=(10, 6))
    plt.bar(dist_persistencia.index.astype(str), dist_persistencia.values)
    plt.xlabel("Persistência temporal")
    plt.ylabel("Número de CIDRs reincidentes")
    plt.title("Persistência temporal de CIDRs reincidentes")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/persistencia_cidrs_reincidentes.png", dpi=300)
    plt.close()
else:
    print("\nNenhum CIDR reincidente para análise de persistência temporal.")

# ============================================================
# MUDANÇA DE PROTOCOLO EM CIDRS REINCIDENTES
# ============================================================

if not df_reincidentes.empty:
    protocolos_por_cidr = (
        df_reincidentes
        .groupby("cidr")[cols]
        .sum()
    )

    protocolos_por_cidr["protocolos_distintos"] = (protocolos_por_cidr[cols] > 0).sum(axis=1)

    dist_protocolos_cidr = (
        protocolos_por_cidr["protocolos_distintos"]
        .value_counts()
        .sort_index()
    )

    plt.figure(figsize=(10, 6))
    plt.bar(dist_protocolos_cidr.index.astype(str), dist_protocolos_cidr.values)
    plt.xlabel("Quantidade de protocolos distintos")
    plt.ylabel("Número de CIDRs reincidentes")
    plt.title("Variação de protocolos em CIDRs reincidentes")
    plt.yscale("log")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/protocolos_distintos_cidrs_reincidentes.png", dpi=300)
    plt.close()
else:
    print("\nNenhum CIDR reincidente para análise de mudança de protocolo.")

# ============================================================
# GRÁFICOS JÁ EXISTENTES
# ============================================================

# Ataques por CIDR

if len(cidrs_counts) > 0:
    plt.figure(figsize=(10, 6))

    if cidrs_counts.min() > 0 and cidrs_counts.max() > cidrs_counts.min():
        bins_cidr = np.logspace(np.log10(cidrs_counts.min()), np.log10(cidrs_counts.max()), 50)
    else:
        bins_cidr = 10

    plt.hist(cidrs_counts, bins=bins_cidr, edgecolor="black", alpha=0.7)
    plt.yscale("log")
    plt.xlabel("Quantidade de ataques", fontsize=12)
    plt.ylabel("Número de CIDRs (log)", fontsize=12)
    plt.title("Distribuição de ataques por CIDR", fontsize=14)
    media = cidrs_counts.mean()
    mediana = cidrs_counts.median()
    plt.axvline(media, color="red", linestyle="--", alpha=0.7, label=f"Média: {media:.2f} ataques")
    plt.axvline(mediana, color="green", linestyle="--", alpha=0.7, label=f"Mediana: {mediana:.2f} ataques")
    plt.legend()
    plt.grid(True, which="both", ls="-", alpha=0.2)
    plt.tight_layout()
    plt.savefig(f"{PASTA_GRAFICOS}/ataques_por_cidr.png", dpi=300)
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
# REGULARIDADE DOS ATAQUES POR CIDR
# ============================================================

MIN_ATAQUES = 20
cidrs_100 = cidrs_counts[cidrs_counts >= MIN_ATAQUES].index
df_100 = df_reincidentes[df_reincidentes["cidr"].isin(cidrs_100)].copy()

# Calcular CV por CIDR

if not df_100.empty:
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
    df_cv = df_cv.replace([np.inf, -np.inf], np.nan).dropna(subset=["cv"]).reset_index()
else:
    df_cv = pd.DataFrame(columns=["cidr", "ataques", "media", "desvio", "cv"])

# Regularidade dos ataques por CIDR

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
    plt.title("Regularidade dos ataques por CIDR vítima")
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

    # Ataques por hora para CIDRs reincidentes regulares

    df_cv_filtrado = df_cv[df_cv["cv"] <= 0.8]
    top5_vitimas_regulares = df_cv_filtrado.nlargest(5, "ataques")

    if not top5_vitimas_regulares.empty:
        df_top5 = df_reincidentes[df_reincidentes["cidr"].isin(top5_vitimas_regulares["cidr"])].copy()
        df_top5["hora"] = df_top5["tempoInicio"].dt.hour

        plt.figure(figsize=(10, 6))
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

        # Intervalos para top 5 CIDRs regulares

        plt.figure(figsize=(10, 6))
        for cidr in top5_vitimas_regulares["cidr"]:
            df_cidr = df_top5[df_top5["cidr"] == cidr].copy()
            df_cidr = df_cidr.dropna(subset=["intervalo"])

            intervalos_minutos = df_cidr["intervalo"].dt.total_seconds() / 60
            intervalos_minutos = (10 * (intervalos_minutos / 10).round()).astype(int)
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

print("\nAnálises carpet bombing finalizadas.")