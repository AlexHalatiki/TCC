import sqlite3
import ipaddress
import pandas as pd
from collections import defaultdict
from datetime import timedelta
import os
# Corrige variável HOME no Windows (ip2asn)
if "HOME" not in os.environ:
    os.environ["HOME"] = os.environ["USERPROFILE"]
import ip2asn

def consolidar_multiprotocolo(ip, cidr, df_ip):
    ataques = []
    inicio_atual = None
    fim_atual = None
    counts = defaultdict(int)
    tolerancia = timedelta(minutes=1)

    for row in df_ip.itertuples(index=False):
        inicio = row.tempoInicio
        fim = row.tempoFinal
        count = row.count
        protocol = row.protocol

        if inicio_atual is None:
            inicio_atual = inicio
            fim_atual = fim
            counts["countTotal"] += count
            counts["count" + protocol] += count
        else:
            if inicio <= fim_atual + tolerancia:
                fim_atual = max(fim_atual, fim)
                counts["countTotal"] += count
                counts["count" + protocol] += count
            else:
                ataques.append({
                    "ip": ip,
                    "cidr": cidr,
                    "tempoInicio": inicio_atual,
                    "tempoFinal": fim_atual,
                    **dict(counts)
                })

                inicio_atual = inicio
                fim_atual = fim
                counts = defaultdict(int)
                counts["countTotal"] += count
                counts["count" + protocol] += count

    if inicio_atual is not None:
        ataques.append({
            "ip": ip,
            "cidr": cidr,
            "tempoInicio": inicio_atual,
            "tempoFinal": fim_atual,
            **dict(counts)
        })

    return ataques

def consolidar_carpet_bombing(cidr, df_cidr):
    ataques = []
    inicio_atual = None
    fim_atual = None
    ips_set = set()
    tolerancia = timedelta(minutes=1)

    for row in df_cidr.itertuples(index=False):
        inicio = row.tempoInicio
        fim = row.tempoFinal
        ip = row.ip

        if inicio_atual is None:
            inicio_atual = inicio
            fim_atual = fim
            ips_set.add(ip)
        else:
            if inicio <= fim_atual + tolerancia:
                fim_atual = max(fim_atual, fim)
                ips_set.add(ip)
            else:
                ataques.append({
                    "cidr": cidr,
                    "tempoInicio": inicio_atual,
                    "tempoFinal": fim_atual,
                    "ips_count": len(ips_set)
                })

                inicio_atual = inicio
                fim_atual = fim
                ips_set = {ip}
    
    if inicio_atual is not None:
        ataques.append({
            "cidr": cidr,
            "tempoInicio": inicio_atual,
            "tempoFinal": fim_atual,
            "ips_count": len(ips_set)
        })

    return ataques


asn_db = ip2asn.IP2ASN("./ip2asn-v4-u32.tsv")
PASTA = "db-honeypots/database-br-2025-10-17"
PASTA_GRAFICOS = "graficos"
dados_completos = []

for arquivo in os.listdir(PASTA):
    if "6" not in arquivo and "ataques" not in arquivo and arquivo.endswith(".sqlite"):
        conn = sqlite3.connect(os.path.join(PASTA, arquivo))
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

        # Adiciona '.000000' para datas que não têm microsegundos
        df["tempoInicio"] = df["tempoInicio"].apply(lambda x: x + ".000000" if "." not in x else x)
        df["tempoInicio"] = pd.to_datetime(df["tempoInicio"], errors="coerce")
        df["tempoFinal"] = df["tempoFinal"].apply(lambda x: x + ".000000" if "." not in x else x)
        df["tempoFinal"] = pd.to_datetime(df["tempoFinal"], errors="coerce")
        df["protocol"] = tabela_memoria.split("_")[0]

        dados_completos.append(df)

        conn.close()

# juntar bases

df_raw = pd.concat(dados_completos, ignore_index=True)

# consolidar ataques (multiprotocolo)

ataques_consolidados = []
for ip, grupo in df_raw.groupby("ip"):
    # pegar CIDR pelo ASN do IP
    result = asn_db.lookup_address(ip)
    if result is None or "ip_range" not in result:
        print(f"IP {ip} não encontrado ou sem range")
        exit()

    cidrs = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(result["ip_range"][0]),ipaddress.IPv4Address(result["ip_range"][1])))
    cidr_str = ";".join(str(c) for c in cidrs)

    grupo = grupo.sort_values("tempoInicio")
    ataques_consolidados.extend(consolidar_multiprotocolo(ip, cidr_str, grupo))

df_multiprotocolo = pd.DataFrame(ataques_consolidados)

# consolidar ataques (carpet bombing)

ataques_consolidados = []
for cidr, grupo in df_multiprotocolo.groupby("cidr"):
    grupo = grupo.sort_values("tempoInicio")
    ataques_consolidados.extend(consolidar_carpet_bombing(cidr, grupo))

df_carpet_bombing = pd.DataFrame(ataques_consolidados)

# salvar no banco

# preencher NaN dos counts com 0
colunas_count = [col for col in df_multiprotocolo.columns if "count" in col]
df_multiprotocolo[colunas_count] = df_multiprotocolo[colunas_count].fillna(0).astype(int)
# converte tempoInicio e tempoFinal para string (SQLite não tem datetime nativo)
df_multiprotocolo["tempoInicio"] = df_multiprotocolo["tempoInicio"].astype(str)
df_multiprotocolo["tempoFinal"] = df_multiprotocolo["tempoFinal"].astype(str)
df_carpet_bombing["tempoInicio"] = df_carpet_bombing["tempoInicio"].astype(str)
df_carpet_bombing["tempoFinal"] = df_carpet_bombing["tempoFinal"].astype(str)

conn = sqlite3.connect(os.path.join(PASTA, "ataques.sqlite"))
df_multiprotocolo.to_sql("multiprotocol", conn, if_exists="replace", index=False)
df_carpet_bombing.to_sql("carpet_bombing", conn, if_exists="replace", index=False)
conn.close()