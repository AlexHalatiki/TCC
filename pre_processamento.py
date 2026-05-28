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
    instancias = set()
    tolerancia = timedelta(minutes=1)

    for row in df_ip.itertuples(index=False):
        inicio = row.tempoInicio
        fim = row.tempoFinal
        count = row.count
        protocol = row.protocol
        instancia = row.instancia

        if inicio_atual is None:
            inicio_atual = inicio
            fim_atual = fim
            counts["countTotal"] += count
            counts["count" + protocol] += count
            instancias.add(instancia)
        else:
            if inicio <= fim_atual + tolerancia:
                fim_atual = max(fim_atual, fim)
                counts["countTotal"] += count
                counts["count" + protocol] += count
                instancias.add(instancia)
            else:
                ataques.append({
                    "ip": ip,
                    "cidr": cidr,
                    "tempoInicio": inicio_atual,
                    "tempoFinal": fim_atual,
                    "instancias": set(instancias),
                    **dict(counts)
                })

                inicio_atual = inicio
                fim_atual = fim
                counts = defaultdict(int)
                instancias = set()
                counts["countTotal"] += count
                counts["count" + protocol] += count
                instancias.add(instancia)

    if inicio_atual is not None:
        ataques.append({
            "ip": ip,
            "cidr": cidr,
            "tempoInicio": inicio_atual,
            "tempoFinal": fim_atual,
            "instancias": set(instancias),
            **dict(counts)
        })

    return ataques

def consolidar_carpet_bombing(cidr, df_cidr):
    ataques = []
    inicio_atual = None
    fim_atual = None
    ips_set = set()
    instancias = set()
    counts = defaultdict(int)
    tolerancia = timedelta(minutes=1)

    for row in df_cidr.itertuples(index=False):
        inicio = row.tempoInicio
        fim = row.tempoFinal
        ip = row.ip

        if inicio_atual is None:
            inicio_atual = inicio
            fim_atual = fim
            ips_set.add(ip)

            for coluna in row._fields:
                if coluna.startswith("count"):
                    valor = getattr(row, coluna)

                    if valor is not None:
                        counts[coluna] += valor

            if row.instancias:
                instancias.update(row.instancias)
        else:
            if inicio <= fim_atual + tolerancia:
                fim_atual = max(fim_atual, fim)
                ips_set.add(ip)

                for coluna in row._fields:
                    if coluna.startswith("count"):
                        valor = getattr(row, coluna)

                        if valor is not None:
                            counts[coluna] += valor

                if row.instancias:
                    instancias.update(row.instancias)
            else:
                ataques.append({
                    "cidr": cidr,
                    "tempoInicio": inicio_atual,
                    "tempoFinal": fim_atual,
                    "ips_count": len(ips_set),
                    "instancias": set(instancias),
                    **dict(counts)
                })

                inicio_atual = inicio
                fim_atual = fim
                ips_set = {ip}
                instancias = set()
                counts = defaultdict(int)

                for coluna in row._fields:
                    if coluna.startswith("count"):
                        valor = getattr(row, coluna)

                        if valor is not None:
                            counts[coluna] += valor

                if row.instancias:
                    instancias.update(row.instancias)
    
    if inicio_atual is not None:
        ataques.append({
            "cidr": cidr,
            "tempoInicio": inicio_atual,
            "tempoFinal": fim_atual,
            "ips_count": len(ips_set),
            "instancias": set(instancias),
            **dict(counts)
        })

    return ataques

def ler_ataques_honeypot():
    dados_completos = []

    for instancia in INSTANCIAS_PASTAS:
        pasta_instancia = os.path.join(PASTA, instancia)

        for arquivo in os.listdir(pasta_instancia):
            if "6" not in arquivo and "ataques" not in arquivo and arquivo.endswith(".sqlite"):
                conn = sqlite3.connect(os.path.join(pasta_instancia, arquivo))
                cursor = conn.cursor()

                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tabelas = cursor.fetchall()

                tabela_memoria = None
                for (nome_tabela,) in tabelas:
                    if nome_tabela.endswith("MEMORY_DICT"):
                        tabela_memoria = nome_tabela
                        break
                
                if not tabela_memoria:
                    print(f"{instancia}/{arquivo} → Tabela MEMORY_DICT não encontrada.")
                    conn.close()
                    exit()

                query = f"SELECT * FROM {tabela_memoria} where count >= 5 and tempoInicio >= '2023-04-01' and tempoFinal < '2026-04-01'"
                df = pd.read_sql_query(query, conn)

                # Adiciona '.000000' para datas que não têm microsegundos
                df["tempoInicio"] = df["tempoInicio"].apply(lambda x: x + ".000000" if "." not in x else x)
                df["tempoInicio"] = pd.to_datetime(df["tempoInicio"], errors="coerce")
                df["tempoFinal"] = df["tempoFinal"].apply(lambda x: x + ".000000" if "." not in x else x)
                df["tempoFinal"] = pd.to_datetime(df["tempoFinal"], errors="coerce")
                df["protocol"] = tabela_memoria.split("_")[0]
                df["instancia"] = instancia

                dados_completos.append(df)

                conn.close()
    
    return dados_completos


asn_db = ip2asn.IP2ASN("./ip2asn-v4-u32.tsv")
PASTA = "db-honeypots"
INSTANCIAS_PASTAS = ["1", "2", "3", "4"]
PATH_ATAQUES_PROCESSADOS = os.path.join(PASTA, "ataques.sqlite")

if __name__ == "__main__":
    # juntar bases

    df_raw = pd.concat(ler_ataques_honeypot(), ignore_index=True)

    # consolidar ataques (multiprotocolo)

    ataques_consolidados = []
    grupos_ip = df_raw.groupby("ip")
    total_grupos_ip = grupos_ip.ngroups
    ultimo_percentual = -1
    for i, (ip, grupo) in enumerate(grupos_ip, start=1):
        percentual = int((i / total_grupos_ip) * 100)

        if percentual >= ultimo_percentual + 5 or percentual == 100:
            print(f"[multiprotocolo] {percentual}% ({i}/{total_grupos_ip})", end="\r", flush=True)
            ultimo_percentual = percentual
        
        # pegar CIDR pelo ASN do IP
        result = asn_db.lookup_address(ip)
        if result is None or "ip_range" not in result:
            print(f"IP {ip} não encontrado ou sem range")
            exit()

        cidrs = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(result["ip_range"][0]),ipaddress.IPv4Address(result["ip_range"][1])))
        cidr_str = ";".join(str(c) for c in cidrs)

        grupo = grupo.sort_values("tempoInicio")
        ataques_consolidados.extend(consolidar_multiprotocolo(ip, cidr_str, grupo))

    print()
    df_multiprotocolo = pd.DataFrame(ataques_consolidados)

    # preencher NaN dos counts com 0 - multiprotocolo
    colunas_count = [col for col in df_multiprotocolo.columns if col.startswith("count")]
    df_multiprotocolo[colunas_count] = df_multiprotocolo[colunas_count].fillna(0).astype(int)

    # consolidar ataques (carpet bombing)

    ataques_consolidados = []
    grupos_cidr = df_multiprotocolo.groupby("cidr")
    total_grupos_cidr = grupos_cidr.ngroups
    ultimo_percentual = -1
    for i, (cidr, grupo) in enumerate(grupos_cidr, start=1):
        percentual = int((i / total_grupos_cidr) * 100)

        if percentual >= ultimo_percentual + 5 or percentual == 100:
            print(f"[carpet bombing] {percentual}% ({i}/{total_grupos_cidr})", end="\r", flush=True)
            ultimo_percentual = percentual
        
        grupo = grupo.sort_values("tempoInicio")
        ataques_consolidados.extend(consolidar_carpet_bombing(cidr, grupo))

    print()
    df_carpet_bombing = pd.DataFrame(ataques_consolidados)

    # salvar no banco

    # preencher NaN dos counts com 0 - carpet bombing
    colunas_count = [col for col in df_carpet_bombing.columns if col.startswith("count")]
    df_carpet_bombing[colunas_count] = df_carpet_bombing[colunas_count].fillna(0).astype(int)

    # converter instancias de set para string separada por ;
    df_multiprotocolo["instancias"] = df_multiprotocolo["instancias"].apply(
        lambda x: ";".join(sorted(str(i) for i in x)) if isinstance(x, set) else x
    )

    df_carpet_bombing["instancias"] = df_carpet_bombing["instancias"].apply(
        lambda x: ";".join(sorted(str(i) for i in x)) if isinstance(x, set) else x
    )

    # converte tempoInicio e tempoFinal para string (SQLite não tem datetime nativo)
    df_multiprotocolo["tempoInicio"] = df_multiprotocolo["tempoInicio"].astype(str)
    df_multiprotocolo["tempoFinal"] = df_multiprotocolo["tempoFinal"].astype(str)

    df_carpet_bombing["tempoInicio"] = df_carpet_bombing["tempoInicio"].astype(str)
    df_carpet_bombing["tempoFinal"] = df_carpet_bombing["tempoFinal"].astype(str)

    conn = sqlite3.connect(PATH_ATAQUES_PROCESSADOS)

    df_multiprotocolo.to_sql("multiprotocol", conn, if_exists="replace", index=False)
    df_carpet_bombing.to_sql("carpet_bombing", conn, if_exists="replace", index=False)

    conn.close()