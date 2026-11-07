"""Serena Quantum-Safe Readiness (QSR): inventario, classificacao, veredito e recibo.

Principio: o modulo nao afirma conformidade regulatoria. Ele responde a uma pergunta
estreita e verificavel: para cada ativo criptografico, o tempo de migracao somado ao
tempo de sigilo do dado excede o tempo estimado ate um computador quantico relevante?
Se excede, migrar agora. Se nao, planejar. Se falta evidencia, REFUSED.

Desigualdade de Mosca: (X + Y) > Z  -> migrar agora
  X = anos para migrar o sistema
  Y = anos que o dado precisa permanecer secreto
  Z = anos ate o CRQC (hipotese declarada, nao fato)

Uso:
  python -m quantum_safe_readiness scan <caminho> --crqc 2035 --json
  python -m quantum_safe_readiness check inventario.json --crqc 2035
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VULNERAVEIS = {"rsa", "ecdsa", "ecdh", "dh", "dsa", "ed25519", "x25519"}
SEGUROS = {"ml-kem", "ml-kem-768", "ml-dsa", "ml-dsa-44", "aes-256", "sha3-256", "sha3-384"}
PADROES = {
    "rsa": re.compile(r"\b(RSA|rsa[-_ ]?(1024|2048|3072|4096))\b"),
    "ecc": re.compile(r"\b(ECDSA|ECDH|secp256r1|prime256v1|P-256|P-384)\b"),
    "tls_antigo": re.compile(r"\b(TLSv1(\.0|\.1)?|SSLv[23])\b"),
    "hash_fraco": re.compile(r"\b(MD5|SHA-?1)\b"),
    "certificado": re.compile(r"-----BEGIN (CERTIFICATE|RSA PRIVATE KEY|EC PRIVATE KEY)-----"),
    "biblioteca": re.compile(r"\b(openssl|cryptography|pycryptodome|bouncycastle|wolfssl)\b", re.I),
    "pqc": re.compile(r"\b(ML-?KEM|ML-?DSA|Kyber|Dilithium|SPHINCS)\b", re.I),
    "ot_ics": re.compile(r"\b(Modbus|DNP3|PROFIBUS|PROFINET|OPC[- ]UA|SCADA|PLC)\b", re.I),
}
EXTENSOES = {".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".conf", ".ini",
             ".cfg", ".pem", ".crt", ".key", ".md", ".tf", ".env", ".sh", ".service"}
FONTES = {
    "FIPS 203 (2024-08-13)": "parametros e tamanhos do ML-KEM",
    "FIPS 204 (2024-08-13)": "parametros e tamanhos do ML-DSA",
    "FIPS 205 (2024-08-13)": "alternativa SLH-DSA (hash)",
    "NIST IR 8547 final (2026-10-27)": "plano de transicao; substitui o rascunho de 2024-11-12",
    "SP 800-57": "criptoperiodo e ciclo de vida de chave",
    "CNSA 2.0 (2022)": "teto conservador para defesa e infraestrutura critica",
    "SP 1800-38": "fases de inventario e prova de migracao",
    "Mosca": "criterio X + Y > Z com Z declarado, nunca afirmado",
}
TAMANHOS_PADRAO = {
    "ml_kem_768": {"chave_publica": 1184, "texto_cifrado": 1088, "segredo": 32},
    "ml_dsa_44": {"chave_publica": 1312, "assinatura": 2420},
}
IGNORAR = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv"}


# ---------------------------------------------------------------- inventario
@dataclass
class Achado:
    arquivo: str
    linha: int
    categoria: str
    trecho: str


def scan(caminho: str | Path, max_bytes: int = 2_000_000) -> list[Achado]:
    """Varredura passiva: le arquivos de texto e aponta uso criptografico."""
    achados: list[Achado] = []
    raiz = Path(caminho)
    alvos = [raiz] if raiz.is_file() else raiz.rglob("*")
    for p in alvos:
        if not p.is_file() or p.suffix.lower() not in EXTENSOES:
            continue
        if any(parte in IGNORAR for parte in p.parts):
            continue
        try:
            if p.stat().st_size > max_bytes:
                continue
            texto = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for n, linha in enumerate(texto.splitlines(), 1):
            for cat, rx in PADROES.items():
                if rx.search(linha):
                    achados.append(Achado(str(p), n, cat, linha.strip()[:120]))
    return achados


def achados_para_ci(achados: list[Achado], limite: int = 50) -> list[dict]:
    """Achados no formato que o GitHub Actions consome como anotacao."""
    saida = []
    for a in achados:
        if a.categoria in ("pqc", "ot_ics", "biblioteca", "certificado"):
            continue
        saida.append({"arquivo": a.arquivo, "linha": a.linha,
                      "titulo": f"criptografia vulneravel: {a.categoria}", "trecho": a.trecho})
        if len(saida) >= limite:
            break
    return saida


def resumo_inventario(achados: list[Achado]) -> dict[str, Any]:
    por_cat: dict[str, int] = {}
    arquivos: set[str] = set()
    for a in achados:
        por_cat[a.categoria] = por_cat.get(a.categoria, 0) + 1
        arquivos.add(a.arquivo)
    return {"total": len(achados), "por_categoria": por_cat,
            "arquivos": len(arquivos),
            "tem_ot_ics": por_cat.get("ot_ics", 0) > 0,
            "ja_usa_pqc": por_cat.get("pqc", 0) > 0}


# ------------------------------------------------------- veredito de risco
@dataclass
class Ativo:
    nome: str
    algoritmo: str
    anos_migracao: float
    anos_sigilo: float
    tem_evidencia: bool = True
    notas: str = ""


def mosca(ativo: Ativo, ano_crqc: float, ano_atual: float | None = None) -> dict[str, Any]:
    """Desigualdade de Mosca aplicada a um ativo. Veredito 1 / 0 / REFUSED."""
    ano_atual = ano_atual if ano_atual is not None else datetime.now(timezone.utc).year + 0.9
    z = max(0.0, ano_crqc - ano_atual)
    alg = ativo.algoritmo.lower()
    vulneravel = any(v in alg for v in VULNERAVEIS)
    if not ativo.tem_evidencia:
        return {"ativo": ativo.nome, "veredito": "REFUSED",
                "motivo": "sem evidencia de inventario para este ativo"}
    if not vulneravel:
        return {"ativo": ativo.nome, "veredito": "1",
                "motivo": f"algoritmo fora da lista vulneravel ({ativo.algoritmo})"}
    x, y = ativo.anos_migracao, ativo.anos_sigilo
    if x + y > z:
        return {"ativo": ativo.nome, "veredito": "0",
                "motivo": f"migracao {x:g} + sigilo {y:g} = {x+y:g} anos > janela {z:g} anos",
                "x": x, "y": y, "z": round(z, 2)}
    return {"ativo": ativo.nome, "veredito": "1",
            "motivo": f"migracao {x:g} + sigilo {y:g} = {x+y:g} <= janela {z:g} anos",
            "x": x, "y": y, "z": round(z, 2)}


def veredito_sistema(ativos: list[Ativo], ano_crqc: float) -> dict[str, Any]:
    por_ativo = [mosca(a, ano_crqc) for a in ativos]
    vs = [r["veredito"] for r in por_ativo]
    if any(v == "REFUSED" for v in vs):
        agregado = "REFUSED"
    elif any(v == "0" for v in vs):
        agregado = "0"
    else:
        agregado = "1"
    return {"veredito": agregado, "ativos": por_ativo,
            "contagem": {k: vs.count(k) for k in ("1", "0", "REFUSED")}}


# ---------------------------------------------------------- agilidade
def agilidade(achados: list[Achado], total_arquivos: int) -> dict[str, Any]:
    """Agilidade = trocar algoritmo sem reconstruir. Proxy observavel:
    quantos arquivos distintos mencionam algoritmo vulneravel (espalhamento)
    contra quantos centralizam em configuracao. Nao e prova, e indicador."""
    arqs_vuln = {a.arquivo for a in achados if a.categoria in ("rsa", "ecc", "tls_antigo", "hash_fraco")}
    arqs_pqc = {a.arquivo for a in achados if a.categoria == "pqc"}
    espalhamento = len(arqs_vuln) / total_arquivos if total_arquivos else 0.0
    if espalhamento > 0.25 and len(arqs_vuln) > 3:
        veredito, motivo = "0", f"algoritmo vulneravel espalhado por {len(arqs_vuln)} arquivos"
    elif espalhamento <= 0.10:
        veredito, motivo = "1", f"uso concentrado em {len(arqs_vuln)} arquivo(s)"
    else:
        veredito, motivo = "REFUSED", f"espalhamento intermediario ({espalhamento:.2f}) sem politica declarada"
    return {"veredito": veredito, "motivo": motivo,
            "arquivos_com_vulneravel": len(arqs_vuln), "arquivos_com_pqc": len(arqs_pqc),
            "espalhamento": round(espalhamento, 3)}


# ------------------------------------------------ interoperabilidade PQC
def interop_mlkem_mldsa(rodadas: int = 3) -> dict[str, Any]:
    """Exercita ML-KEM-768 e ML-DSA-44 e confere os tamanhos contra o padrao FIPS.

    Sem o extra 'pq' o veredito e REFUSED, nunca aprovado por omissao."""
    def _kem():
        try:
            from pqcrypto import ml_kem_768 as kem
        except Exception:
            from pqcrypto.kem import ml_kem_768 as kem
        if hasattr(kem, "keygen"):
            pk, sk = kem.keygen()
            ct, ss = kem.encaps(pk)
            return pk, ct, kem.decaps(sk, ct) == ss
        pk, sk = kem.generate_keypair()
        ct, seg = kem.encrypt(pk)
        return pk, ct, kem.decrypt(sk, ct) == seg

    def _dsa():
        from pqcrypto.sign import ml_dsa_44 as sig
        msg = os.urandom(48) + hashlib.sha3_256(b"qsr").digest()
        pk, sk = sig.keygen() if hasattr(sig, "keygen") else sig.generate_keypair()
        assin = sig.sign(sk, msg)
        try:
            # o pqcrypto sinaliza sucesso com retorno None e erro com excecao
            sig.verify(pk, msg, assin)
            valida = True
        except Exception:
            valida = False
        return pk, len(assin), valida

    ok_kem = ok_sig = 0
    tam = {"kem_pk": 0, "kem_ct": 0, "sig_pk": 0, "sig_sig": 0}
    try:
        for _ in range(rodadas):
            pk, ct, bateram = _kem()
            if bateram:
                ok_kem += 1
                tam["kem_pk"], tam["kem_ct"] = len(pk), len(ct)
            spk, tam_sig, valida = _dsa()
            if valida:
                ok_sig += 1
                tam["sig_pk"], tam["sig_sig"] = len(spk), tam_sig
    except Exception as e:
        return {"veredito": "REFUSED", "motivo": f"extra 'pq' ausente ou incompativel: {type(e).__name__}"}
    veredito = "1" if (ok_kem == ok_sig == rodadas) else ("0" if ok_kem + ok_sig == 0 else "REFUSED")
    conf = (tam["kem_pk"] == TAMANHOS_PADRAO["ml_kem_768"]["chave_publica"] and
            tam["sig_pk"] == TAMANHOS_PADRAO["ml_dsa_44"]["chave_publica"])
    return {"veredito": veredito, "rodadas": rodadas, "kem_ok": ok_kem, "dsa_ok": ok_sig,
            "tamanhos_bytes": tam, "tamanhos_padrao": TAMANHOS_PADRAO,
            "confere_padrao_fips": conf,
            "nota": "chaves publicas identicas ao padrao provam que o algoritmo e o declarado"}


# ------------------------------------------------------------- recibo
def selar(payload: dict[str, Any], caminho: str | Path | None = None,
          anterior: str | None = None) -> dict[str, Any]:
    corpo = dict(payload)
    corpo.pop("sha3_256", None)
    if anterior:
        corpo["prev_sha3_256"] = anterior
    corpo["carimbo_utc"] = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    selo = hashlib.sha3_256(json.dumps(corpo, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    corpo["sha3_256"] = selo
    if caminho:
        Path(caminho).parent.mkdir(parents=True, exist_ok=True)
        Path(caminho).write_text(json.dumps(corpo, indent=1, ensure_ascii=False))
    return corpo


def verificar_recibo(caminho: str | Path) -> bool:
    d = json.loads(Path(caminho).read_text())
    selo = d.pop("sha3_256", None)
    calc = hashlib.sha3_256(json.dumps(d, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return selo == calc


# ------------------------------------------------------------ avaliacao
def avaliar(caminho: str | Path, ano_crqc: float = 2035, ativos: list[Ativo] | None = None) -> dict[str, Any]:
    achados = scan(caminho)
    inv = resumo_inventario(achados)
    arqs = len({a.arquivo for a in achados}) or 1
    ativos = ativos or []
    if not ativos:
        # deriva ativos do que foi encontrado, sem inventar tempo de sigilo
        if inv["por_categoria"].get("rsa"):
            ativos = [Ativo("rsa_detectado", "RSA", anos_migracao=3, anos_sigilo=10, tem_evidencia=True)]
        if inv["por_categoria"].get("ecc"):
            ativos.append(Ativo("ecc_detectado", "ECDSA", anos_migracao=3, anos_sigilo=10, tem_evidencia=True))
        if not ativos:
            ativos = [Ativo("sem_uso_detectado", "nenhum", 0, 0, tem_evidencia=True)]
    risco = veredito_sistema(ativos, ano_crqc)
    ag = agilidade(achados, arqs)
    io = interop_mlkem_mldsa()
    perfil = "ot_ics" if inv["tem_ot_ics"] else "corporativo"
    if perfil == "ot_ics":
        # ativo industrial vive 20+ anos: sigilo efetivo sobe
        risco = veredito_sistema([Ativo(a.nome, a.algoritmo, a.anos_migracao,
                                        a.anos_sigilo + 10, a.tem_evidencia, a.notas) for a in ativos], ano_crqc)
    final = "REFUSED" if "REFUSED" in (risco["veredito"], ag["veredito"], io["veredito"]) else \
            ("0" if "0" in (risco["veredito"], ag["veredito"], io["veredito"]) else "1")
    return {"modulo": "quantum_safe_readiness", "versao": "0.1.0",
            "alvo": str(caminho), "ano_crqc_hipotese": ano_crqc, "perfil": perfil,
            "inventario": inv, "risco": risco, "agilidade": ag, "interop_pqc": io,
            "veredito_final": final, "fontes": FONTES,
            "ressalva": "nao e atestado de conformidade regulatoria; e evidencia de prontidao"}


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(__doc__)
        return 2
    cmd, resto = argv[0], argv[1:]
    crqc = 2035
    if "--crqc" in resto:
        crqc = float(resto[resto.index("--crqc") + 1])
    if cmd == "scan":
        alvo = resto[0] if resto else "."
        quer_json = "--json" in resto
        r = avaliar(alvo, crqc)
        if quer_json:
            import tempfile
            rec = selar(r, None)
            print(json.dumps({"avaliacao": r, "recibo": rec}, ensure_ascii=False))
            return 0 if r["veredito_final"] == "1" else 1
        rec = selar(r, "examples/recibos/qsr_readiness.json")
        print(f"QSR | alvo: {alvo} | perfil: {r['perfil']}")
        print(f"inventario: {r['inventario']['total']} achados em {r['inventario']['arquivos']} arquivos {r['inventario']['por_categoria']}")
        print(f"risco: {r['risco']['veredito']} | agilidade: {r['agilidade']['veredito']} | interop PQC: {r['interop_pqc']['veredito']}")
        print(f"veredito final: {r['veredito_final']}")
        print(f"recibo: {rec['sha3_256'][:32]}")
        return 0 if r["veredito_final"] == "1" else 1
    if cmd == "check":
        cam = Path(resto[0])
        d = json.loads(cam.read_text())
        ativos = [Ativo(**a) for a in d.get("ativos", [])]
        r = veredito_sistema(ativos, crqc)
        print(json.dumps(r, indent=1, ensure_ascii=False))
        return 0 if r["veredito"] == "1" else 1
    print(f"comando desconhecido: {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
