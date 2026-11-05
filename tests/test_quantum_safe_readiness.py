"""Testes do QSR: cada assert compara com a conclusao esperada por construcao."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from quantum_safe_readiness import (Ativo, agilidade, avaliar, interop_mlkem_mldsa,
                                    mosca, scan, selar, veredito_sistema, verificar_recibo)

ANO_CRQC = 2035
ATUAL = 2026.9


def test_mosca_migrar_agora():
    # migracao 5 + sigilo 12 = 17 > janela 8.1 -> veredito 0
    r = mosca(Ativo("core", "RSA-2048", 5, 12), ANO_CRQC, ATUAL)
    assert r["veredito"] == "0", r
    assert r["x"] + r["y"] > r["z"]


def test_mosca_pode_planejar():
    # migracao 1 + sigilo 2 = 3 <= 8.1 -> veredito 1
    r = mosca(Ativo("telemetria", "RSA-2048", 1, 2), ANO_CRQC, ATUAL)
    assert r["veredito"] == "1", r


def test_mosca_algoritmo_seguro():
    r = mosca(Ativo("novo", "ML-KEM-768", 0, 30), ANO_CRQC, ATUAL)
    assert r["veredito"] == "1"
    assert "fora da lista vulneravel" in r["motivo"]


def test_mosca_sem_evidencia_e_refused():
    r = mosca(Ativo("desconhecido", "RSA-2048", 0, 0, tem_evidencia=False), ANO_CRQC, ATUAL)
    assert r["veredito"] == "REFUSED"


def test_agregacao_sistema():
    ativos = [Ativo("a", "RSA-2048", 5, 12), Ativo("b", "ML-DSA-44", 0, 30)]
    assert veredito_sistema(ativos, ANO_CRQC)["veredito"] == "0"
    ativos = [Ativo("a", "RSA-1024", 5, 12, tem_evidencia=False), Ativo("b", "RSA-2048", 5, 12)]
    assert veredito_sistema(ativos, ANO_CRQC)["veredito"] == "REFUSED"
    ativos = [Ativo("a", "ML-KEM-768", 1, 1)]
    assert veredito_sistema(ativos, ANO_CRQC)["veredito"] == "1"


def test_scan_detecta_padroes(tmp_path):
    f = tmp_path / "cfg.yaml"
    f.write_text("tls: TLSv1.1\nkey: RSA-2048\nmodbus: plc\n", encoding="utf-8")
    achados = scan(tmp_path)
    cats = {a.categoria for a in achados}
    assert "tls_antigo" in cats and "rsa" in cats and "ot_ics" in cats, cats


def test_agilidade_espalhada(tmp_path):
    for i in range(6):
        (tmp_path / f"m{i}.py").write_text("use RSA-2048 aqui\n", encoding="utf-8")
    achados = scan(tmp_path)
    r = agilidade(achados, total_arquivos=6)
    assert r["veredito"] == "0", r


def test_agilidade_concentrada(tmp_path):
    for i in range(10):
        (tmp_path / f"m{i}.py").write_text("print('sem cripto')\n", encoding="utf-8")
    (tmp_path / "crypto.py").write_text("RSA-2048\n", encoding="utf-8")
    achados = scan(tmp_path)
    assert agilidade(achados, total_arquivos=11)["veredito"] == "1"


def test_interop_pqc_ou_refused():
    r = interop_mlkem_mldsa(rodadas=2)
    assert r["veredito"] in ("1", "REFUSED"), r
    if r["veredito"] == "1":
        assert r["kem_ok"] == 2 and r["dsa_ok"] == 2


def test_recibo_selado_e_verificavel(tmp_path):
    cam = tmp_path / "r.json"
    rec = selar({"x": 1}, cam)
    assert verificar_recibo(cam)
    d = json.loads(cam.read_text())
    d["x"] = 2
    cam.write_text(json.dumps(d))
    assert not verificar_recibo(cam)


def test_avaliar_no_proprio_repositorio():
    r = avaliar(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"), ANO_CRQC)
    assert r["veredito_final"] in ("0", "1", "REFUSED")
    assert r["inventario"]["total"] > 0
    assert "conformidade" in r["ressalva"]
