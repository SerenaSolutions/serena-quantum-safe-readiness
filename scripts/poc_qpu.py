"""Prova de conceito em QPU real, a partir deste repositorio.

O nucleo do QSR e classico; este script existe para que a evidencia citada em
docs/RESULTADOS.md seja reproduzivel por quem instala o extra 'hardware'.
Protocolo selado ANTES da execucao. Sem --hardware, roda em simulador.

    pip install "serena-qsr[hardware]"
    python scripts/poc_qpu.py                     # simulador
    python scripts/poc_qpu.py --hardware          # QPU IBM (requer token)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

AQUI = Path(__file__).resolve().parent.parent
RECIBOS = AQUI / "examples" / "recibos"

PROTOCOLO = {
    "id": "QSR-POC",
    "shots": 2048,
    "circuito": "Grover 3 qubits, marcado |101>, 2 iteracoes (optimo para N=8, M=1)",
    "bandas": {"p_marcado": [0.85, 0.70]},
    "previsao_teorica": {"p_ideal": 0.9453125, "classico": 0.125},
    "declarado_em": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}


def selar(payload: dict, caminho: Path) -> dict:
    corpo = dict(payload)
    corpo["carimbo_utc"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    selo = hashlib.sha3_256(json.dumps(corpo, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    corpo["sha3_256"] = selo
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(json.dumps(corpo, indent=1, ensure_ascii=False))
    return corpo


def grover(marcado: str = "101", iteracoes: int = 2):
    from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister

    qr = QuantumRegister(3, "q")
    cr = ClassicalRegister(3, "c")
    qc = QuantumCircuit(qr, cr)
    for i in range(3):
        qc.h(i)
    for _ in range(iteracoes):
        for i, b in enumerate(marcado):
            if b == "0":
                qc.x(i)
        qc.h(2)
        qc.mcx([0, 1], 2)
        qc.h(2)
        for i, b in enumerate(marcado):
            if b == "0":
                qc.x(i)
        for i in range(3):
            qc.h(i)
            qc.x(i)
        qc.h(2)
        qc.mcx([0, 1], 2)
        qc.h(2)
        for i in range(3):
            qc.x(i)
            qc.h(i)
    qc.measure(qr, cr)
    return qc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hardware", action="store_true")
    ap.add_argument("--shots", type=int, default=PROTOCOLO["shots"])
    a = ap.parse_args()

    protocolo = dict(PROTOCOLO)
    protocolo["shots"] = a.shots
    protocolo["sha3_protocolo"] = hashlib.sha3_256(
        json.dumps(protocolo, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    print("protocolo selado antes da execucao:", protocolo["sha3_protocolo"][:32])

    from qiskit import transpile

    qc = grover()
    if a.hardware:
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

        tok = os.environ.get("IBM_QUANTUM_TOKEN") or os.environ.get("IBM_API_KEY") or os.environ.get("QISKIT_IBM_TOKEN")
        if not tok:
            print("sem token IBM (IBM_QUANTUM_TOKEN / QISKIT_IBM_TOKEN)"); return 2
        svc = QiskitRuntimeService(channel="ibm_quantum_platform", token=tok)
        backend = svc.least_busy(operational=True, simulator=False)
        tqc = transpile(qc, backend=backend, optimization_level=3, seed_transpiler=11)
        job = Sampler(mode=backend).run([tqc], shots=a.shots)
        counts = job.result()[0].data.c.get_counts()
        dispositivo, jid = backend.name, job.job_id()
    else:
        from qiskit_aer import AerSimulator

        sim = AerSimulator(seed_simulator=7)
        job = sim.run(transpile(qc, sim), shots=a.shots)
        counts = job.result().get_counts()
        dispositivo, jid = "aer_simulator", "local"

    n = sum(counts.values())
    p = counts.get("101", 0) / n
    banda = PROTOCOLO["bandas"]["p_marcado"]
    veredito = "1" if p >= banda[0] else ("0" if p < banda[1] else "REFUSED")
    rec = selar({"protocolo": protocolo, "execucao": {"dispositivo": dispositivo, "job_id": jid,
                "shots": a.shots, "contagens": counts},
                "resultado": {"p_marcado": round(p, 4), "p_ideal": 0.9453125,
                              "classico": 0.125, "veredito": veredito}},
                RECIBOS / "poc_qpu.json")
    print(f"dispositivo: {dispositivo} | job: {jid}")
    print(f"p(|101>) = {p:.4f}  (ideal 0.9453, classico 0.125)  -> veredito {veredito}")
    print("recibo:", rec["sha3_256"][:32])
    return 0 if veredito == "1" else 1


if __name__ == "__main__":
    raise SystemExit(main())
