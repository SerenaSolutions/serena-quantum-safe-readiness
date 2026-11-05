# Resultados medidos

## 1. Interoperabilidade contra o padrão (FIPS 203 e FIPS 204)

| Item | Padrão | Medido | Leitura |
|---|---|---|---|
| ML-KEM-768 chave pública | 1184 B | **1184 B** | é ML-KEM-768, não aproximação |
| ML-KEM-768 texto cifrado | 1088 B | 1088 B | conforme |
| ML-DSA-44 chave pública | 1312 B | **1312 B** | é ML-DSA-44 |
| ML-DSA-44 assinatura | 2420 B | 2420 B | conforme |

Rodadas: 3 de 3 encapsulamentos e 3 de 3 assinaturas verificadas.

## 2. Inventário no repositório do Zephirum (2.5.6)

| Categoria | Achados |
|---|---|
| hash fraco | 294 |
| certificados | 142 |
| PQC (menções) | 106 |
| bibliotecas criptográficas | 98 |
| RSA | 38 |
| TLS antigo | 25 |
| ECC | 4 |
| OT/ICS | 2 |

Total: 709 achados em 84 arquivos. Veredito final `REFUSED`: o inventário existe, mas
não há política declarada para classificar o espalhamento, e o critério não inventa.

## 3. Provas de conceito em hardware quântico IBM

Não é requisito do QSR, mas fecha o ciclo do ecossistema: as decisões auditadas rodam
em QPU real.

| Rodada | Backend | Job | Resultado |
|---|---|---|---|
| WORLD-4 | ibm_marrakesh | dbl1pfd6p51s73cnk1bg / dbl1pl56p51s73cnk1k0 / dbl1rdlgg49c73djsmv0 | W-03 p médio 0,8274; TVD 0,1117 a 0,1245 certificado |
| POC-20261105 | ibm_fez | dbmfcvt8ft8s738up32g | W-02 visibilidade 0,8284 certificado; W-01 TVD 0,3547 reprovado; W-03 p 0,7601 recusado pela banda 0,85 |
| POC-20261105b | ibm_marrakesh | dbme1pl8mdtc73d7qbig | W-02 0,8906 certificado; W-03 p 0,8008; W-01 TVD 0,2957 |

Recibos correspondentes em `examples/recibos/`.
