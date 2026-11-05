# Serena Quantum-Safe Readiness

Módulo de prontidão pós-quântica: inventaria onde a organização usa criptografia
vulnerável, aplica o critério de Mosca com hipótese declarada, mede a agilidade para
trocar algoritmos, exercita a camada pós-quântica e sela tudo em recibo auditável.

Não é atestado de conformidade regulatória. É evidência de prontidão, com os limites
escritos no próprio recibo.

## O que ele faz

1. **Inventário passivo**: varre arquivos e aponta RSA, ECC, TLS antigo, hash fraco,
   certificados, bibliotecas criptográficas, menções a PQC e sinais de OT/ICS.
2. **Critério de Mosca**: para cada ativo, compara tempo de migração somado ao tempo de
   sigilo do dado contra a janela até o computador quântico relevante. Se falta
   evidência, o veredito é `REFUSED`, nunca aprovação por omissão.
3. **Agilidade criptográfica**: mede o espalhamento do algoritmo vulnerável pelo código.
   Algoritmo espalhado em muitos arquivos significa troca cara.
4. **Interoperabilidade real**: executa ML-KEM-768 e ML-DSA-44 e confere os tamanhos
   das chaves públicas contra o padrão. Chave de 1184 bytes é ML-KEM-768; outra coisa
   seria outro algoritmo.
5. **Perfil OT/ICS**: ativo industrial ganha 10 anos de sigilo efetivo, porque vive
   décadas em campo.
6. **Recibo**: SHA3-256 sobre o conteúdo canônico, com carimbo de tempo em
   microssegundos e encadeamento opcional com o recibo anterior.

## Vereditos

`1` prontidão demonstrada · `0` migração necessária, provada pelo número ·
`REFUSED` falta evidência para decidir.

## Uso

```bash
pip install "serena-qsr[pq]"
qsr scan ./infra --crqc 2035
```

Saída: inventário por categoria, vereditos por ativo, agilidade, interop e selo do
recibo em `examples/recibos/qsr_readiness.json`.

Sem o extra `pq`, a etapa de interoperabilidade devolve `REFUSED`, que é o
comportamento correto: não se afirma o que não foi medido.

## Base científica

Fundamentação em FIPS 203, FIPS 204, FIPS 205, NIST IR 8547 (versão final de
27/10/2026), NIST SP 800-57, NSA CNSA 2.0 e NIST SP 1800-38. Nenhum texto de
terceiro é reproduzido e nenhum código de terceiro é copiado. Detalhes em
[`docs/QSR_FONTES.md`](docs/QSR_FONTES.md).

## Resultados medidos

Ver [`docs/RESULTADOS.md`](docs/RESULTADOS.md): tamanhos conferidos contra o padrão,
inventário no próprio repositório do Zephirum e provas de conceito executadas em
hardware IBM Quantum.

## Testes

```bash
python -m pytest tests -q
```

Licença Apache-2.0. Autoria institucional: Serena Quantum Solutions.
