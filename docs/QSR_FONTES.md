# QSR — fundamentação na literatura primária

Este documento registra de onde vem cada número usado pelo módulo
`quantum_safe_readiness`. Nenhum texto de terceiro é reproduzido: as fontes foram
lidas, os **fatos** (tamanhos, datas, definições) foram extraídos e reescritos com
nossas palavras. Nenhum código de terceiro foi copiado para dentro do repositório; o
que existe são dependências declaradas e instaladas via `pip`.

## 1. Normas primárias

| Fonte | O que é | O que usamos dela |
|---|---|---|
| FIPS 203, NIST, 13/08/2024 | Padrão do ML-KEM (encapsulamento de chaves baseado em reticulados modulares) | Conjuntos de parâmetros 512/768/1024 e os tamanhos oficiais de chave, texto cifrado e segredo compartilhado |
| FIPS 204, NIST, 13/08/2024 | Padrão do ML-DSA (assinatura digital em reticulados) | Tamanhos oficiais de chave pública, chave secreta e assinatura para o parâmetro 44 |
| FIPS 205, NIST, 13/08/2024 | Padrão do SLH-DSA (assinatura baseada em hash) | Citado como alternativa de assinatura quando o perfil exigir só hipóteses de hash |
| NIST IR 8547, **final**, 27/10/2026 (DOI 10.6028/NIST.IR.8547) | Plano de transição do NIST para criptografia pós-quântica | Estrutura da migração e a existência de datas-limite de descontinuação. A versão preliminar era de 12/11/2024 e foi substituída pela final |
| NIST SP 800-57 (partes 1 e 3) | Gestão de chaves | Conceito de criptoperíodo: por quanto tempo um dado precisa permanecer protegido |
| NSA CNSA 2.0, 2022 | Suite de algoritmos para sistemas de segurança nacional dos EUA | Perfil de exigência mais rígido, usado como teto conservador quando o cliente é defesa ou infraestrutura crítica |
| NIST SP 1800-38 (NCCoE) | Guia prático de migração para PQC | Estrutura das fases de inventário, priorização e prova de migração |

## 2. A desigualdade de Mosca

Mosca formalizou o critério de decisão que o módulo implementa: se o tempo de migração
somado ao tempo de sigilo do dado ultrapassa a janela até um computador quântico
relevante, a ação é agora e não depois. Escrevemos isso como `X + Y > Z`, com
`X` = anos de migração, `Y` = anos de sigilo e `Z` = anos até o CRQC.

O módulo **não** afirma quando o CRQC chega. `Z` é hipótese declarada pelo operador e
vai impressa no recibo, para que o leitor possa discordar do número e refazer a conta.

## 3. Tamanhos: padrão contra medido

O módulo mede o que a nossa camada realmente produz e compara com o padrão. Chave
pública de tamanho diferente do padrão significaria implementação trocada, não
otimização.

| Item | Padrão | Nosso medido | Leitura |
|---|---|---|---|
| ML-KEM-768 chave pública | 1184 B | 1184 B | idêntico: é ML-KEM-768 de verdade |
| ML-KEM-768 texto cifrado | 1088 B | envelope maior | o nosso envelope carrega base64 e metadados JSON |
| ML-DSA-44 chave pública | 1312 B | 1312 B | idêntico: é ML-DSA-44 de verdade |
| ML-DSA-44 assinatura | 2420 B | envelope maior | mesma razão: base64 e JSON |

## 4. O que este módulo não faz

Não emite atestado de conformidade regulatória, não substitui auditoria independente e
não promete interoperabilidade com sistemas de terceiros que não foram testados. Ele
produz inventário, aplica o critério de Mosca com hipótese declarada, mede a camada
PQC e sela o resultado em recibo verificável.

## 5. Datas de política

As datas de descontinuação de RSA e ECC constam da IR 8547. Como a versão final foi
publicada em outubro de 2026 e pode ser revista, o módulo **não** embute prazo fixo:
recebe `--crqc` e as datas de política como entrada declarada, e imprime a hipótese no
recibo.
