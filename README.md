# SciELO Preservation Auditor

MVP para registrar um baseline SHA-256 imutavel dos AIPs locais, detectar mudancas
e expor resultados agregados no formato Prometheus.

## Requisitos

- Python 3.12 ou superior.
- Prometheus e Grafana existentes para coleta e visualizacao.

O MVP usa apenas a biblioteca padrao do Python. O SQLite armazena evidencias
detalhadas localmente e e criado com permissao `0600`.

## Desenvolvimento

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Criar o baseline

Execute somente depois de confirmar que os AIPs de origem sao confiaveis:

```bash
preservation-auditor baseline /var/archivematica/sharedDirectory/www/AIPsStore
```

O comando adiciona arquivos novos, mas nunca substitui baselines existentes.

## Verificar integridade

```bash
preservation-auditor check /var/archivematica/sharedDirectory/www/AIPsStore
```

Codigos de saida:

- `0`: varredura completa e todos os arquivos correspondem ao baseline;
- `2`: falha, ausencia, arquivo sem baseline ou varredura inconclusiva.

Arquivos sem baseline sao registrados como `WARNING`; eles nao sao considerados
integros enquanto um baseline explicito nao for criado.

## Expor metricas

```bash
preservation-auditor serve --host 127.0.0.1 --port 9877
```

Endpoints:

- `/metrics`
- `/health`
- `/ready`

Para aceitar conexoes remotas, publique o exporter somente em rede interna ou atras
de um proxy autenticado. O padrao `127.0.0.1` evita exposicao acidental.

O arquivo `prometheus/scrape-config.example.yml` mostra a configuracao de coleta.
Adicione `prometheus/alerts.yml` ao `rule_files` do Prometheus para habilitar os
alertas de divergencia, ausencia, cobertura incompleta, baseline pendente e auditoria
atrasada.
Importe `grafana/dashboards/integrity-overview.json` no Grafana e selecione o datasource
Prometheus existente.

## Automatizar com systemd

Os exemplos em `systemd/` incluem um timer diario, o job de verificacao e o exporter.
Antes de instala-los:

1. crie o usuario de servico `preservation-auditor` sem shell interativo;
2. instale o projeto em `/opt/preservation-auditor`;
3. copie `systemd/environment.example` para `/etc/preservation-auditor/environment`
   e ajuste apenas os caminhos e endereco de escuta;
4. garanta leitura do AIP e escrita somente em `/var/lib/preservation-auditor` e
   `/var/log/preservation-auditor`;
5. copie as unidades para `/etc/systemd/system`, recarregue o systemd e habilite
   `preservation-auditor-check.timer` e `preservation-auditor-exporter.service`.

O timer usa atraso aleatorio de ate 15 minutos para evitar picos simultaneos. O
exporter somente le o SQLite; a verificacao e feita pelo job agendado.

## Escopo deste MVP

Esta primeira entrega cobre a integridade dos AIPs locais gerados pelo Archivematica.
Os proximos coletores devem reutilizar o mesmo modelo de execucao, evidencia e metricas:

1. presenca e checksum dos AIPs nos buckets DigitalOcean, MinIO e Wasabi;
2. resolucao dos DOIs e campos minimos das landing pages do `data.scielo.org`;
3. validacao estrutural dos pacotes BagIt exportados pelo Dataverse;
4. identificacao de formatos obsoletos ou em risco.

## Testes

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Seguranca operacional

- Nao copie credenciais para `.env.example`, logs ou banco.
- Execute o auditor com usuario de sistema exclusivo e acesso somente de leitura aos AIPs.
- Proteja `data/audit.db` e `data/audit.log` em backup separado.
- Uma mudanca de baseline deve ser um processo administrativo futuro; o MVP nao oferece
  comando para sobrescrever baselines.
- Caminhos absolutos nao sao enviados ao Prometheus.
