# SciELO Preservation Auditor

MVP para registrar um baseline SHA-256 imutavel dos AIPs locais, detectar mudancas
e expor resultados agregados no formato Prometheus.

## Requisitos

- Python 3.9 ou superior.
- Prometheus e Grafana existentes para coleta e visualizacao.

O projeto usa apenas a biblioteca padrao do Python, inclusive para requisicoes S3
assinadas com AWS Signature V4. O SQLite armazena evidencias detalhadas localmente
e e criado com permissao `0600`.

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

## Baseline automatico apos o Archivematica

O comando `baseline-auto` implementa o fluxo confiavel por evento:

1. valida um recibo JSON assinado pelo Archivematica;
2. exige `ingest_status=COMPLETED` e recibo recente;
3. calcula o SHA-256 e tamanho do AIP local;
4. confirma o objeto via `HEAD` no DigitalOcean, MinIO e Wasabi;
5. registra baseline, evento e evidencias das replicas em uma transacao SQLite;
6. executa imediatamente a verificacao integral local.

Copie `config/replicas.example.json` para um arquivo fora do repositorio, ajuste
endpoints e buckets e mantenha as credenciais somente nas variaveis de ambiente
indicadas pelo arquivo. As tres replicas sao obrigatorias.

```bash
preservation-auditor baseline-auto \
  --receipt /var/lib/preservation-auditor/inbox/event-20260914-001.json \
  --aip-root /var/archivematica/sharedDirectory/www/AIPsStore \
  --replicas-config /etc/preservation-auditor/replicas.json
```

O recibo segue `examples/archivematica-receipt.example.json`. A assinatura e o
HMAC-SHA-256 hexadecimal do JSON sem o campo `signature`, serializado com chaves
ordenadas e separadores compactos. A chave compartilhada deve ter ao menos 32 bytes
e existir em `PRESERVATION_RECEIPT_HMAC_KEY` nos dois lados. Exemplo do trecho que
deve rodar no hook confiavel do Archivematica:

```python
canonical = json.dumps(
    receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")
).encode("utf-8")
receipt["signature"] = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
```

O campo `object_key` tambem e assinado. A verificacao nunca usa ETag como checksum,
pois ele pode representar upload multipart. Se os uploads gravarem SHA-256 em
metadata S3, defina `require_checksum_metadata` como `true`; caso contrario, a
replica e confirmada por existencia e tamanho, enquanto o checksum forte e validado
localmente contra o recibo assinado.

Recibos repetidos sao idempotentes: nao sobrescrevem nem duplicam o baseline, mas
refazem a validacao remota e o check local. Recibos expirados, com caminho fora do
AIP root, symlink, checksum divergente ou replica indisponivel nao criam baseline.

## Integracao instalada com o Archivematica

O coletor `preservation_auditor.archivematica` consulta os modelos Django do
Storage Service em uma conexao somente de leitura. O timer
`preservation-auditor-archivematica.timer` executa uma nova consulta um minuto
apos o termino da anterior. Nao depende de entrega de callbacks HTTP: falhas ou
replicas em STAGING permanecem pendentes para a proxima consulta.

Somente AIPs originais locais (FS), UPLOADED e com `stored_date` a partir de
`PRESERVATION_ARCHIVEMATICA_SINCE` sao considerados. Esse instante, com fuso
horario ISO 8601, deve ser fixado na ativacao, em
`/etc/preservation-auditor/archivematica.environment`. Alterar esse marco para
uma data passada inclui ingestoes historicas e exige planejamento do backfill.

O coletor exige tres replicas UPLOADED, com tamanho e SHA-256 iguais aos
registrados para o original. Endpoint e bucket devem corresponder ao
`replicas.json`. No Storage Service, bucket S3 vazio significa usar o UUID do
Space como nome do bucket. O coletor usa o checksum do Storage Service; o
baseline-auto verifica o arquivo local contra esse valor.

O recibo v2 acrescenta `replica_object_keys`, um objeto com as chaves
`digitalocean`, `minio` e `wasabi`. Cada valor combina o `relative_path` da
Location e o `current_path` da replica; isso preserva os UUIDs diferentes usados
pelo Archivematica. Todo o mapa e coberto pela assinatura HMAC. Recibos v1
continuam aceitos. A data de conclusao e a maior `stored_date` do conjunto. O
comando manual `baseline-auto` continua recusando recibos expirados. O coletor
instalado dispensa somente essa verificacao temporal porque, em cada tentativa,
rele o estado atual no Storage Service e refaz as validacoes do arquivo local e
das tres replicas. Assim, uma indisponibilidade prolongada do coletor nao deixa
AIPs permanentemente pendentes.

Os recibos sao publicados atomicamente em
`/var/lib/preservation-auditor/inbox/archivematica-<UUID_DO_AIP>.json`, sem
sobrescrever eventos. O coletor chama diretamente o mesmo fluxo de
`baseline-auto`; eventos ja registrados sao ignorados. O timer de integridade
continua responsavel pelas verificacoes recorrentes. Erros de replica ou
validade ficam no journal e fazem a execucao terminar com codigo 2.

## Auditoria periodica das replicas

Depois que o baseline automatico registra as evidencias, o comando abaixo volta a
consultar cada objeto no DigitalOcean, MinIO e Wasabi:

```bash
preservation-auditor check-replicas \
  --replicas-config /etc/preservation-auditor/replicas.json
```

A verificacao usa somente requisicoes `HEAD`: nao baixa nem modifica os AIPs. Cada
replica e avaliada independentemente para que uma indisponibilidade nao esconda o
estado dos outros provedores. Objeto ausente, tamanho divergente ou SHA-256 de
metadata divergente resultam em `FAIL`; falha de rede, credencial ou configuracao
resulta em `UNKNOWN` e marca a cobertura como incompleta. Quando a metadata SHA-256
nao e obrigatoria nem esta presente, existencia e tamanho sao verificados e a
evidencia registra `checksum_verified=false`.

Instale `systemd/preservation-auditor-replicas.service` e
`systemd/preservation-auditor-replicas.timer`, execute `systemctl daemon-reload` e
habilite com:

```bash
systemctl enable --now preservation-auditor-replicas.timer
```

O timer executa diariamente as 03:00 com atraso aleatorio de ate 15 minutos. O
comando termina com codigo `0` somente quando todas as replicas registradas estao
conformes; divergencia ou resultado inconclusivo termina com codigo `2`.

Instalacao nesta distribuicao:

1. Instale as unidades `systemd/preservation-auditor-archivematica.*` em
   `/etc/systemd/system/`.
2. Copie `config/archivematica-logging.json` para `/etc/preservation-auditor/`.
   O bind do systemd usa esse logging somente no coletor.
3. Grave `PRESERVATION_ARCHIVEMATICA_SINCE=<instante-da-ativacao-com-fuso>`
   em `/etc/preservation-auditor/archivematica.environment` (root, modo 0600).
   Nesse mesmo arquivo, sobrescreva as credenciais do banco com um usuario
   dedicado que tenha apenas permissao `SELECT` no banco do Storage Service.
4. Confira os buckets reais em `replicas.json`, as credenciais e a chave HMAC
   em `/etc/preservation-auditor/environment`.
5. Execute `systemctl daemon-reload`, depois
   `systemctl start preservation-auditor-archivematica.service` e
   `systemctl enable --now preservation-auditor-archivematica.timer`.

O servico usa o Python do Storage Service, seu EnvironmentFile e o codigo do
auditor via PYTHONPATH. Nao executa migracoes nem modifica os pacotes.
Para acompanhar:

```bash
systemctl list-timers preservation-auditor-archivematica.timer
journalctl -u preservation-auditor-archivematica.service -n 50 --no-pager
```

Para repetir manualmente um recibo ja emitido:

```bash
systemctl start preservation-auditor-baseline-auto@archivematica-UUID_DO_AIP.service
```

## Verificar integridade

```bash
preservation-auditor check /var/archivematica/sharedDirectory/www/AIPsStore
```

Codigos de saida:

- `0`: varredura completa e todos os arquivos correspondem ao baseline;
- `2`: falha, ausencia, arquivo sem baseline ou varredura inconclusiva.

Arquivos sem baseline sao registrados como `WARNING`; eles nao sao considerados
integros enquanto um baseline explicito nao for criado.

## Validar pacotes BagIt do Dataverse

O comando `check-bagits` descobre bags em diretorios e dentro de arquivos ZIP,
valida a estrutura, os arquivos obrigatorios, a cobertura do payload e os
checksums sem extrair o ZIP:

```bash
preservation-auditor check-bagits \
  /var/archivematica/sharedDirectory/transferSource/dataverse/dataverse
```

Manifestos SHA-256 e SHA-512 sao aceitos como evidencia forte. Para os pacotes
historicos, `manifest-md5.txt` e recalculado e comparado, mas um resultado correto
recebe `WARNING` com `BAG_WEAK_MANIFEST_ALGORITHM` e
`BAG_STRONG_MANIFEST_MISSING`: MD5 ajuda a detectar alteracoes acidentais, mas nao
e aceito como evidencia criptografica forte. Uma divergencia MD5 continua sendo
`FAIL`. A remediacao recomendada e gerar tambem um manifesto SHA-256 ou SHA-512 no
fluxo produtor, sem alterar silenciosamente o pacote preservado.

ZIPs sao lidos em streaming e nunca extraidos. Caminhos absolutos ou com `..`,
arquivos duplicados, entradas criptografadas e razoes de compressao suspeitas sao
rejeitados. Diretorios ZIP repetidos sao tolerados. Caminhos com `//` e descricoes
multilinha nao padronizadas do Dataverse sao validados pelo nome exato e registrados
como `WARNING`. O comando retorna `0` quando todos os pacotes sao legiveis e estao
em `PASS` ou `WARNING`; retorna `2` quando encontra `FAIL` ou `UNKNOWN`.

Configure `PRESERVATION_BAGIT_ROOT` em
`/etc/preservation-auditor/environment`, instale as unidades
`preservation-auditor-bagits.service` e `.timer`, recarregue o systemd e habilite:

```bash
systemctl daemon-reload
systemctl enable --now preservation-auditor-bagits.timer
systemctl start preservation-auditor-bagits.service
journalctl -u preservation-auditor-bagits.service -n 50 --no-pager
```

O timer executa aos domingos as 04:00, com atraso aleatorio de ate 30 minutos.
Os resultados detalhados ficam no SQLite e no log de auditoria; os agregados
`scielo_preservation_bagits_*` sao publicados pelo exporter para Prometheus e
Grafana.

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
alertas de divergencia, ausencia, cobertura incompleta, baseline pendente, BagIt
invalido e auditoria atrasada.
Importe `grafana/dashboards/integrity-overview.json` no Grafana e selecione o datasource
Prometheus existente.

## Automatizar com systemd

Os exemplos em `systemd/` incluem os timers de integridade, replicas e BagIt, o
exporter e a unidade parametrizada
`preservation-auditor-baseline-auto@.service`.
Antes de instala-los:

1. crie o usuario de servico `preservation-auditor` sem shell interativo;
2. instale o projeto em `/opt/preservation-auditor`;
3. copie `systemd/environment.example` para `/etc/preservation-auditor/environment`
   e ajuste apenas os caminhos e endereco de escuta;
4. garanta leitura do AIP e escrita somente em `/var/lib/preservation-auditor` e
   `/var/log/preservation-auditor`;
5. copie as unidades para `/etc/systemd/system`, recarregue o systemd e habilite
   `preservation-auditor-check.timer`, `preservation-auditor-replicas.timer`,
   `preservation-auditor-bagits.timer` e `preservation-auditor-exporter.service`.

Depois que o hook do Archivematica gravar atomicamente um recibo assinado em
`/var/lib/preservation-auditor/inbox/`, ele pode iniciar a unidade usando somente o
`event_id` validado:

```bash
systemctl start preservation-auditor-baseline-auto@event-20260914-001.service
```

Restrinja essa autorizacao do systemd ao usuario do hook e apenas a essa unidade.
Proteja `/etc/preservation-auditor/environment` com modo `0600` e acesso de root,
pois ele recebe a chave HMAC e as credenciais S3 por provisionamento seguro.

O timer usa atraso aleatorio de ate 15 minutos para evitar picos simultaneos. O
exporter somente le o SQLite; a verificacao e feita pelo job agendado.

## Escopo deste MVP

Esta entrega cobre a integridade local e o baseline automatico condicionado as tres
replicas dos AIPs gerados pelo Archivematica. Os proximos coletores devem reutilizar
o mesmo modelo de execucao, evidencia e metricas:

1. resolucao dos DOIs e campos minimos das landing pages do `data.scielo.org`;
2. validacao estrutural dos pacotes BagIt exportados pelo Dataverse;
3. identificacao de formatos obsoletos ou em risco.

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
