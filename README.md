# Framework de Investigação Forense Digital em Dispositivos IoT

Este repositório contém scripts automatizados em Shell Script (`bash`) desenvolvida no âmbito da **Dissertação do Mestrado em Segurança de Informação e Direito no Ciberespaço**.

A framework foi concebida para automatizar e padronizar o processo de recolha, preservação, exame e análise de evidências digitais em ecossistemas de Internet das Coisas (IoT), alinhando-se rigorosamente com os modelos internacionais de boas práticas:
* **NIST Forensics Process Model** (NIST SP 800-86)
* **SWGDE Best Practices for IoT Forensics** (Scientific Working Group on Digital Evidence)

---

## Estrutura de Scripts

O projeto divide-se em três fases de estudo de caso, cada uma focada num cenário tecnológico e arquitetura IoT distintos:

### 🔹 Fase 1: Raspberry Pi 4 + NoIR Camera Module v2 (Dispositivos abertos)
Focada na recolha direta de artefactos locais, dados voláteis de sistema e streams de vídeo raw em dispositivos controlados pelo utilizador.
* `capturar_rede_fase1.sh`: *Collection* — Identificação do dispositivo na rede local, scanning de portas abertas (`nmap`), persistência de conexões de rede e sniffing de tráfego (`tshark` / `pcap`).
* `extrair_evidencias_fase1.sh`: *Examination* — Indexação e hashing prévio na origem, extração segura via SCP e verificação bit-a-bit contra falhas de transporte.
* `analisar_evidencias_fase1.sh`: *Analysis & Reporting* — Parse de logs, extração de metadados estruturados (`ExifTool`) e consolidação do relatório pericial final.

### 🔹 Fase 2: TP-Link Tapo TC71 + Agent DVR (Dispositivos proprietários/fechados)
Focada em servidores de gestão de vídeo (Video Management Software) locais que interagem com câmaras IP de consumo.
* `capturar_rede_fase2.sh`: *Collection* — Isolamento e escuta do tráfego RTSP/ONVIF da câmara.
* `extrair_evidencias_fase2.sh`: *Examination* — Análise e dumping da base de dados SQLite do Agent DVR, extração de logs de sessão, ficheiros de configuração JSON e conteúdos multimédia.
* `analisar_evidencias_fase2.sh`: *Analysis & Reporting* — Reconstrução lógica de eventos forenses e inventariação de integridade global.

### 🔹 Fase 3: TP-Link Tapo Pan/Tilt (Dispositivos cloud-connected)
Focada em dispositivos estritamente dependentes de infraestruturas Cloud proprietárias, onde os dados locais estão cifrados.
* `capturar_rede_fase3.sh`: *Collection* — Captura detalhada de pacotes de sinalização e comunicação TLS/DNS.
* `geolocalizacao_ips_fase3.sh`: *Analysis* — Resolução em lote e geolocalização IP geográfica (`ip-api`) dos endpoints de comando e controlo do fabricante (Cloud).
* `analisar_evidencias_fase3.sh`: *Analysis & Reporting* — Análise de volumes de tráfego, perfis de comunicação e geração do documento probatório final.

---

## Alinhamento Normativo e Garantias Forenses

Para assegurar a admissibilidade das evidências em tribunal, a framework executa de forma nativa controlos automatizados:

1.  **Cadeia de Custódia Digital (Chain of Custody):** Cada script gera ou atualiza um ficheiro de registo histórico imutável (`cadeia_custodia_*.txt`), documentando quem executou a ação, quando (em marcas de tempo UTC) e quais os hashes envolvidos.
2.  **Preservação de Integridade (Anti-Adulteração):** Implementação do algoritmo **SHA-256** executado na origem (Live Forensics controlado) antes de qualquer transferência lógica de ficheiros, mitigando riscos de alteração de metadados do sistema de ficheiros nativo (*MAC times*).
3.  **Reprodutibilidade:** Os outputs de análise baseiam-se em ferramentas standard da indústria (`tshark`, `exiftool`, `nmap`, `sqlite3`), garantindo que qualquer contra-perícia independente consiga replicar exatamente os mesmos resultados.

---

## Pré-requisitos e Instalação

Os scripts foram desenvolvidos para correr nativamente num **PC Forense** Linux (testado e homologado em ambiente WSL2 / Ubuntu).

### Instalação das dependências locais:
```bash
sudo apt update && sudo apt install -y \
    nmap \
    tshark \
    libimage-exiftool-perl \
    sqlite3 \
    curl \
    awk \
    diffutils
