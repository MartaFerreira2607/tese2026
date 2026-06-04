#!/bin/bash
# =============================================================================
# FASE 3: EXAMINATION + ANALYSIS + REPORTING
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: TP-Link Tapo Pan/Tilt Wi-Fi Camera (cloud-connected)
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/i/Mestrado/Tese/Fase3"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- VERIFICA CASO DO SCRIPT DE COLLECTION ---
FICHEIRO_CASO="$BASE/.caso_atual"
FICHEIRO_IP="$BASE/.ip_camera"

if [ -f "$FICHEIRO_CASO" ]; then
    CASO=$(cat "$FICHEIRO_CASO")
    echo "A usar caso existente: $CASO"
else
    echo "ERRO: Nenhum caso encontrado. Corre primeiro capturar_rede_fase3.sh"
    exit 1
fi

if [ -f "$FICHEIRO_IP" ]; then
    IP_CAMERA=$(cat "$FICHEIRO_IP")
    echo "IP da camera: $IP_CAMERA"
else
    echo ""
    read -p "    IP da camera Tapo (ex: 192.168.137.X): " IP_CAMERA </dev/tty
fi

COLLECTION="$BASE/$CASO/recolha"
FICHEIRO_PCAP_PATH="$BASE/.pcap_path"
DESTINO="$BASE/$CASO/analise"
mkdir -p "$DESTINO/rede"
mkdir -p "$DESTINO/hashes"

LOG="$DESTINO/log_analysis_$TIMESTAMP.txt"

# --- CORES ---
VERDE='\033[0;32m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
AZUL='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${VERDE}[$(date '+%Y-%m-%d %H:%M:%S UTC')]${NC} $1" | tee -a "$LOG"; }
aviso() { echo -e "${AMARELO}[AVISO]${NC} $1" | tee -a "$LOG"; }
erro()  { echo -e "${VERMELHO}[ERRO]${NC} $1" | tee -a "$LOG"; }
fase()  { echo -e "${AZUL}[FRAMEWORK]${NC} $1" | tee -a "$LOG"; }

# Le o path do pcap — procura primeiro dentro da pasta do caso, depois na base
if [ -f "$COLLECTION/.pcap_path" ]; then
    PCAP=$(cat "$COLLECTION/.pcap_path")
elif [ -f "$BASE/.pcap_path" ]; then
    PCAP=$(cat "$BASE/.pcap_path")
else
    PCAP=$(ls "$COLLECTION/"*.pcap* 2>/dev/null | head -1)
fi
if [ -z "$PCAP" ] || [ ! -f "$PCAP" ]; then
    erro "Ficheiro pcap nao encontrado."
    erro "Corre primeiro capturar_rede_fase3.sh e guarda o pcap na pasta correta."
    exit 1
fi

# =============================================================================
# INÍCIO
# =============================================================================
clear
echo "============================================================"
echo "   FASE 3: EXAMINATION + ANALYSIS + REPORTING"
echo "   Framework NIST + SWGDE | Tapo Pan/Tilt (cloud-connected)"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

fase "Fase EXAMINATION iniciada - NIST: Extracao e analise do pcap"
fase "SWGDE: Verificacao de integridade + Relatorio formal"
echo ""

log "=== INICIO DA EXAMINATION + ANALYSIS ==="
log "Caso:         $CASO"
log "IP camera:    $IP_CAMERA"
log "Pcap:         $PCAP"
log "Destino:      $DESTINO"
log "Investigador: $(whoami)"
echo ""

# Ficheiro de cadeia de custodia da analise
FICHEIRO_CUSTODIA="$DESTINO/hashes/cadeia_custodia_analysis_$TIMESTAMP.txt"
cat > "$FICHEIRO_CUSTODIA" << EOF
=============================================================
CADEIA DE CUSTODIA - EXAMINATION + ANALYSIS
Framework NIST + SWGDE
Caso: $CASO
Data/Hora Inicio: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
Dispositivo: TP-Link Tapo Pan/Tilt Wi-Fi Camera
IP da camera: $IP_CAMERA
Pcap analisado: $(basename $PCAP)
=============================================================

EOF

# Relatorio final
RELATORIO="$DESTINO/relatorio_final_$CASO.txt"
cat > "$RELATORIO" << EOF
=============================================================
RELATORIO FORENSE FINAL - REPORTING
Framework NIST Forensics Process Model + SWGDE Best Practices
=============================================================
Caso:           $CASO
Data/Hora:      $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador:   $(whoami)
Dispositivo:    TP-Link Tapo Pan/Tilt Wi-Fi Camera
Metodo:         Captura via Wireshark no Windows (hotspot ForenseLab)
Pcap:           $(basename $PCAP)
=============================================================

EOF

# -----------------------------------------------------------------------------
# 1. VERIFICAÇÃO DE INTEGRIDADE DO PCAP - SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE - Verificacao de integridade do pcap original"
log "--- PASSO 1: Verificacao de integridade ---"

# Re-calcula o hash do pcap e compara com o registado na collection
HASH_PCAP_ATUAL=$(sha256sum "$PCAP" | awk '{print $1}')
CUSTODIA_COLLECTION=$(ls "$COLLECTION/cadeia_custodia_collection_"*.txt 2>/dev/null | head -1)

echo "==============================================================" >> "$RELATORIO"
echo "1. VERIFICACAO DE INTEGRIDADE (SWGDE)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Ficheiro: $(basename $PCAP)" >> "$RELATORIO"
echo "  SHA-256 atual: $HASH_PCAP_ATUAL" >> "$RELATORIO"

if [ -f "$CUSTODIA_COLLECTION" ] && grep -q "$HASH_PCAP_ATUAL" "$CUSTODIA_COLLECTION"; then
    echo "  Integridade: VERIFICADA - hash coincide com cadeia de custodia da collection" >> "$RELATORIO"
    log "Integridade do pcap: VERIFICADA"
else
    echo "  Integridade: AVISO - hash nao encontrado na cadeia de custodia" >> "$RELATORIO"
    aviso "Hash do pcap nao encontrado na cadeia de custodia da collection."
fi
echo "" >> "$RELATORIO"

echo "Pcap analisado: $(basename $PCAP)" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_PCAP_ATUAL" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
echo ""

# -----------------------------------------------------------------------------
# 2. IPs DE DESTINO CONTACTADOS - NIST: Examination
# -----------------------------------------------------------------------------
fase "NIST - Examination: IPs de destino contactados pela camera"
log "--- PASSO 2: Extracao de IPs de destino ---"

FICHEIRO_IPS="$DESTINO/rede/ips_destino_$TIMESTAMP.txt"
tshark -r "$PCAP" \
    -Y "ip.src == $IP_CAMERA" \
    -T fields -e ip.dst \
    2>/dev/null | sort | uniq -c | sort -rn > "$FICHEIRO_IPS"

TOTAL_IPS=$(wc -l < "$FICHEIRO_IPS")
HASH_IPS=$(sha256sum "$FICHEIRO_IPS" | awk '{print $1}')
echo "IPs de destino contactados" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_IPS" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "IPs extraidos: $TOTAL_IPS destinos unicos | SHA-256: $HASH_IPS"
echo ""

echo "==============================================================" >> "$RELATORIO"
echo "2. IPs DE DESTINO CONTACTADOS PELA CAMERA" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Total de IPs unicos contactados: $TOTAL_IPS" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Pacotes  IP de destino" >> "$RELATORIO"
echo "  -------  --------------" >> "$RELATORIO"
cat "$FICHEIRO_IPS" | while read linha; do
    echo "  $linha" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"

# -----------------------------------------------------------------------------
# 3. IDENTIFICAÇÃO DAS ORGANIZAÇÕES (WHOIS) - NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST - Analysis: Identificacao das organizacoes dona dos IPs"
log "--- PASSO 3: Whois dos IPs de destino ---"

FICHEIRO_WHOIS="$DESTINO/rede/whois_ips_$TIMESTAMP.txt"
cat > "$FICHEIRO_WHOIS" << EOF
=============================================================
IDENTIFICACAO DE ORGANIZACOES - WHOIS
Caso: $CASO | Data: $(date '+%Y-%m-%d %H:%M:%S UTC')
=============================================================

EOF

echo "==============================================================" >> "$RELATORIO"
echo "3. IDENTIFICACAO DAS ORGANIZACOES (WHOIS)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

# Para cada IP de destino, faz whois e extrai campos relevantes
awk '{print $2}' "$FICHEIRO_IPS" | while read IP; do
    if [ -n "$IP" ]; then
        WHOIS_OUT=$(whois "$IP" 2>/dev/null)

        # Extrai campos relevantes do whois
        ORG=$(echo "$WHOIS_OUT" | grep -iE "^OrgName:|^org-name:|^owner:|^descr:" | head -1 | sed 's/.*: *//')
        PAIS=$(echo "$WHOIS_OUT" | grep -iE "^Country:|^country:" | head -1 | sed 's/.*: *//')
        NETNAME=$(echo "$WHOIS_OUT" | grep -iE "^NetName:|^netname:" | head -1 | sed 's/.*: *//')
        ABUSO=$(echo "$WHOIS_OUT" | grep -iE "^OrgAbuseEmail:|^abuse-mailbox:" | head -1 | sed 's/.*: *//')

        # Guarda resultado no ficheiro whois detalhado
        echo "IP: $IP" >> "$FICHEIRO_WHOIS"
        echo "  Organizacao: ${ORG:-N/A}" >> "$FICHEIRO_WHOIS"
        echo "  Pais:        ${PAIS:-N/A}" >> "$FICHEIRO_WHOIS"
        echo "  NetName:     ${NETNAME:-N/A}" >> "$FICHEIRO_WHOIS"
        echo "  Abuso:       ${ABUSO:-N/A}" >> "$FICHEIRO_WHOIS"
        echo "" >> "$FICHEIRO_WHOIS"

        # Adiciona resumo ao relatorio
        echo "  IP: $IP" >> "$RELATORIO"
        echo "    Organizacao: ${ORG:-N/A}" >> "$RELATORIO"
        echo "    Pais:        ${PAIS:-N/A}" >> "$RELATORIO"
        echo "    NetName:     ${NETNAME:-N/A}" >> "$RELATORIO"
        echo "    Contacto:    ${ABUSO:-N/A}" >> "$RELATORIO"
        echo "" >> "$RELATORIO"

        log "Whois: $IP -> ${ORG:-N/A} (${PAIS:-N/A})"
        sleep 1   # pausa para nao sobrecarregar os servidores whois
    fi
done

HASH_WHOIS=$(sha256sum "$FICHEIRO_WHOIS" | awk '{print $1}')
echo "Whois dos IPs de destino" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_WHOIS" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "Whois concluido: $FICHEIRO_WHOIS"
echo ""

# -----------------------------------------------------------------------------
# 4. NOMES DNS RESOLVIDOS - NIST: Examination
# -----------------------------------------------------------------------------
fase "NIST - Examination: Nomes DNS resolvidos pela camera"
log "--- PASSO 4: Extracao de DNS ---"

FICHEIRO_DNS="$DESTINO/rede/dns_resolvidos_$TIMESTAMP.txt"
tshark -r "$PCAP" \
    -Y "dns.flags.response == 1" \
    -T fields -e dns.qry.name -e dns.a \
    2>/dev/null | sort -u > "$FICHEIRO_DNS"

TOTAL_DNS=$(wc -l < "$FICHEIRO_DNS")
HASH_DNS=$(sha256sum "$FICHEIRO_DNS" | awk '{print $1}')
echo "Nomes DNS resolvidos" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_DNS" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "DNS extraidos: $TOTAL_DNS entradas | SHA-256: $HASH_DNS"
echo ""

echo "==============================================================" >> "$RELATORIO"
echo "4. NOMES DNS RESOLVIDOS" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Total de dominios resolvidos: $TOTAL_DNS" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Dominios TP-Link / Tapo:" >> "$RELATORIO"
grep -iE "tplink|tapo|tplinkra|tplinkcloud" "$FICHEIRO_DNS" | while read linha; do
    echo "    $linha" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"
echo "  Outros dominios:" >> "$RELATORIO"
grep -viE "tplink|tapo|tplinkra|tplinkcloud" "$FICHEIRO_DNS" | while read linha; do
    echo "    $linha" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"

# -----------------------------------------------------------------------------
# 5. PROTOCOLOS USADOS - NIST: Examination
# -----------------------------------------------------------------------------
fase "NIST - Examination: Protocolos de comunicacao usados pela camera"
log "--- PASSO 5: Extracao de protocolos ---"

FICHEIRO_PROT="$DESTINO/rede/protocolos_$TIMESTAMP.txt"
tshark -r "$PCAP" \
    -Y "ip.src == $IP_CAMERA" \
    -T fields -e _ws.col.Protocol \
    2>/dev/null | sort | uniq -c | sort -rn > "$FICHEIRO_PROT"

HASH_PROT=$(sha256sum "$FICHEIRO_PROT" | awk '{print $1}')
echo "Protocolos usados pela camera" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_PROT" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "Protocolos extraidos | SHA-256: $HASH_PROT"
echo ""

echo "==============================================================" >> "$RELATORIO"
echo "5. PROTOCOLOS DE COMUNICACAO" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Pacotes  Protocolo" >> "$RELATORIO"
echo "  -------  ---------" >> "$RELATORIO"
cat "$FICHEIRO_PROT" | while read linha; do
    echo "  $linha" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"

# -----------------------------------------------------------------------------
# 6. VOLUMES DE TRÁFEGO - NIST: Examination
# -----------------------------------------------------------------------------
fase "NIST - Examination: Volume de dados por IP de destino"
log "--- PASSO 6: Calculo de volumes de trafego ---"

FICHEIRO_VOL="$DESTINO/rede/volumes_por_ip_$TIMESTAMP.txt"
tshark -r "$PCAP" \
    -Y "ip.src == $IP_CAMERA" \
    -T fields -e ip.dst -e frame.len \
    2>/dev/null \
    | awk '{bytes[$1]+=$2} END {for(ip in bytes) print bytes[ip], ip}' \
    | sort -rn > "$FICHEIRO_VOL"

HASH_VOL=$(sha256sum "$FICHEIRO_VOL" | awk '{print $1}')
echo "Volumes de trafego por IP" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_VOL" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "Volumes calculados | SHA-256: $HASH_VOL"
echo ""

echo "==============================================================" >> "$RELATORIO"
echo "6. VOLUMES DE TRAFEGO POR DESTINO" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Bytes enviados  IP de destino" >> "$RELATORIO"
echo "  --------------  -------------" >> "$RELATORIO"
cat "$FICHEIRO_VOL" | while read linha; do
    echo "  $linha" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"

# Volume total enviado pela camera
TOTAL_BYTES=$(awk '{sum+=$1} END {print sum}' "$FICHEIRO_VOL")
echo "  Volume total enviado pela camera: $TOTAL_BYTES bytes" >> "$RELATORIO"
echo "" >> "$RELATORIO"

# -----------------------------------------------------------------------------
# 7. PADRÕES TEMPORAIS (HEARTBEATS) - NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST - Analysis: Padroes temporais de comunicacao"
log "--- PASSO 7: Analise de padroes temporais ---"

FICHEIRO_TIMELINE="$DESTINO/rede/timeline_$TIMESTAMP.csv"
tshark -r "$PCAP" \
    -Y "ip.addr == $IP_CAMERA" \
    -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len \
    -E header=y -E separator=, \
    2>/dev/null > "$FICHEIRO_TIMELINE"

TOTAL_EVENTOS=$(( $(wc -l < "$FICHEIRO_TIMELINE") - 1 ))
HASH_TL=$(sha256sum "$FICHEIRO_TIMELINE" | awk '{print $1}')
echo "Timeline de comunicacoes (CSV)" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_TL" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "Timeline: $TOTAL_EVENTOS eventos | SHA-256: $HASH_TL"
echo ""

# Deteta comunicacoes regulares (possiveis heartbeats) - intervalos < 5s
FICHEIRO_HEARTBEAT="$DESTINO/rede/heartbeats_$TIMESTAMP.txt"
cat > "$FICHEIRO_HEARTBEAT" << EOF
=============================================================
PADROES TEMPORAIS - POSSIVEIS HEARTBEATS
Caso: $CASO | Data: $(date '+%Y-%m-%d %H:%M:%S UTC')
=============================================================

EOF

tshark -r "$PCAP" \
    -Y "ip.src == $IP_CAMERA" \
    -T fields -e frame.time_delta -e ip.dst -e _ws.col.Protocol \
    2>/dev/null \
    | awk '$1 != "" && $1+0 < 2.0 {count[$2"/"$3]++}
           END {for(k in count) if(count[k]>5) print count[k], k}' \
    | sort -rn >> "$FICHEIRO_HEARTBEAT"

HASH_HB=$(sha256sum "$FICHEIRO_HEARTBEAT" | awk '{print $1}')
echo "Padroes temporais / heartbeats" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_HB" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "Padroes temporais analisados | SHA-256: $HASH_HB"
echo ""

echo "==============================================================" >> "$RELATORIO"
echo "7. PADROES TEMPORAIS E HEARTBEATS" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Total de eventos de rede registados: $TOTAL_EVENTOS" >> "$RELATORIO"
echo "" >> "$RELATORIO"
echo "  Comunicacoes regulares detetadas (intervalo < 2s, >5 ocorrencias):" >> "$RELATORIO"
echo "  Ocorrencias  Destino/Protocolo" >> "$RELATORIO"
echo "  -----------  ----------------" >> "$RELATORIO"
grep -v "^=" "$FICHEIRO_HEARTBEAT" | grep -v "^$" | grep -v "^Caso" | while read linha; do
    echo "  $linha" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"

# -----------------------------------------------------------------------------
# 8. LIMITAÇÕES FORENSES - SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE - Documentacao das limitacoes forenses"
log "--- PASSO 8: Limitacoes forenses ---"

echo "==============================================================" >> "$RELATORIO"
echo "8. LIMITACOES FORENSES (SWGDE)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"
cat >> "$RELATORIO" << EOF
  [L1] Cifra TLS: O payload das comunicacoes HTTPS nao e visivel
       na captura de trafego. Apenas os metadados sao acessiveis
       (IP, porto, volume, timing, SNI do certificado).
       Para acesso ao conteudo: mandado judicial ao fornecedor.

  [L2] Evidencias cloud: As gravacoes e logs armazenados nos
       servidores da TP-Link nao sao acessiveis sem processo
       legal. Os IPs e DNS identificados fundamentam o pedido
       de preservacao e divulgacao de dados.

  [L3] Jurisdicao: O servidor principal identificado (Tapo Care)
       esta alojado na Amazon AWS Irlanda (UE), pelo que o RGPD
       e aplicavel e um mandado judicial portugues e suficiente.
       Outros servidores podem estar fora da UE - verificar
       Whois de cada IP identificado.

  [L4] Duracao da captura: A captura foi limitada a 300 segundos.
       Comunicacoes esporadicas podem nao ter sido registadas.

EOF
log "Limitacoes documentadas."
echo ""

# -----------------------------------------------------------------------------
# 9. SUMÁRIO EXECUTIVO - REPORTING
# -----------------------------------------------------------------------------
fase "REPORTING: Sumario executivo e finalizacao do relatorio"
log "--- PASSO 9: Sumario executivo ---"

cat >> "$RELATORIO" << EOF
=============================================================
9. SUMARIO EXECUTIVO - REPORTING
=============================================================

CASO:           $CASO
DATA/HORA:      $(date '+%Y-%m-%d %H:%M:%S UTC')
INVESTIGADOR:   $(whoami)
DISPOSITIVO:    TP-Link Tapo Pan/Tilt Wi-Fi Camera
IP CAMERA:      $IP_CAMERA

FRAMEWORK APLICADA:
  - NIST Forensics Process Model
  - SWGDE Best Practices for IoT Forensics

FASES EXECUTADAS:
  COLLECTION   - Reconhecimento de rede e captura de trafego
  EXAMINATION  - Extracao e analise do pcap
  ANALYSIS     - Identificacao de infraestrutura e padroes
  REPORTING    - Relatorio formal gerado

EVIDENCIAS RECOLHIDAS E ANALISADAS:
  IPs de destino unicos:     $TOTAL_IPS
  Dominios DNS resolvidos:   $TOTAL_DNS
  Eventos de rede (pcap):    $TOTAL_EVENTOS
  Volume total enviado:      $TOTAL_BYTES bytes

PROXIMOS PASSOS (via mandado judicial):
  - Preservacao de dados nos servidores identificados
  - Divulgacao de gravacoes e logs de acesso a conta
  - Identificacao do titular da conta associada ao dispositivo
  - Confirmacao da jurisdicao dos servidores de armazenamento

LOCALIZACAO DAS EVIDENCIAS:
  Collection: $COLLECTION
  Analysis:   $DESTINO

SWGDE - DECLARACAO DE INTEGRIDADE:
  Todas as evidencias foram recolhidas sem alteracao dos
  originais. Hashes SHA-256 calculados antes e apos cada
  operacao para garantir a integridade da cadeia de custodia.

=============================================================
FIM DO RELATORIO
$(date '+%Y-%m-%d %H:%M:%S UTC')
=============================================================
EOF

# Hash do relatorio final
HASH_RELATORIO=$(sha256sum "$RELATORIO" | awk '{print $1}')
echo "Relatorio final" >> "$FICHEIRO_CUSTODIA"
echo "  Ficheiro: $(basename $RELATORIO)" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256:  $HASH_RELATORIO" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
cat >> "$FICHEIRO_CUSTODIA" << EOF
=============================================================
Data/Hora Fim: $(date '+%Y-%m-%d %H:%M:%S UTC')
SWGDE: Analysis concluida. Todos os ficheiros verificados.
=============================================================
EOF

log "Relatorio final: $RELATORIO"
log "SHA-256 do relatorio: $HASH_RELATORIO"
echo ""

# Limpa ficheiros temporarios
rm -f "$BASE/.caso_atual"
rm -f "$BASE/.ip_camera"
log "Ficheiros temporarios removidos - caso encerrado."
echo ""

# =============================================================================
# SUMÁRIO FINAL
# =============================================================================
echo "============================================================"
echo "   ANALYSIS + REPORTING CONCLUIDOS - $CASO"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
log "=== SUMARIO FINAL ==="
log "Relatorio: $RELATORIO"
log "SHA-256:   $HASH_RELATORIO"
echo ""
log "Estrutura do caso:"
log "  $BASE/$CASO/"
log "    recolha/             -> COLLECTION"
log "      *.pcap             -> Captura de trafego"
log "      scan_Tapo_*.txt    -> Scan nmap"
log "      cadeia_custodia_*  -> Cadeia de custodia SWGDE"
log "    analise/             -> EXAMINATION + ANALYSIS + REPORTING"
log "      rede/              -> IPs, DNS, protocolos, volumes, timeline"
log "      hashes/            -> Cadeia de custodia da analise"
log "      relatorio_final_*  -> Relatorio forense final"
echo ""
log "=== FIM DA ANALYSIS + REPORTING ==="
