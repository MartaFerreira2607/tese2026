#!/bin/bash
# =============================================================================
# FASE 2: COLLECTION - CAPTURA DE REDE
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: TP-Link Tapo TC71 + Agent DVR
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/e/Mestrado/Tese/Fase2"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CASO="CASO_$TIMESTAMP"
DESTINO="$BASE/$CASO/recolha"
IP_CAMERA="192.168.1.109"
REDE="192.168.1.0/24"
DURACAO_CAPTURA=300
INTERFACE="eth0"

# Criar pasta ANTES de qualquer log
mkdir -p "$DESTINO"
LOG="$DESTINO/log_collection_$TIMESTAMP.txt"

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

# =============================================================================
# INÍCIO
# =============================================================================
clear
echo "============================================================"
echo "   FASE: COLLECTION"
echo "   Framework NIST + SWGDE | Tapo TC71 + Agent DVR"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

fase "Fase COLLECTION iniciada — NIST: Identificação e recolha de dados de rede"
fase "SWGDE: Documentação do ambiente antes de qualquer intervenção"
echo ""

log "=== INÍCIO DA COLLECTION ==="
log "Caso:                    $CASO"
log "Dispositivo sob análise: TP-Link Tapo TC71"
log "IP da câmara:            $IP_CAMERA"
log "Rede:                    $REDE"
log "Destino:                 $DESTINO"
log "Investigador:            $(whoami)"
echo ""

# -----------------------------------------------------------------------------
# 1. ESTADO INICIAL DO AMBIENTE — NIST: Identificação
# -----------------------------------------------------------------------------
fase "NIST — Identificação: Documentar estado inicial do ambiente"
log "--- PASSO 1: Documentação do estado inicial ---"

FICHEIRO_ESTADO="$DESTINO/estado_inicial_$TIMESTAMP.txt"
cat > "$FICHEIRO_ESTADO" << EOF
=============================================================
ESTADO INICIAL DO AMBIENTE — COLLECTION
Framework NIST + SWGDE
Caso: $CASO
Data/Hora: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
=============================================================

SISTEMA DO INVESTIGADOR (WSL):
$(uname -a)

INTERFACES DE REDE ANTES DA CAPTURA:
$(ip addr)

TABELA DE ROUTING:
$(ip route)

HORA DO SISTEMA (LOCAL):    $(date)
HORA DO SISTEMA (UTC):      $(date -u)

DISPOSITIVO SOB ANÁLISE:
  Modelo:     TP-Link Tapo TC71
  IP:         $IP_CAMERA
  Rede:       $REDE
  Interface:  $INTERFACE

FERRAMENTAS UTILIZADAS:
  Nmap:    $(nmap --version | head -1)
  tshark:  $(tshark --version | head -1)
=============================================================
EOF

HASH_ESTADO=$(sha256sum "$FICHEIRO_ESTADO" | awk '{print $1}')
log "Estado inicial documentado: $FICHEIRO_ESTADO"
log "SHA-256: $HASH_ESTADO"
echo ""

# -----------------------------------------------------------------------------
# 2. DESCOBERTA DE HOSTS — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Descoberta de todos os dispositivos na rede"
log "--- PASSO 2: Descoberta de dispositivos na rede ($REDE) ---"

FICHEIRO_HOSTS="$DESTINO/hosts_rede_$TIMESTAMP.txt"
sudo nmap -sn "$REDE" -oN "$FICHEIRO_HOSTS" 2>> "$LOG"
HASH_HOSTS=$(sha256sum "$FICHEIRO_HOSTS" | awk '{print $1}')
log "Hosts descobertos guardados: $FICHEIRO_HOSTS"
log "SHA-256: $HASH_HOSTS"
echo ""

# -----------------------------------------------------------------------------
# 3. SCAN DETALHADO À CÂMARA — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Identificação de serviços e portas do dispositivo"
log "--- PASSO 3: Scan detalhado à câmara Tapo TC71 ($IP_CAMERA) ---"

FICHEIRO_SCAN="$DESTINO/scan_TC71_$TIMESTAMP.txt"
sudo nmap -sV -sC -O "$IP_CAMERA" -oN "$FICHEIRO_SCAN" 2>> "$LOG"
HASH_SCAN=$(sha256sum "$FICHEIRO_SCAN" | awk '{print $1}')
log "Scan detalhado guardado: $FICHEIRO_SCAN"
log "SHA-256: $HASH_SCAN"
echo ""

# -----------------------------------------------------------------------------
# 4. SCAN COMPLETO DE PORTAS — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Mapeamento completo de superfície de ataque"
log "--- PASSO 4: Scan completo de portas ($IP_CAMERA) ---"

FICHEIRO_PORTAS="$DESTINO/portas_TC71_$TIMESTAMP.txt"
sudo nmap -p- "$IP_CAMERA" -oN "$FICHEIRO_PORTAS" 2>> "$LOG"
HASH_PORTAS=$(sha256sum "$FICHEIRO_PORTAS" | awk '{print $1}')
log "Scan de portas guardado: $FICHEIRO_PORTAS"
log "SHA-256: $HASH_PORTAS"
echo ""

# -----------------------------------------------------------------------------
# 5. CAPTURA DE TRÁFEGO — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Captura de tráfego de rede gerado pelo dispositivo"
log "--- PASSO 5: Captura de tráfego ($DURACAO_CAPTURA segundos) ---"

FICHEIRO_PCAP="$DESTINO/captura_rede_TC71_$TIMESTAMP.pcap"
aviso "A capturar tráfego durante $DURACAO_CAPTURA segundos... Não interrompas o processo."
sudo tshark -i "$INTERFACE" -a duration:"$DURACAO_CAPTURA" -w "$FICHEIRO_PCAP" 2>> "$LOG"
HASH_PCAP=$(sha256sum "$FICHEIRO_PCAP" | awk '{print $1}')
log "Captura de tráfego guardada: $FICHEIRO_PCAP"
log "SHA-256: $HASH_PCAP"
echo ""

# -----------------------------------------------------------------------------
# 6. CADEIA DE CUSTÓDIA — SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE — Cadeia de custódia: Registo de todos os hashes SHA-256"
log "--- PASSO 6: Registo de cadeia de custódia ---"

FICHEIRO_CUSTODIA="$DESTINO/cadeia_custodia_collection_$TIMESTAMP.txt"
cat > "$FICHEIRO_CUSTODIA" << EOF
=============================================================
CADEIA DE CUSTÓDIA — COLLECTION
Framework NIST + SWGDE
Caso: $CASO
Data/Hora Início: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
=============================================================

FICHEIROS RECOLHIDOS E VERIFICADOS:

[1] Estado inicial do ambiente
    Ficheiro: $(basename $FICHEIRO_ESTADO)
    SHA-256:  $HASH_ESTADO

[2] Hosts descobertos na rede
    Ficheiro: $(basename $FICHEIRO_HOSTS)
    SHA-256:  $HASH_HOSTS

[3] Scan detalhado ao dispositivo
    Ficheiro: $(basename $FICHEIRO_SCAN)
    SHA-256:  $HASH_SCAN

[4] Scan completo de portas
    Ficheiro: $(basename $FICHEIRO_PORTAS)
    SHA-256:  $HASH_PORTAS

[5] Captura de tráfego de rede
    Ficheiro: $(basename $FICHEIRO_PCAP)
    SHA-256:  $HASH_PCAP

=============================================================
SWGDE: Todos os ficheiros foram recolhidos sem alteração
das evidências originais. Hashes calculados imediatamente
após recolha para garantir integridade.
=============================================================
EOF

log "Cadeia de custódia registada: $FICHEIRO_CUSTODIA"
echo ""

# --- GUARDA O NOME DO CASO PARA OS SCRIPTS SEGUINTES ---
echo "$CASO" > "$BASE/.caso_atual"
log "Caso guardado para scripts de Examination e Analysis: $CASO"
echo ""

# =============================================================================
# SUMÁRIO
# =============================================================================
echo "============================================================"
echo "   COLLECTION CONCLUÍDA — $CASO"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
log "=== SUMÁRIO DA COLLECTION ==="
log "Ficheiros gerados em: $DESTINO"
log "  estado_inicial_*.txt         → Estado do ambiente"
log "  hosts_rede_*.txt             → Dispositivos na rede"
log "  scan_TC71_*.txt              → Scan detalhado câmara"
log "  portas_TC71_*.txt            → Scan completo de portas"
log "  captura_rede_TC71_*.pcap     → Tráfego de rede"
log "  cadeia_custodia_*.txt        → Cadeia de custódia SWGDE"
echo ""
log "Próximo passo: correr extracao_evidencias.sh (Extracao)"
log "=== FIM DA COLLECTION ==="
