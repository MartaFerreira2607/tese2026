#!/bin/bash
# =============================================================================
# FASE 1 — COLLECTION: CAPTURA DE REDE E ARTEFACTOS DO DISPOSITIVO
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: Raspberry Pi 4 + NoIR Camera Module v2
# Executar no WSL do PC forense
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/i/Mestrado/Tese/Fase1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CASO="CASO_$TIMESTAMP"
DESTINO="$BASE/$CASO/recolha"

PI_USER="marta"
PI_HOST="192.168.1.123"
PI_KEY="$HOME/.ssh/id_rsa"
REDE="192.168.1.0/24"
INTERFACE_REDE="wlan0"           # interface de rede do Raspberry Pi
TEMPO_CAPTURA_REDE=300           # segundos de captura de tráfego
TIMEOUT_SSH=5

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

# --- FUNÇÕES SSH ---
ssh_opts() {
    local opts="-o ConnectTimeout=$TIMEOUT_SSH -o StrictHostKeyChecking=no"
    if [ -n "$PI_KEY" ] && [ -f "$PI_KEY" ]; then
        opts="$opts -i $PI_KEY -o BatchMode=yes"
    fi
    echo "$opts"
}

pi_ssh() { ssh $(ssh_opts) "$PI_USER@$PI_HOST" "$@"; }
pi_scp() { scp $(ssh_opts) "$1" "$2"; }

verificar_ssh() {
    ssh -o ConnectTimeout="$TIMEOUT_SSH" -o StrictHostKeyChecking=no \
        ${PI_KEY:+-i "$PI_KEY" -o BatchMode=yes} \
        -q "$PI_USER@$PI_HOST" exit
    return $?
}

# =============================================================================
# INÍCIO
# =============================================================================
clear
echo "============================================================"
echo "   FASE 1 — COLLECTION"
echo "   Framework NIST + SWGDE | Raspberry Pi 4 + NoIR Camera"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

fase "Fase COLLECTION iniciada — NIST: Identificação e recolha de dados"
fase "SWGDE: Documentação do ambiente antes de qualquer intervenção"
echo ""

log "=== INÍCIO DA COLLECTION ==="
log "Caso:          $CASO"
log "Dispositivo:   $PI_USER@$PI_HOST (Raspberry Pi 4 + NoIR Camera)"
log "Rede:          $REDE"
log "Destino:       $DESTINO"
log "Investigador:  $(whoami)"
echo ""

# -----------------------------------------------------------------------------
# 1. ESTADO INICIAL DO AMBIENTE — NIST: Identificação
# -----------------------------------------------------------------------------
fase "NIST — Identificação: Documentar estado inicial do ambiente"
log "--- PASSO 1: Estado inicial do ambiente ---"

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

INTERFACES DE REDE (WSL):
$(ip addr)

TABELA DE ROUTING:
$(ip route)

HORA DO SISTEMA (LOCAL): $(date)
HORA DO SISTEMA (UTC):   $(date -u)

DISPOSITIVO SOB ANÁLISE:
  Modelo:     Raspberry Pi 4 + NoIR Camera Module v2
  IP:         $PI_HOST
  Utilizador: $PI_USER
  Interface:  $INTERFACE_REDE

FERRAMENTAS UTILIZADAS:
  SSH/SCP: $(ssh -V 2>&1 | head -1)
  Nmap:    $(nmap --version 2>/dev/null | head -1 || echo "não instalado")
  tshark:  $(tshark --version 2>/dev/null | head -1 || echo "não instalado")
=============================================================
EOF

HASH_ESTADO=$(sha256sum "$FICHEIRO_ESTADO" | awk '{print $1}')
log "Estado inicial documentado: $FICHEIRO_ESTADO"
log "SHA-256: $HASH_ESTADO"
echo ""

# -----------------------------------------------------------------------------
# 2. VERIFICAÇÃO SSH — SWGDE: Árvore de decisão
# -----------------------------------------------------------------------------
fase "SWGDE — Árvore de decisão: Avaliar estado do dispositivo"
log "--- PASSO 2: Verificação de conectividade SSH ---"

if ! verificar_ssh; then
    erro "Sem ligação SSH ao dispositivo ($PI_HOST)."
    aviso "SWGDE — Árvore de decisão:"
    aviso "  Dispositivo LIGADO sem rede → remover SD; aquisição física com dd"
    aviso "  Dispositivo DESLIGADO       → não ligar; aquisição física com dd"
    aviso "Extracção remota inviável. A encerrar."
    exit 1
fi
log "SSH confirmado. Dispositivo ligado e acessível via rede. ✓"
echo ""

# -----------------------------------------------------------------------------
# 3. DESCOBERTA DE HOSTS — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Descoberta de dispositivos na rede"
log "--- PASSO 3: Scan de hosts na rede ($REDE) ---"

FICHEIRO_HOSTS="$DESTINO/hosts_rede_$TIMESTAMP.txt"
sudo nmap -sn "$REDE" -oN "$FICHEIRO_HOSTS" 2>> "$LOG"
HASH_HOSTS=$(sha256sum "$FICHEIRO_HOSTS" | awk '{print $1}')
log "Hosts descobertos: $FICHEIRO_HOSTS"
log "SHA-256: $HASH_HOSTS"
echo ""

# -----------------------------------------------------------------------------
# 4. SCAN DETALHADO AO RASPBERRY PI — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Identificação de serviços e portas do dispositivo"
log "--- PASSO 4: Scan detalhado ao Raspberry Pi ($PI_HOST) ---"

FICHEIRO_SCAN="$DESTINO/scan_RaspberryPi_$TIMESTAMP.txt"
sudo nmap -sV -sC -O "$PI_HOST" -oN "$FICHEIRO_SCAN" 2>> "$LOG"
HASH_SCAN=$(sha256sum "$FICHEIRO_SCAN" | awk '{print $1}')
log "Scan detalhado: $FICHEIRO_SCAN"
log "SHA-256: $HASH_SCAN"
echo ""

# -----------------------------------------------------------------------------
# 5. SCAN COMPLETO DE PORTAS — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Mapeamento completo de superfície de ataque"
log "--- PASSO 5: Scan completo de portas ($PI_HOST) ---"

FICHEIRO_PORTAS="$DESTINO/portas_RaspberryPi_$TIMESTAMP.txt"
sudo nmap -p- "$PI_HOST" -oN "$FICHEIRO_PORTAS" 2>> "$LOG"
HASH_PORTAS=$(sha256sum "$FICHEIRO_PORTAS" | awk '{print $1}')
log "Scan de portas: $FICHEIRO_PORTAS"
log "SHA-256: $HASH_PORTAS"
echo ""

# -----------------------------------------------------------------------------
# 6. ARTEFACTOS VOLÁTEIS — NIST: Collection (prioridade máxima)
# -----------------------------------------------------------------------------
fase "NIST — Collection: Recolha de artefactos voláteis (prioridade máxima)"
log "--- PASSO 6: Artefactos voláteis ---"

mkdir -p "$DESTINO/sistema"

pi_ssh "ps aux" > "$DESTINO/sistema/processos_ativos_$TIMESTAMP.txt"
pi_ssh "ss -tulpn" > "$DESTINO/sistema/conexoes_rede_$TIMESTAMP.txt"
pi_ssh "who -a && last -n 50" > "$DESTINO/sistema/ultimos_logins_$TIMESTAMP.txt"
pi_ssh "netstat -rn 2>/dev/null || ip route show" > "$DESTINO/sistema/tabela_routing_$TIMESTAMP.txt"

for f in processos_ativos conexoes_rede ultimos_logins tabela_routing; do
    FICHEIRO="$DESTINO/sistema/${f}_$TIMESTAMP.txt"
    if [ -f "$FICHEIRO" ]; then
        HASH=$(sha256sum "$FICHEIRO" | awk '{print $1}')
        log "  $f → SHA-256: $HASH"
    fi
done
echo ""

# -----------------------------------------------------------------------------
# 7. ARTEFACTOS NÃO-VOLÁTEIS — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Recolha de artefactos não-voláteis"
log "--- PASSO 7: Artefactos não-voláteis ---"

pi_ssh "cat /etc/os-release" > "$DESTINO/sistema/os_release_$TIMESTAMP.txt"
pi_ssh "uname -a && cat /proc/cpuinfo | grep -E 'Model|Hardware|Revision'" \
    > "$DESTINO/sistema/hardware_$TIMESTAMP.txt"
pi_ssh "cat /etc/passwd" > "$DESTINO/sistema/utilizadores_$TIMESTAMP.txt"
pi_ssh "ip addr show && ip route show" > "$DESTINO/sistema/configuracao_rede_$TIMESTAMP.txt"
pi_ssh "crontab -l 2>/dev/null || echo 'Sem crontab'" > "$DESTINO/sistema/crontab_$TIMESTAMP.txt"
pi_ssh "sudo crontab -l 2>/dev/null || echo 'Sem crontab root'" >> "$DESTINO/sistema/crontab_$TIMESTAMP.txt"
pi_ssh "rpicam-hello --list-cameras 2>&1 || vcgencmd get_camera 2>/dev/null || echo 'Câmara não detectada'" \
    > "$DESTINO/sistema/camera_info_$TIMESTAMP.txt"
pi_ssh "cat /etc/hostname && cat /etc/hosts" > "$DESTINO/sistema/hostname_$TIMESTAMP.txt"
pi_ssh "sudo timedatectl status 2>/dev/null || date" > "$DESTINO/sistema/timezone_$TIMESTAMP.txt"

for f in os_release hardware utilizadores configuracao_rede crontab camera_info hostname timezone; do
    FICHEIRO="$DESTINO/sistema/${f}_$TIMESTAMP.txt"
    if [ -f "$FICHEIRO" ]; then
        HASH=$(sha256sum "$FICHEIRO" | awk '{print $1}')
        log "  $f → SHA-256: $HASH"
    fi
done
echo ""

# -----------------------------------------------------------------------------
# 8. LOGS DO SISTEMA — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Recolha de logs do sistema"
log "--- PASSO 8: Logs do sistema ---"

mkdir -p "$DESTINO/logs"

pi_ssh "sudo journalctl -b 0 --no-pager 2>/dev/null || sudo cat /var/log/syslog" \
    > "$DESTINO/logs/syslog_$TIMESTAMP.txt"
pi_ssh "sudo journalctl -t sshd -t sudo -t systemd-logind --no-pager 2>/dev/null \
    || sudo cat /var/log/auth.log" \
    > "$DESTINO/logs/auth_log_$TIMESTAMP.txt"
pi_ssh "dmesg" > "$DESTINO/logs/dmesg_$TIMESTAMP.txt"

for f in syslog auth_log dmesg; do
    FICHEIRO="$DESTINO/logs/${f}_$TIMESTAMP.txt"
    if [ -f "$FICHEIRO" ]; then
        HASH=$(sha256sum "$FICHEIRO" | awk '{print $1}')
        log "  $f → SHA-256: $HASH"
    fi
done
echo ""

# -----------------------------------------------------------------------------
# 9. CAPTURA DE TRÁFEGO — NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST — Collection: Captura de tráfego de rede no dispositivo"
log "--- PASSO 9: Captura de tráfego ($TEMPO_CAPTURA_REDE segundos) ---"
aviso "A capturar tráfego durante $TEMPO_CAPTURA_REDE segundos no Raspberry Pi..."

mkdir -p "$DESTINO/rede"

pi_ssh "sudo timeout $TEMPO_CAPTURA_REDE tcpdump -i $INTERFACE_REDE \
    -w /tmp/captura_rede_$TIMESTAMP.pcap 2>/dev/null; exit 0"

pi_scp "$PI_USER@$PI_HOST:/tmp/captura_rede_$TIMESTAMP.pcap" \
    "$DESTINO/rede/captura_rede_$TIMESTAMP.pcap"

if [ $? -eq 0 ] && [ -f "$DESTINO/rede/captura_rede_$TIMESTAMP.pcap" ]; then
    pi_ssh "sudo rm -f /tmp/captura_rede_$TIMESTAMP.pcap"
    HASH_PCAP=$(sha256sum "$DESTINO/rede/captura_rede_$TIMESTAMP.pcap" | awk '{print $1}')
    TAMANHO_PCAP=$(du -h "$DESTINO/rede/captura_rede_$TIMESTAMP.pcap" | awk '{print $1}')
    TOTAL_PACOTES=$(tshark -r "$DESTINO/rede/captura_rede_$TIMESTAMP.pcap" 2>/dev/null | wc -l)
    log "Captura de rede: $TAMANHO_PCAP | $TOTAL_PACOTES pacotes | SHA-256: $HASH_PCAP"
else
    aviso "Captura de rede falhou ou ficheiro não encontrado."
    HASH_PCAP="N/A"
    TAMANHO_PCAP="N/A"
    TOTAL_PACOTES="0"
fi
echo ""

# -----------------------------------------------------------------------------
# 10. CADEIA DE CUSTÓDIA — SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE — Cadeia de custódia: Registo de todos os hashes SHA-256"
log "--- PASSO 10: Registo de cadeia de custódia ---"

FICHEIRO_CUSTODIA="$DESTINO/cadeia_custodia_collection_$TIMESTAMP.txt"
cat > "$FICHEIRO_CUSTODIA" << EOF
=============================================================
CADEIA DE CUSTÓDIA — COLLECTION
Framework NIST Forensics Process Model + SWGDE Best Practices
Caso: $CASO
Data/Hora Início: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
Dispositivo: Raspberry Pi 4 + NoIR Camera Module v2
IP do dispositivo: $PI_HOST
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

[5] Artefactos voláteis (processos, conexões, logins, routing)
    Localização: $DESTINO/sistema/
    SHA-256: (individual por ficheiro — ver pasta sistema/)

[6] Artefactos não-voláteis (SO, hardware, cron, câmara)
    Localização: $DESTINO/sistema/
    SHA-256: (individual por ficheiro — ver pasta sistema/)

[7] Logs do sistema (syslog, auth, dmesg)
    Localização: $DESTINO/logs/
    SHA-256: (individual por ficheiro — ver pasta logs/)

[8] Captura de tráfego de rede (pcap)
    Ficheiro: captura_rede_$TIMESTAMP.pcap
    Tamanho:  $TAMANHO_PCAP
    Pacotes:  $TOTAL_PACOTES
    SHA-256:  $HASH_PCAP

=============================================================
SWGDE: Todos os ficheiros foram recolhidos sem alteração
das evidências originais. Hashes SHA-256 calculados
imediatamente após recolha para garantir integridade.
=============================================================
Data/Hora Fim: $(date '+%Y-%m-%d %H:%M:%S UTC')
=============================================================
EOF

log "Cadeia de custódia: $FICHEIRO_CUSTODIA"
echo ""

# Guardar caso e IP para os scripts seguintes
echo "$CASO" > "$BASE/.caso_atual"
echo "$PI_HOST" > "$BASE/.ip_dispositivo"
log "Caso guardado para scripts seguintes: $CASO"
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
log "Ficheiros em: $DESTINO"
log "  estado_inicial_*.txt          → Estado do ambiente"
log "  hosts_rede_*.txt              → Dispositivos na rede"
log "  scan_RaspberryPi_*.txt        → Scan detalhado"
log "  portas_RaspberryPi_*.txt      → Scan completo de portas"
log "  sistema/                      → Artefactos voláteis e não-voláteis"
log "  logs/                         → Logs do sistema"
log "  rede/captura_rede_*.pcap      → Tráfego de rede"
log "  cadeia_custodia_*.txt         → Cadeia de custódia SWGDE"
echo ""
log "Próximo passo: correr extrair_evidencias_fase1.sh (Examination)"
log "=== FIM DA COLLECTION ==="
