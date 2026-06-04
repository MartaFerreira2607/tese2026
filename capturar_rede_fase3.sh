#!/bin/bash
# =============================================================================
# FASE 3: COLLECTION - CAPTURA DE REDE
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: TP-Link Tapo Pan/Tilt Wi-Fi Camera (cloud-connected)
# NOTA: Captura feita via Wireshark no Windows (interface Wi-Fi)
#       O WSL não tem acesso direto à interface Wi-Fi física do Windows
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/i/Mestrado/Tese/Fase3"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CASO="CASO_$TIMESTAMP"
DESTINO="$BASE/$CASO/recolha"
REDE="192.168.137.0/24"
INTERFACE="eth0"
IP_CAMERA=""  # preenchido pelo utilizador

# --- SOLICITA IP DA CÂMARA ---
echo ""
echo "============================================================"
echo "   FASE 3: COLLECTION — TP-Link Tapo Pan/Tilt"
echo "============================================================"
echo ""
echo "Qual o IP atual da camera Tapo no hotspot ForenseLab?"
echo "(Confirma na app Tapo: Definicoes -> Informacoes do dispositivo)"
echo ""
read -p "    IP da camera (ex: 192.168.137.X): " IP_CAMERA </dev/tty
echo ""

# Criar pasta ANTES de qualquer log
mkdir -p "$DESTINO"
LOG="$DESTINO/log_collection_$TIMESTAMP.txt"

# --- CORES ---
VERDE='\033[0;32m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
AZUL='\033[0;34m'
CIANO='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${VERDE}[$(date '+%Y-%m-%d %H:%M:%S UTC')]${NC} $1" | tee -a "$LOG"; }
aviso() { echo -e "${AMARELO}[AVISO]${NC} $1" | tee -a "$LOG"; }
erro()  { echo -e "${VERMELHO}[ERRO]${NC} $1" | tee -a "$LOG"; }
fase()  { echo -e "${AZUL}[FRAMEWORK]${NC} $1" | tee -a "$LOG"; }
passo() { echo -e "${CIANO}[WIRESHARK]${NC} $1" | tee -a "$LOG"; }

# =============================================================================
# INÍCIO
# =============================================================================
clear
echo "============================================================"
echo "   FASE 3: COLLECTION"
echo "   Framework NIST + SWGDE | Tapo Pan/Tilt (cloud-connected)"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

fase "Fase COLLECTION iniciada - NIST: Identificacao e recolha de dados de rede"
fase "SWGDE: Documentacao do ambiente antes de qualquer intervencao"
echo ""

log "=== INICIO DA COLLECTION ==="
log "Caso:           $CASO"
log "Dispositivo:    TP-Link Tapo Pan/Tilt Wi-Fi Camera"
log "IP Camera:      $IP_CAMERA"
log "Rede:           $REDE"
log "Destino:        $DESTINO"
log "Investigador:   $(whoami)"
echo ""

# -----------------------------------------------------------------------------
# 1. ESTADO INICIAL DO AMBIENTE - NIST: Identificação
# -----------------------------------------------------------------------------
fase "NIST - Identificacao: Documentar estado inicial do ambiente"
log "--- PASSO 1: Documentacao do estado inicial ---"

FICHEIRO_ESTADO="$DESTINO/estado_inicial_$TIMESTAMP.txt"
cat > "$FICHEIRO_ESTADO" << EOF
=============================================================
ESTADO INICIAL DO AMBIENTE - COLLECTION
Framework NIST + SWGDE
Caso: $CASO
Data/Hora: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
=============================================================

SISTEMA DO INVESTIGADOR (WSL):
$(uname -a)

INTERFACES DE REDE (WSL):
$(ip addr)

TABELA DE ROUTING (WSL):
$(ip route)

HORA DO SISTEMA (LOCAL): $(date)
HORA DO SISTEMA (UTC):   $(date -u)

TOPOLOGIA DO CENARIO:
  Camera Tapo Pan/Tilt (192.168.1.144)
      -> Wi-Fi -> router domestico (192.168.1.1)
  Portatil de investigacao (192.168.1.191)
      -> Wi-Fi -> router domestico (192.168.1.1)
  Captura: Wireshark no Windows, interface Wi-Fi
  Analise: tshark no WSL sobre pcap gerado pelo Wireshark

NOTA FORENSE:
  O WSL (Windows Subsystem for Linux) nao tem acesso direto
  a interface Wi-Fi fisica do Windows. A captura de trafego
  e feita pelo Wireshark nativo no Windows que tem acesso
  completo a interface Wi-Fi e ao trafego da camara.

FERRAMENTAS UTILIZADAS:
  Wireshark: (Windows - captura)
  tshark:    $(tshark --version | head -1) (WSL - analise)
  Nmap:      $(nmap --version | head -1)
=============================================================
EOF

HASH_ESTADO=$(sha256sum "$FICHEIRO_ESTADO" | awk '{print $1}')
log "Estado inicial documentado: $FICHEIRO_ESTADO"
log "SHA-256: $HASH_ESTADO"
echo ""

# -----------------------------------------------------------------------------
# 2. SCAN DETALHADO À CÂMARA - NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST - Collection: Identificacao de servicos e portas do dispositivo"
log "--- PASSO 2: Scan detalhado a camera Tapo ($IP_CAMERA) ---"

FICHEIRO_SCAN="$DESTINO/scan_Tapo_$TIMESTAMP.txt"
sudo nmap -sV -sC -O "$IP_CAMERA" -oN "$FICHEIRO_SCAN" 2>> "$LOG"
HASH_SCAN=$(sha256sum "$FICHEIRO_SCAN" | awk '{print $1}')
log "Scan detalhado: $FICHEIRO_SCAN"
log "SHA-256: $HASH_SCAN"
echo ""

# -----------------------------------------------------------------------------
# 3. SCAN COMPLETO DE PORTAS - NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST - Collection: Mapeamento completo de superficie de ataque"
log "--- PASSO 3: Scan completo de portas ($IP_CAMERA) ---"

FICHEIRO_PORTAS="$DESTINO/portas_Tapo_$TIMESTAMP.txt"
sudo nmap -p- "$IP_CAMERA" -oN "$FICHEIRO_PORTAS" 2>> "$LOG"
HASH_PORTAS=$(sha256sum "$FICHEIRO_PORTAS" | awk '{print $1}')
log "Scan de portas: $FICHEIRO_PORTAS"
log "SHA-256: $HASH_PORTAS"
echo ""

# -----------------------------------------------------------------------------
# 4. CAPTURA DE TRÁFEGO - WIRESHARK NO WINDOWS
# -----------------------------------------------------------------------------
fase "NIST - Collection: Captura de trafego via Wireshark no Windows"
log "--- PASSO 4: Instrucoes de captura no Wireshark ---"
echo ""
echo "============================================================"
passo "ABRE O WIRESHARK NO WINDOWS E SEGUE ESTES PASSOS:"
echo "============================================================"
echo ""
passo "1. Abre o Wireshark"
passo "2. Na lista de interfaces, seleciona: Ligacao de Area Local* 2"
passo "3. No campo 'Capture Filter' (barra superior) digita:"
echo ""
echo "          host $IP_CAMERA"
echo ""
passo "4. Clica no botao azul 'Start' (ou prime Enter)"
passo "5. Deixa capturar durante 5 minutos"
passo "6. Durante a captura, provoca eventos na camera:"
passo "   - Passa a mao a frente da camera (detetar movimento)"
passo "   - Abre a app Tapo no telemovel"
passo "   - Move a camera PTZ pela app"
passo "7. Apos 5 minutos, prime Ctrl+E para parar a captura"
passo "8. Guarda o ficheiro: File -> Save As"
passo "   Nome: captura_rede_Tapo_$TIMESTAMP.pcapng"
passo "   Pasta: I:\\Mestrado\\Tese\\Fase3\\$CASO\\recolha\\"
echo ""
echo "============================================================"
echo ""

read -p "    Prima ENTER depois de teres guardado o ficheiro pcapng..." </dev/tty
echo ""

# Verifica se o ficheiro foi guardado
PCAP_NG="$DESTINO/captura_rede_Tapo_$TIMESTAMP.pcapng"
PCAP_OLD="$DESTINO/captura_rede_Tapo_$TIMESTAMP.pcap"

# Aceita tanto .pcapng como .pcap
if [ -f "$PCAP_NG" ]; then
    FICHEIRO_PCAP="$PCAP_NG"
elif [ -f "$PCAP_OLD" ]; then
    FICHEIRO_PCAP="$PCAP_OLD"
else
    # Procura qualquer pcap na pasta
    FICHEIRO_PCAP=$(ls "$DESTINO/"*.pcap* 2>/dev/null | head -1)
fi

if [ -z "$FICHEIRO_PCAP" ] || [ ! -f "$FICHEIRO_PCAP" ]; then
    erro "Ficheiro pcap nao encontrado em $DESTINO"
    erro "Verifica se guardaste o ficheiro na pasta correta:"
    erro "  I:\\Mestrado\\Tese\\Fase3\\$CASO\\recolha\\"
    exit 1
fi

TAMANHO_PCAP=$(du -h "$FICHEIRO_PCAP" | awk '{print $1}')
TOTAL_PACOTES=$(tshark -r "$FICHEIRO_PCAP" 2>/dev/null | wc -l)
HASH_PCAP=$(sha256sum "$FICHEIRO_PCAP" | awk '{print $1}')
log "Pcap encontrado: $(basename $FICHEIRO_PCAP) ($TAMANHO_PCAP)"
log "Total de pacotes capturados: $TOTAL_PACOTES"
log "SHA-256: $HASH_PCAP"
echo ""

if [ "$TOTAL_PACOTES" -eq 0 ]; then
    aviso "O ficheiro pcap parece estar vazio (0 pacotes)."
    aviso "Verifica se o filtro 'host $IP_CAMERA' estava correto no Wireshark."
    aviso "e se a camera estava a comunicar durante a captura."
fi

# -----------------------------------------------------------------------------
# 5. EXTRAÇÃO RÁPIDA DE DNS E IPs - NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST - Collection: Extracao sumaria de DNS e IPs do pcap"
log "--- PASSO 5: Extracao rapida de DNS e IPs ---"

FICHEIRO_DNS="$DESTINO/dns_resolvidos_$TIMESTAMP.txt"
tshark -r "$FICHEIRO_PCAP" \
    -Y "dns.flags.response == 1" \
    -T fields -e dns.qry.name -e dns.a \
    2>/dev/null | sort -u > "$FICHEIRO_DNS"

FICHEIRO_IPS="$DESTINO/ips_destino_$TIMESTAMP.txt"
tshark -r "$FICHEIRO_PCAP" \
    -Y "ip.src == $IP_CAMERA" \
    -T fields -e ip.dst \
    2>/dev/null | sort | uniq -c | sort -rn > "$FICHEIRO_IPS"

TOTAL_DNS=$(wc -l < "$FICHEIRO_DNS")
TOTAL_IPS=$(wc -l < "$FICHEIRO_IPS")
HASH_DNS=$(sha256sum "$FICHEIRO_DNS" | awk '{print $1}')
HASH_IPS=$(sha256sum "$FICHEIRO_IPS" | awk '{print $1}')

log "DNS resolvidos: $TOTAL_DNS entradas | SHA-256: $HASH_DNS"
log "IPs de destino: $TOTAL_IPS unicos | SHA-256: $HASH_IPS"
echo ""

# -----------------------------------------------------------------------------
# 6. DESCOBERTA DE HOSTS - NIST: Collection
# -----------------------------------------------------------------------------
fase "NIST - Collection: Descoberta de dispositivos no hotspot ForenseLab"
log "--- PASSO 6: Scan de hosts na rede ---"

FICHEIRO_HOSTS="$DESTINO/hosts_rede_$TIMESTAMP.txt"
sudo nmap -sn "$REDE" -oN "$FICHEIRO_HOSTS" 2>> "$LOG"
HASH_HOSTS=$(sha256sum "$FICHEIRO_HOSTS" | awk '{print $1}')
log "Hosts descobertos: $FICHEIRO_HOSTS"
log "SHA-256: $HASH_HOSTS"
echo ""

# -----------------------------------------------------------------------------
# 7. CADEIA DE CUSTÓDIA - SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE - Cadeia de custodia: Registo de todos os hashes SHA-256"
log "--- PASSO 7: Registo de cadeia de custodia ---"

FICHEIRO_CUSTODIA="$DESTINO/cadeia_custodia_collection_$TIMESTAMP.txt"
cat > "$FICHEIRO_CUSTODIA" << EOF
=============================================================
CADEIA DE CUSTODIA - COLLECTION
Framework NIST + SWGDE
Caso: $CASO
Data/Hora Inicio: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
Dispositivo: TP-Link Tapo Pan/Tilt Wi-Fi Camera
IP da camera: $IP_CAMERA
Rede: $REDE (hotspot ForenseLab - Windows Hotspot Movel)
Metodo de captura: Wireshark no Windows (interface Wi-Fi)
=============================================================

FICHEIROS RECOLHIDOS E VERIFICADOS:

[1] Estado inicial do ambiente
    Ficheiro: $(basename $FICHEIRO_ESTADO)
    SHA-256:  $HASH_ESTADO

[2] Scan detalhado ao dispositivo Tapo
    Ficheiro: $(basename $FICHEIRO_SCAN)
    SHA-256:  $HASH_SCAN

[3] Scan completo de portas
    Ficheiro: $(basename $FICHEIRO_PORTAS)
    SHA-256:  $HASH_PORTAS

[4] Captura de trafego de rede (pcap - Wireshark)
    Ficheiro: $(basename $FICHEIRO_PCAP)
    Tamanho:  $TAMANHO_PCAP
    Pacotes:  $TOTAL_PACOTES
    SHA-256:  $HASH_PCAP

[5] Nomes DNS resolvidos (extracao sumaria)
    Ficheiro: $(basename $FICHEIRO_DNS)
    Total:    $TOTAL_DNS entradas
    SHA-256:  $HASH_DNS

[6] IPs de destino contactados (extracao sumaria)
    Ficheiro: $(basename $FICHEIRO_IPS)
    Total:    $TOTAL_IPS IPs unicos
    SHA-256:  $HASH_IPS

[7] Hosts descobertos na rede
    Ficheiro: $(basename $FICHEIRO_HOSTS)
    SHA-256:  $HASH_HOSTS

=============================================================
SWGDE: Todos os ficheiros foram recolhidos sem alteracao
das evidencias originais. Hashes SHA-256 calculados
imediatamente apos recolha para garantir integridade.
=============================================================
Data/Hora Fim: $(date '+%Y-%m-%d %H:%M:%S UTC')
=============================================================
EOF

log "Cadeia de custodia: $FICHEIRO_CUSTODIA"
echo ""

# Guarda caso e IP para o script de analise
echo "$CASO" > "$BASE/.caso_atual"
echo "$IP_CAMERA" > "$BASE/.ip_camera"
echo "$FICHEIRO_PCAP" > "$DESTINO/.pcap_path"
log "Caso, IP e path do pcap guardados para analisar_evidencias_fase3.sh"
echo ""

# =============================================================================
# SUMÁRIO
# =============================================================================
echo "============================================================"
echo "   COLLECTION CONCLUIDA - $CASO"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
log "=== SUMARIO DA COLLECTION ==="
log "Ficheiros em: $DESTINO"
log "  estado_inicial_*.txt       -> Estado do ambiente"
log "  scan_Tapo_*.txt            -> Scan detalhado camera"
log "  portas_Tapo_*.txt          -> Scan completo de portas"
log "  captura_rede_Tapo_*.pcap*  -> Trafego de rede (Wireshark)"
log "  dns_resolvidos_*.txt       -> DNS (extracao sumaria)"
log "  ips_destino_*.txt          -> IPs contactados (extracao sumaria)"
log "  hosts_rede_*.txt           -> Dispositivos na rede"
log "  cadeia_custodia_*.txt      -> Cadeia de custodia SWGDE"
echo ""
log "Proximo passo: correr analisar_evidencias_fase3.sh"
log "=== FIM DA COLLECTION ==="
