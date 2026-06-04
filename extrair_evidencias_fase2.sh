#!/bin/bash
# =============================================================================
# FASE 2: EXAMINATION - EXTRAÇÃO DE EVIDÊNCIAS
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: TP-Link Tapo TC71 + Agent DVR
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/e/Mestrado/Tese/Fase2"
AGENTDVR_VIDEO="/mnt/d/Program Files/Agent/Media/WebServerRoot/Media/video/XCGGR"
AGENTDVR_MEDIA="/mnt/d/Program Files/Agent/Media"
AGENTDVR_XML="/mnt/d/Program Files/Agent/Media/XML"
AGENTDVR_BASE="/mnt/d/Program Files/Agent"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- VERIFICA CASO DO SCRIPT DE COLLECTION ---
FICHEIRO_CASO="$BASE/.caso_atual"
if [ -f "$FICHEIRO_CASO" ]; then
    CASO=$(cat "$FICHEIRO_CASO")
    echo "A usar caso existente: $CASO"
else
    CASO="CASO_$TIMESTAMP"
    echo "Novo caso criado: $CASO"
fi

DESTINO="$BASE/$CASO/extracao"

# Criar estrutura ANTES de qualquer log
mkdir -p "$DESTINO/videos"
mkdir -p "$DESTINO/imagens"
mkdir -p "$DESTINO/metadados"
mkdir -p "$DESTINO/base_dados"
mkdir -p "$DESTINO/logs_agentdvr"
mkdir -p "$DESTINO/config"
mkdir -p "$DESTINO/hashes"

LOG="$DESTINO/log_examination_$TIMESTAMP.txt"

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

# Função de hash e verificação de integridade SWGDE
registar_e_verificar() {
    local original="$1"
    local copia="$2"
    local descricao="$3"

    local hash_original=$(sha256sum "$original" | awk '{print $1}')
    local hash_copia=$(sha256sum "$copia" | awk '{print $1}')

    echo "$descricao" >> "$FICHEIRO_CUSTODIA"
    echo "  Original:  $original" >> "$FICHEIRO_CUSTODIA"
    echo "  Cópia:     $copia" >> "$FICHEIRO_CUSTODIA"
    echo "  SHA-256 (original): $hash_original" >> "$FICHEIRO_CUSTODIA"
    echo "  SHA-256 (cópia):    $hash_copia" >> "$FICHEIRO_CUSTODIA"

    if [ "$hash_original" = "$hash_copia" ]; then
        echo "  Integridade:   VERIFICADA" >> "$FICHEIRO_CUSTODIA"
        log "   Integridade verificada [$descricao]"
    else
        echo "  Integridade:   FALHOU" >> "$FICHEIRO_CUSTODIA"
        erro "  Falha de integridade [$descricao]"
    fi
    echo "" >> "$FICHEIRO_CUSTODIA"
}

# =============================================================================
# INÍCIO
# =============================================================================
clear
echo "============================================================"
echo "   FASE: EXAMINATION"
echo "   Framework NIST + SWGDE | Tapo TC71 + Agent DVR"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

# Ficheiro de cadeia de custódia
FICHEIRO_CUSTODIA="$DESTINO/hashes/cadeia_custodia_examination_$TIMESTAMP.txt"
cat > "$FICHEIRO_CUSTODIA" << EOF
=============================================================
CADEIA DE CUSTÓDIA — EXAMINATION
Framework NIST + SWGDE
Caso: $CASO
Data/Hora Início: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
=============================================================
SWGDE: Verificação de integridade SHA-256 — original vs cópia
=============================================================

EOF

fase "Fase EXAMINATION iniciada — NIST: Extração e preservação de evidências"
fase "SWGDE: Verificação de integridade SHA-256 em cada evidência recolhida"
echo ""

log "=== INÍCIO DA EXAMINATION ==="
log "Caso:                     $CASO"
log "Fonte Agent DVR (vídeos): $AGENTDVR_VIDEO"
log "Destino evidências:       $DESTINO"
log "Investigador:             $(whoami)"
echo ""

# -----------------------------------------------------------------------------
# 1. EXTRAÇÃO DE VÍDEOS
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extração de vídeos gravados pelo servidor NVR"
log "--- PASSO 1: Extração de vídeos do Agent DVR ---"
VIDEO_COUNT=0
for video in "$AGENTDVR_VIDEO"/*.mkv "$AGENTDVR_VIDEO"/*.mp4 "$AGENTDVR_VIDEO"/*.avi; do
    if [ -f "$video" ]; then
        NOME=$(basename "$video")
        cp "$video" "$DESTINO/videos/$NOME"
        registar_e_verificar "$video" "$DESTINO/videos/$NOME" "Vídeo: $NOME"
        VIDEO_COUNT=$((VIDEO_COUNT + 1))
        log "Extraído: $NOME"
    fi
done
log "Total de vídeos extraídos: $VIDEO_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 2. EXTRAÇÃO DE MINIATURAS (THUMBS)
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extração de miniaturas dos vídeos"
log "--- PASSO 2: Extração de miniaturas (thumbs) ---"
IMG_COUNT=0
THUMB_DIR="/mnt/d/Program Files/Agent/Media/WebServerRoot/Media/video/XCGGR/thumbs"
if [ -d "$THUMB_DIR" ] && [ "$(ls -A "$THUMB_DIR" 2>/dev/null)" ]; then
    for imagem in "$THUMB_DIR"/*; do
        if [ -f "$imagem" ]; then
            NOME=$(basename "$imagem")
            cp "$imagem" "$DESTINO/imagens/$NOME"
            registar_e_verificar "$imagem" "$DESTINO/imagens/$NOME" "Miniatura: $NOME"
            IMG_COUNT=$((IMG_COUNT + 1))
        fi
    done
    log "Total de miniaturas extraídas: $IMG_COUNT"
else
    aviso "Pasta thumbs vazia ou não encontrada."
fi
echo ""

# -----------------------------------------------------------------------------
# 3. METADADOS DOS VÍDEOS (EXIFTOOL)
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extração de metadados para análise forense"
log "--- PASSO 3: Metadados dos vídeos com ExifTool ---"
if [ $VIDEO_COUNT -gt 0 ]; then
    FICHEIRO_META_CSV="$DESTINO/metadados/metadados_videos_$TIMESTAMP.csv"
    FICHEIRO_META_TXT="$DESTINO/metadados/metadados_detalhado_$TIMESTAMP.txt"
    exiftool -csv "$DESTINO/videos/"* > "$FICHEIRO_META_CSV" 2>> "$LOG"
    exiftool "$DESTINO/videos/"* > "$FICHEIRO_META_TXT" 2>> "$LOG"

    HASH_META_CSV=$(sha256sum "$FICHEIRO_META_CSV" | awk '{print $1}')
    HASH_META_TXT=$(sha256sum "$FICHEIRO_META_TXT" | awk '{print $1}')

    echo "Metadados vídeos (CSV)" >> "$FICHEIRO_CUSTODIA"
    echo "  SHA-256: $HASH_META_CSV" >> "$FICHEIRO_CUSTODIA"
    echo "" >> "$FICHEIRO_CUSTODIA"
    echo "Metadados vídeos (TXT detalhado)" >> "$FICHEIRO_CUSTODIA"
    echo "  SHA-256: $HASH_META_TXT" >> "$FICHEIRO_CUSTODIA"
    echo "" >> "$FICHEIRO_CUSTODIA"

    log "SHA-256 metadados CSV: $HASH_META_CSV"
    log "SHA-256 metadados TXT: $HASH_META_TXT"
    log "Metadados guardados em: $DESTINO/metadados/"
else
    aviso "Sem vídeos para extrair metadados."
fi
echo ""

# -----------------------------------------------------------------------------
# 4. BASE DE DADOS SQLite
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extração da base de dados do servidor NVR"
log "--- PASSO 4: Extração da base de dados SQLite (fileDB.db3) ---"
DB_PATH="$AGENTDVR_XML/fileDB.db3"
if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "$DESTINO/base_dados/fileDB.db3"
    registar_e_verificar "$DB_PATH" "$DESTINO/base_dados/fileDB.db3" "Base de dados SQLite Agent DVR"
    log "Base de dados copiada: fileDB.db3"

    TABELAS=$(sqlite3 "$DESTINO/base_dados/fileDB.db3" ".tables" 2>> "$LOG")
    log "Tabelas encontradas: $TABELAS"
    for tabela in $TABELAS; do
        FICHEIRO_CSV="$DESTINO/base_dados/tabela_${tabela}_$TIMESTAMP.csv"
        sqlite3 -header -csv "$DESTINO/base_dados/fileDB.db3" \
            "SELECT * FROM $tabela;" > "$FICHEIRO_CSV" 2>> "$LOG"
        LINHAS=$(wc -l < "$FICHEIRO_CSV")
        if [ "$LINHAS" -gt 1 ]; then
            HASH_CSV=$(sha256sum "$FICHEIRO_CSV" | awk '{print $1}')
            echo "Tabela BD: $tabela ($((LINHAS-1)) registos)" >> "$FICHEIRO_CUSTODIA"
            echo "  SHA-256: $HASH_CSV" >> "$FICHEIRO_CUSTODIA"
            echo "" >> "$FICHEIRO_CUSTODIA"
            log "Tabela exportada com dados: $tabela ($((LINHAS-1)) registos)"
        else
            rm "$FICHEIRO_CSV"
            aviso "Tabela vazia (ignorada): $tabela"
        fi
    done
else
    aviso "Base de dados não encontrada em: $DB_PATH"
fi
echo ""

# -----------------------------------------------------------------------------
# 5. LOGS DO AGENT DVR
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extração de logs do servidor NVR"
log "--- PASSO 5: Extração de logs do Agent DVR ---"
LOG_COUNT=0
for i in 1 2 3 4; do
    LOG_FILE="$AGENTDVR_MEDIA/log_${i}.json"
    if [ -f "$LOG_FILE" ]; then
        cp "$LOG_FILE" "$DESTINO/logs_agentdvr/log_${i}.json"
        registar_e_verificar "$LOG_FILE" "$DESTINO/logs_agentdvr/log_${i}.json" "Log Agent DVR: log_${i}.json"
        LOG_COUNT=$((LOG_COUNT + 1))
        log "Log copiado: log_${i}.json"
    fi
done
SESSION_LOG="$AGENTDVR_MEDIA/sessionlog.txt"
if [ -f "$SESSION_LOG" ]; then
    cp "$SESSION_LOG" "$DESTINO/logs_agentdvr/sessionlog.txt"
    registar_e_verificar "$SESSION_LOG" "$DESTINO/logs_agentdvr/sessionlog.txt" "Session log Agent DVR"
    LOG_COUNT=$((LOG_COUNT + 1))
    log "Log copiado: sessionlog.txt"
fi
log "Total de logs extraídos: $LOG_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 6. FICHEIROS DE CONFIGURAÇÃO
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extração de ficheiros de configuração do dispositivo"
log "--- PASSO 6: Extração de ficheiros de configuração ---"
CONFIG_COUNT=0
declare -A CONFIGS=(
    ["$AGENTDVR_XML/config.json"]="Configuração principal Agent DVR"
    ["$AGENTDVR_XML/objects.json"]="Objetos e câmaras configuradas"
    ["$AGENTDVR_XML/NetworkDeviceList.json"]="Lista de dispositivos de rede"
    ["$AGENTDVR_XML/layouts.json"]="Layout da interface"
    ["$AGENTDVR_BASE/PTZ.json"]="Configuração Pan/Tilt TC71"
)
for config_file in "${!CONFIGS[@]}"; do
    descricao="${CONFIGS[$config_file]}"
    if [ -f "$config_file" ]; then
        NOME=$(basename "$config_file")
        cp "$config_file" "$DESTINO/config/$NOME"
        registar_e_verificar "$config_file" "$DESTINO/config/$NOME" "$descricao"
        CONFIG_COUNT=$((CONFIG_COUNT + 1))
        log "Copiado [$descricao]: $NOME"
    else
        aviso "Não encontrado: $config_file"
    fi
done
log "Total de ficheiros de configuração extraídos: $CONFIG_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 7. INFORMAÇÕES DO SISTEMA
# -----------------------------------------------------------------------------
fase "SWGDE — Documentação do ambiente de extração"
log "--- PASSO 7: Registo de informações do sistema ---"
FICHEIRO_SISTEMA="$DESTINO/info_sistema_$TIMESTAMP.txt"
cat > "$FICHEIRO_SISTEMA" << EOF
=============================================================
INFORMAÇÕES DO SISTEMA — EXAMINATION
Framework NIST + SWGDE
Caso: $CASO
Data/Hora: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
=============================================================

SISTEMA OPERATIVO (WSL): $(uname -a)
UTILIZADOR: $(whoami)
DATA/HORA LOCAL: $(date)
DATA/HORA UTC:   $(date -u)

INTERFACES DE REDE:
$(ip addr)

TABELA DE ROUTING:
$(ip route)

FERRAMENTAS UTILIZADAS:
  ExifTool: $(exiftool -ver)
  SQLite3:  $(sqlite3 --version)
  Nmap:     $(nmap --version | head -1)
  tshark:   $(tshark --version | head -1)
=============================================================
EOF
HASH_SISTEMA=$(sha256sum "$FICHEIRO_SISTEMA" | awk '{print $1}')
echo "Informações do sistema" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_SISTEMA" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "SHA-256 info sistema: $HASH_SISTEMA"
log "Informações do sistema guardadas."
echo ""

# Fechar cadeia de custódia
cat >> "$FICHEIRO_CUSTODIA" << EOF
=============================================================
Data/Hora Fim: $(date '+%Y-%m-%d %H:%M:%S UTC')
SWGDE: Examination concluída. Todos os ficheiros verificados.
Próxima fase: Analysis
=============================================================
EOF

# Próximo script usa o mesmo CASO
echo "$CASO" > "$BASE/.caso_atual"

# =============================================================================
# SUMÁRIO
# =============================================================================
echo "============================================================"
echo "   EXAMINATION CONCLUÍDA — $CASO"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
log "=== SUMÁRIO DA EXAMINATION ==="
log "Vídeos extraídos:          $VIDEO_COUNT"
log "Miniaturas extraídas:      $IMG_COUNT"
log "Logs extraídos:            $LOG_COUNT"
log "Configurações extraídas:   $CONFIG_COUNT"
echo ""
log "Estrutura em: $DESTINO"
log "  videos/          → Vídeos gravados pelo Agent DVR"
log "  imagens/         → Miniaturas (thumbs)"
log "  metadados/       → Metadados ExifTool (CSV + TXT)"
log "  base_dados/      → Base de dados SQLite + tabelas CSV"
log "  logs_agentdvr/   → Logs JSON + sessionlog"
log "  config/          → Ficheiros de configuração JSON"
log "  hashes/          → Cadeia de custódia SWGDE"
echo ""
log "Próximo passo: correr analise_evidencias.sh (Analysis + Reporting)"
log "=== FIM DA EXAMINATION ==="
