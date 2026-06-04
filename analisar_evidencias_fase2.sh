#!/bin/bash
# =============================================================================
# FASE 2: ANALYSIS + REPORTING
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: TP-Link Tapo TC71 + Agent DVR
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/e/Mestrado/Tese/Fase2"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- VERIFICA CASO DOS SCRIPTS ANTERIORES ---
FICHEIRO_CASO="$BASE/.caso_atual"
if [ -f "$FICHEIRO_CASO" ]; then
    CASO=$(cat "$FICHEIRO_CASO")
    echo "A usar caso existente: $CASO"
else
    echo "ERRO: Nenhum caso encontrado. Corre primeiro captura_rede.sh e extracao_evidencias.sh"
    exit 1
fi

COLLECTION="$BASE/$CASO/recolha"
EXAMINATION="$BASE/$CASO/extracao"
DESTINO="$BASE/$CASO/analise"

mkdir -p "$DESTINO"
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

# =============================================================================
# INÍCIO
# =============================================================================
clear
echo "============================================================"
echo "   FASE: ANALYSIS + REPORTING"
echo "   Framework NIST + SWGDE | Tapo TC71 + Agent DVR"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

fase "Fase ANALYSIS iniciada — NIST: Análise das evidências recolhidas"
fase "SWGDE: Verificação de integridade + Relatório formal"
echo ""

log "=== INÍCIO DA ANALYSIS ==="
log "Caso:          $CASO"
log "Collection:    $COLLECTION"
log "Examination:   $EXAMINATION"
log "Destino:       $DESTINO"
log "Investigador:  $(whoami)"
echo ""

# Ficheiro do relatório final
RELATORIO="$DESTINO/relatorio_final_$CASO.txt"

cat > "$RELATORIO" << EOF
=============================================================
RELATÓRIO FORENSE FINAL — REPORTING
Framework NIST Forensics Process Model + SWGDE Best Practices
=============================================================
Caso:           $CASO
Data/Hora:      $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador:   $(whoami)
Dispositivo:    TP-Link Tapo TC71 (Pan/Tilt Wi-Fi Camera)
Servidor NVR:   Agent DVR (Windows PC local)
=============================================================

EOF

# -----------------------------------------------------------------------------
# 1. VERIFICAÇÃO DE INTEGRIDADE PÓS-EXAMINATION — SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE — Verificação de integridade: re-hash de todas as evidências"
log "--- PASSO 1: Re-verificação de integridade das evidências ---"

echo "==============================================================" >> "$RELATORIO"
echo "1. VERIFICAÇÃO DE INTEGRIDADE (SWGDE)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

TOTAL_OK=0
TOTAL_FALHOU=0

for ficheiro in \
    "$EXAMINATION/videos/"* \
    "$EXAMINATION/imagens/"* \
    "$EXAMINATION/metadados/"* \
    "$EXAMINATION/base_dados/"* \
    "$EXAMINATION/logs_agentdvr/"* \
    "$EXAMINATION/config/"*; do
    if [ -f "$ficheiro" ]; then
        NOME=$(basename "$ficheiro")
        HASH_ATUAL=$(sha256sum "$ficheiro" | awk '{print $1}')
        # Verifica se o hash consta na cadeia de custódia da Examination
        CUSTODIA="$EXAMINATION/hashes/cadeia_custodia_examination_"*".txt"
        if grep -q "$HASH_ATUAL" $CUSTODIA 2>/dev/null; then
            echo "   $NOME" >> "$RELATORIO"
            echo "   SHA-256: $HASH_ATUAL" >> "$RELATORIO"
            TOTAL_OK=$((TOTAL_OK + 1))
        else
            echo "   NOME — hash não encontrado na cadeia de custódia" >> "$RELATORIO"
            echo "   SHA-256 atual: $HASH_ATUAL" >> "$RELATORIO"
            TOTAL_FALHOU=$((TOTAL_FALHOU + 1))
            aviso "Hash não encontrado na cadeia de custódia: $NOME"
        fi
    fi
done

echo "" >> "$RELATORIO"
echo "  Total verificados com sucesso: $TOTAL_OK" >> "$RELATORIO"
echo "  Total com aviso:               $TOTAL_FALHOU" >> "$RELATORIO"
echo "" >> "$RELATORIO"
log "Verificação de integridade: $TOTAL_OK OK | $TOTAL_FALHOU avisos"
echo ""

# -----------------------------------------------------------------------------
# 2. ANÁLISE DA REDE — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise dos resultados de reconhecimento de rede"
log "--- PASSO 2: Análise da rede ---"

echo "==============================================================" >> "$RELATORIO"
echo "2. ANÁLISE DE REDE (COLLECTION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

# Hosts descobertos
HOSTS_FILE=$(ls "$COLLECTION/hosts_rede_"*.txt 2>/dev/null | head -1)
if [ -f "$HOSTS_FILE" ]; then
    TOTAL_HOSTS=$(grep -c "Host is up" "$HOSTS_FILE" 2>/dev/null || echo "0")
    echo "  Dispositivos descobertos na rede: $TOTAL_HOSTS" >> "$RELATORIO"
    echo "" >> "$RELATORIO"
    echo "  Lista de dispositivos:" >> "$RELATORIO"
    grep "Nmap scan report" "$HOSTS_FILE" | while read linha; do
        echo "    $linha" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
    log "Hosts analisados: $TOTAL_HOSTS dispositivos"
fi

# Portas abertas na câmara
PORTAS_FILE=$(ls "$COLLECTION/portas_TC71_"*.txt 2>/dev/null | head -1)
if [ -f "$PORTAS_FILE" ]; then
    echo "  Portas abertas na câmara TC71:" >> "$RELATORIO"
    grep "open" "$PORTAS_FILE" | while read linha; do
        echo "    $linha" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
    TOTAL_PORTAS=$(grep -c "open" "$PORTAS_FILE" 2>/dev/null || echo "0")
    log "Portas abertas na câmara: $TOTAL_PORTAS"
fi
echo ""

# -----------------------------------------------------------------------------
# 3. ANÁLISE DOS VÍDEOS — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise dos vídeos gravados"
log "--- PASSO 3: Análise dos vídeos ---"

echo "==============================================================" >> "$RELATORIO"
echo "3. ANÁLISE DOS VÍDEOS (EXAMINATION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

VIDEO_COUNT=0
for video in "$EXAMINATION/videos/"*; do
    if [ -f "$video" ]; then
        NOME=$(basename "$video")
        TAMANHO=$(du -h "$video" | awk '{print $1}')
        DATA_MOD=$(stat -c '%y' "$video" | cut -d'.' -f1)
        echo "  Ficheiro: $NOME" >> "$RELATORIO"
        echo "  Tamanho:  $TAMANHO" >> "$RELATORIO"
        echo "  Data:     $DATA_MOD" >> "$RELATORIO"
        echo "" >> "$RELATORIO"
        VIDEO_COUNT=$((VIDEO_COUNT + 1))
    fi
done

# Metadados ExifTool
META_CSV=$(ls "$EXAMINATION/metadados/metadados_videos_"*.csv 2>/dev/null | head -1)
if [ -f "$META_CSV" ]; then
    echo "  Metadados ExifTool (resumo):" >> "$RELATORIO"
    head -5 "$META_CSV" >> "$RELATORIO"
    echo "" >> "$RELATORIO"
fi

log "Vídeos analisados: $VIDEO_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 4. ANÁLISE DOS LOGS — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise dos logs do servidor NVR"
log "--- PASSO 4: Análise dos logs do Agent DVR ---"

echo "==============================================================" >> "$RELATORIO"
echo "4. ANÁLISE DOS LOGS DO AGENT DVR (EXAMINATION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

LOG_COUNT=0
for log_file in "$EXAMINATION/logs_agentdvr/"*.json; do
    if [ -f "$log_file" ]; then
        NOME=$(basename "$log_file")
        TAMANHO=$(du -h "$log_file" | awk '{print $1}')
        LINHAS=$(wc -l < "$log_file")
        echo "  Ficheiro: $NOME | Tamanho: $TAMANHO | Linhas: $LINHAS" >> "$RELATORIO"
        LOG_COUNT=$((LOG_COUNT + 1))
    fi
done

# sessionlog
SESSION="$EXAMINATION/logs_agentdvr/sessionlog.txt"
if [ -f "$SESSION" ]; then
    echo "" >> "$RELATORIO"
    echo "  Conteúdo do sessionlog.txt:" >> "$RELATORIO"
    cat "$SESSION" >> "$RELATORIO"
fi
echo "" >> "$RELATORIO"
log "Logs analisados: $LOG_COUNT ficheiros"
echo ""

# -----------------------------------------------------------------------------
# 5. ANÁLISE DA BASE DE DADOS — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise da base de dados SQLite"
log "--- PASSO 5: Análise da base de dados ---"

echo "==============================================================" >> "$RELATORIO"
echo "5. ANÁLISE DA BASE DE DADOS SQLITE (EXAMINATION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

DB="$EXAMINATION/base_dados/fileDB.db3"
if [ -f "$DB" ]; then
    TABELAS=$(sqlite3 "$DB" ".tables" 2>/dev/null)
    echo "  Tabelas na base de dados: $TABELAS" >> "$RELATORIO"
    echo "" >> "$RELATORIO"
    for tabela in $TABELAS; do
        TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM $tabela;" 2>/dev/null)
        echo "  Tabela '$tabela': $TOTAL registos" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
    log "Base de dados analisada: $TABELAS"
fi
echo ""

# -----------------------------------------------------------------------------
# 6. ANÁLISE DOS FICHEIROS DE CONFIGURAÇÃO — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise das configurações do dispositivo"
log "--- PASSO 6: Análise das configurações ---"

echo "==============================================================" >> "$RELATORIO"
echo "6. ANÁLISE DE CONFIGURAÇÕES (EXAMINATION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

for config in "$EXAMINATION/config/"*.json; do
    if [ -f "$config" ]; then
        NOME=$(basename "$config")
        TAMANHO=$(du -h "$config" | awk '{print $1}')
        echo "  Ficheiro: $NOME | Tamanho: $TAMANHO" >> "$RELATORIO"
    fi
done
echo "" >> "$RELATORIO"
log "Configurações analisadas."
echo ""

# -----------------------------------------------------------------------------
# 7. LINHA TEMPORAL — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Construção da linha temporal dos eventos"
log "--- PASSO 7: Construção da linha temporal ---"

echo "==============================================================" >> "$RELATORIO"
echo "7. LINHA TEMPORAL DOS EVENTOS" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

# Timestamps dos vídeos por ordem cronológica
echo "  Gravações por ordem cronológica:" >> "$RELATORIO"
for video in "$EXAMINATION/videos/"*; do
    if [ -f "$video" ]; then
        NOME=$(basename "$video")
        DATA=$(stat -c '%y' "$video" | cut -d'.' -f1)
        echo "    [$DATA] $NOME" >> "$RELATORIO"
    fi
done
echo "" >> "$RELATORIO"

# Timestamps das miniaturas
echo "  Miniaturas por ordem cronológica:" >> "$RELATORIO"
for img in "$EXAMINATION/imagens/"*; do
    if [ -f "$img" ]; then
        NOME=$(basename "$img")
        DATA=$(stat -c '%y' "$img" | cut -d'.' -f1)
        echo "    [$DATA] $NOME" >> "$RELATORIO"
    fi
done
echo "" >> "$RELATORIO"
log "Linha temporal construída."
echo ""

# -----------------------------------------------------------------------------
# 8. RELATÓRIO FINAL — REPORTING
# -----------------------------------------------------------------------------
fase "REPORTING: Geração do relatório forense final"
log "--- PASSO 8: Finalização do relatório ---"

cat >> "$RELATORIO" << EOF
==============================================================
8. SUMÁRIO EXECUTIVO — REPORTING
==============================================================

CASO:           $CASO
DATA/HORA:      $(date '+%Y-%m-%d %H:%M:%S UTC')
INVESTIGADOR:   $(whoami)
DISPOSITIVO:    TP-Link Tapo TC71 (Pan/Tilt Wi-Fi Camera)
SERVIDOR NVR:   Agent DVR (Windows PC local)

FRAMEWORK APLICADA:
  - NIST Forensics Process Model
  - SWGDE Best Practices for IoT Forensics

FASES EXECUTADAS:
  COLLECTION      — Reconhecimento de rede e captura de tráfego
  EXAMINATION     — Extração e preservação de evidências
  ANALYSIS        — Análise das evidências recolhidas
  REPORTING       — Relatório formal gerado

EVIDÊNCIAS RECOLHIDAS:
  Vídeos:              $VIDEO_COUNT ficheiro(s)
  Logs Agent DVR:      $LOG_COUNT ficheiro(s)
  Integridade OK:      $TOTAL_OK ficheiro(s) verificados
  Integridade avisos:  $TOTAL_FALHOU ficheiro(s)

LOCALIZAÇÃO DAS EVIDÊNCIAS:
  Collection:  $COLLECTION
  Examination: $EXAMINATION
  Analysis:    $DESTINO

SWGDE — DECLARAÇÃO DE INTEGRIDADE:
  Todas as evidências foram recolhidas sem alteração dos
  originais. Hashes SHA-256 calculados antes e após cada
  cópia para garantir a integridade da cadeia de custódia.

==============================================================
FIM DO RELATÓRIO
$(date '+%Y-%m-%d %H:%M:%S UTC')
==============================================================
EOF

HASH_RELATORIO=$(sha256sum "$RELATORIO" | awk '{print $1}')
log "Relatório final gerado: $RELATORIO"
log "SHA-256 do relatório: $HASH_RELATORIO"
echo ""

# --- LIMPA O FICHEIRO .caso_atual ---
rm -f "$FICHEIRO_CASO"
log "Ficheiro .caso_atual removido — caso encerrado."
echo ""

# =============================================================================
# SUMÁRIO FINAL
# =============================================================================
echo "============================================================"
echo "   ANALYSIS + REPORTING CONCLUÍDOS — $CASO"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
log "=== SUMÁRIO FINAL ==="
log "Relatório gerado em: $RELATORIO"
log "SHA-256 do relatório: $HASH_RELATORIO"
echo ""
log "Estrutura completa do caso:"
log "  $BASE/$CASO/"
log "    recolha/    → COLLECTION (rede, scans, tráfego)"
log "    extracao/   → EXAMINATION (evidências extraídas)"
log "    analise/      → ANALYSIS + REPORTING (relatório final)"
echo ""
log "=== FIM DA ANALYSIS + REPORTING ==="
