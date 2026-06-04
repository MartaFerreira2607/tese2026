#!/bin/bash
# =============================================================================
# FASE 1 — ANALYSIS + REPORTING
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: Raspberry Pi 4 + NoIR Camera Module v2
# Executar no WSL do PC forense
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/i/Mestrado/Tese/Fase1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- VERIFICA CASO DOS SCRIPTS ANTERIORES ---
FICHEIRO_CASO="$BASE/.caso_atual"
if [ -f "$FICHEIRO_CASO" ]; then
    CASO=$(cat "$FICHEIRO_CASO")
    echo "A usar caso existente: $CASO"
else
    echo "ERRO: Nenhum caso encontrado. Corre primeiro capturar_rede_fase1.sh e extrair_evidencias_fase1.sh"
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
echo "   FASE 1 — ANALYSIS + REPORTING"
echo "   Framework NIST + SWGDE | Raspberry Pi 4 + NoIR Camera"
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

RELATORIO="$DESTINO/relatorio_final_$CASO.txt"
cat > "$RELATORIO" << EOF
=============================================================
RELATÓRIO FORENSE FINAL — REPORTING
Framework NIST Forensics Process Model + SWGDE Best Practices
=============================================================
Caso:           $CASO
Data/Hora:      $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador:   $(whoami)
Dispositivo:    Raspberry Pi 4 + NoIR Camera Module v2
=============================================================

EOF

# -----------------------------------------------------------------------------
# 1. VERIFICAÇÃO DE INTEGRIDADE PÓS-EXAMINATION — SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE — Verificação de integridade: re-hash de todas as evidências"
log "--- PASSO 1: Re-verificação de integridade ---"

echo "==============================================================" >> "$RELATORIO"
echo "1. VERIFICAÇÃO DE INTEGRIDADE (SWGDE)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

TOTAL_OK=0
TOTAL_FALHOU=0

CUSTODIA="$EXAMINATION/hashes/cadeia_custodia_examination_"*".txt"
for ficheiro in \
    "$EXAMINATION/videos/"* \
    "$EXAMINATION/imagens/"* \
    "$EXAMINATION/metadados/"*; do
    if [ -f "$ficheiro" ]; then
        NOME=$(basename "$ficheiro")
        HASH_ATUAL=$(sha256sum "$ficheiro" | awk '{print $1}')
        if grep -q "$HASH_ATUAL" $CUSTODIA 2>/dev/null; then
            echo "  $NOME" >> "$RELATORIO"
            echo "  SHA-256: $HASH_ATUAL" >> "$RELATORIO"
            echo "  Integridade: VERIFICADA" >> "$RELATORIO"
            echo "" >> "$RELATORIO"
            TOTAL_OK=$((TOTAL_OK + 1))
        else
            echo "  $NOME — hash não encontrado na cadeia de custódia" >> "$RELATORIO"
            echo "  SHA-256 actual: $HASH_ATUAL" >> "$RELATORIO"
            echo "" >> "$RELATORIO"
            TOTAL_FALHOU=$((TOTAL_FALHOU + 1))
            aviso "Hash não encontrado na cadeia de custódia: $NOME"
        fi
    fi
done

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

PORTAS_FILE=$(ls "$COLLECTION/portas_RaspberryPi_"*.txt 2>/dev/null | head -1)
if [ -f "$PORTAS_FILE" ]; then
    echo "  Portas abertas no Raspberry Pi:" >> "$RELATORIO"
    grep "open" "$PORTAS_FILE" | while read linha; do
        echo "    $linha" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
    TOTAL_PORTAS=$(grep -c "open" "$PORTAS_FILE" 2>/dev/null || echo "0")
    log "Portas abertas no dispositivo: $TOTAL_PORTAS"
fi
echo ""

# -----------------------------------------------------------------------------
# 3. ANÁLISE DO TRÁFEGO DE REDE — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise do tráfego de rede capturado"
log "--- PASSO 3: Análise do pcap ---"

echo "==============================================================" >> "$RELATORIO"
echo "3. ANÁLISE DO TRÁFEGO DE REDE (COLLECTION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

PCAP=$(ls "$COLLECTION/rede/captura_rede_"*.pcap 2>/dev/null | head -1)
if [ -f "$PCAP" ]; then
    TOTAL_PACOTES=$(tshark -r "$PCAP" 2>/dev/null | wc -l)
    echo "  Ficheiro pcap: $(basename $PCAP)" >> "$RELATORIO"
    echo "  Total de pacotes: $TOTAL_PACOTES" >> "$RELATORIO"
    echo "" >> "$RELATORIO"

    echo "  Protocolos detectados:" >> "$RELATORIO"
    tshark -r "$PCAP" -T fields -e _ws.col.Protocol 2>/dev/null \
        | sort | uniq -c | sort -rn | head -10 \
        | while read linha; do echo "    $linha" >> "$RELATORIO"; done
    echo "" >> "$RELATORIO"

    echo "  IPs de destino contactados (top 10):" >> "$RELATORIO"
    tshark -r "$PCAP" -T fields -e ip.dst 2>/dev/null \
        | sort | uniq -c | sort -rn | head -10 \
        | while read linha; do echo "    $linha" >> "$RELATORIO"; done
    echo "" >> "$RELATORIO"

    echo "  Consultas DNS:" >> "$RELATORIO"
    tshark -r "$PCAP" -Y "dns.flags.response == 1" \
        -T fields -e dns.qry.name -e dns.a 2>/dev/null \
        | sort -u \
        | while read linha; do echo "    $linha" >> "$RELATORIO"; done
    echo "" >> "$RELATORIO"

    log "Pcap analisado: $TOTAL_PACOTES pacotes"
else
    aviso "Ficheiro pcap não encontrado em $COLLECTION/rede/"
    echo "  Ficheiro pcap não encontrado." >> "$RELATORIO"
    echo "" >> "$RELATORIO"
fi
echo ""

# -----------------------------------------------------------------------------
# 4. ANÁLISE DOS VÍDEOS — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise dos vídeos gravados"
log "--- PASSO 4: Análise dos vídeos ---"

echo "==============================================================" >> "$RELATORIO"
echo "4. ANÁLISE DOS VÍDEOS (EXAMINATION)" >> "$RELATORIO"
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

META_TXT=$(ls "$EXAMINATION/metadados/metadados_videos_"*.txt 2>/dev/null | head -1)
if [ -f "$META_TXT" ]; then
    echo "  Metadados ExifTool (resumo):" >> "$RELATORIO"
    grep -E "File Name|Create Date|Duration|Image Size|Video Frame Rate" \
        "$META_TXT" 2>/dev/null | head -20 \
        | while read linha; do echo "    $linha" >> "$RELATORIO"; done
    echo "" >> "$RELATORIO"
fi

log "Vídeos analisados: $VIDEO_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 5. ANÁLISE DAS IMAGENS — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise das imagens capturadas"
log "--- PASSO 5: Análise das imagens ---"

echo "==============================================================" >> "$RELATORIO"
echo "5. ANÁLISE DAS IMAGENS (EXAMINATION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

IMG_COUNT=0
for imagem in "$EXAMINATION/imagens/"*; do
    if [ -f "$imagem" ]; then
        NOME=$(basename "$imagem")
        TAMANHO=$(du -h "$imagem" | awk '{print $1}')
        DATA_MOD=$(stat -c '%y' "$imagem" | cut -d'.' -f1)
        echo "  Ficheiro: $NOME" >> "$RELATORIO"
        echo "  Tamanho:  $TAMANHO" >> "$RELATORIO"
        echo "  Data:     $DATA_MOD" >> "$RELATORIO"
        echo "" >> "$RELATORIO"
        IMG_COUNT=$((IMG_COUNT + 1))
    fi
done

META_IMG=$(ls "$EXAMINATION/metadados/metadados_imagens_"*.txt 2>/dev/null | head -1)
if [ -f "$META_IMG" ]; then
    echo "  Metadados ExifTool (resumo):" >> "$RELATORIO"
    grep -E "File Name|Create Date|Image Size|Camera Model" \
        "$META_IMG" 2>/dev/null | head -20 \
        | while read linha; do echo "    $linha" >> "$RELATORIO"; done
    echo "" >> "$RELATORIO"
fi

log "Imagens analisadas: $IMG_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 6. ANÁLISE DO SISTEMA — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Análise dos artefactos do sistema"
log "--- PASSO 6: Análise do sistema ---"

echo "==============================================================" >> "$RELATORIO"
echo "6. ANÁLISE DO SISTEMA (COLLECTION)" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

OS_FILE=$(ls "$COLLECTION/sistema/os_release_"*.txt 2>/dev/null | head -1)
if [ -f "$OS_FILE" ]; then
    echo "  Sistema operativo:" >> "$RELATORIO"
    grep "PRETTY_NAME" "$OS_FILE" | while read linha; do
        echo "    $linha" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
fi

CRON_FILE=$(ls "$COLLECTION/sistema/crontab_"*.txt 2>/dev/null | head -1)
if [ -f "$CRON_FILE" ]; then
    echo "  Crontab (script de vigilância):" >> "$RELATORIO"
    cat "$CRON_FILE" | while read linha; do
        echo "    $linha" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
fi

CAM_FILE=$(ls "$COLLECTION/sistema/camera_info_"*.txt 2>/dev/null | head -1)
if [ -f "$CAM_FILE" ]; then
    echo "  Informação da câmara:" >> "$RELATORIO"
    cat "$CAM_FILE" | while read linha; do
        echo "    $linha" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
fi

CONN_FILE=$(ls "$COLLECTION/sistema/conexoes_rede_"*.txt 2>/dev/null | head -1)
if [ -f "$CONN_FILE" ]; then
    echo "  Conexões de rede activas:" >> "$RELATORIO"
    head -20 "$CONN_FILE" | while read linha; do
        echo "    $linha" >> "$RELATORIO"
    done
    echo "" >> "$RELATORIO"
fi

log "Análise do sistema concluída."
echo ""

# -----------------------------------------------------------------------------
# 7. LINHA TEMPORAL — NIST: Analysis
# -----------------------------------------------------------------------------
fase "NIST — Analysis: Construção da linha temporal dos eventos"
log "--- PASSO 7: Linha temporal ---"

echo "==============================================================" >> "$RELATORIO"
echo "7. LINHA TEMPORAL DOS EVENTOS" >> "$RELATORIO"
echo "==============================================================" >> "$RELATORIO"
echo "" >> "$RELATORIO"

echo "  Vídeos por ordem cronológica:" >> "$RELATORIO"
find "$EXAMINATION/videos" -type f 2>/dev/null | sort | while read f; do
    NOME=$(basename "$f")
    DATA=$(stat -c '%y' "$f" | cut -d'.' -f1)
    echo "    [$DATA] $NOME" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"

echo "  Imagens por ordem cronológica:" >> "$RELATORIO"
find "$EXAMINATION/imagens" -type f 2>/dev/null | sort | while read f; do
    NOME=$(basename "$f")
    DATA=$(stat -c '%y' "$f" | cut -d'.' -f1)
    echo "    [$DATA] $NOME" >> "$RELATORIO"
done
echo "" >> "$RELATORIO"

log "Linha temporal construída."
echo ""

# -----------------------------------------------------------------------------
# 8. SUMÁRIO EXECUTIVO — REPORTING
# -----------------------------------------------------------------------------
fase "REPORTING: Geração do sumário executivo"
log "--- PASSO 8: Sumário executivo ---"

TOTAL_EVIDENCIAS=$(find "$EXAMINATION" -type f | wc -l)
TAMANHO_TOTAL=$(du -sh "$BASE/$CASO" | cut -f1)

cat >> "$RELATORIO" << EOF
==============================================================
8. SUMÁRIO EXECUTIVO — REPORTING
==============================================================

CASO:           $CASO
DATA/HORA:      $(date '+%Y-%m-%d %H:%M:%S UTC')
INVESTIGADOR:   $(whoami)
DISPOSITIVO:    Raspberry Pi 4 + NoIR Camera Module v2

FRAMEWORK APLICADA:
  - NIST Forensics Process Model
  - SWGDE Best Practices for IoT Forensics

FASES EXECUTADAS:
  COLLECTION  — Reconhecimento de rede, artefactos e captura de tráfego
  EXAMINATION — Extracção, verificação de integridade e metadados
  ANALYSIS    — Análise das evidências recolhidas
  REPORTING   — Relatório formal gerado

EVIDÊNCIAS RECOLHIDAS:
  Vídeos:              $VIDEO_COUNT ficheiro(s)
  Imagens:             $IMG_COUNT ficheiro(s)
  Total de ficheiros:  $TOTAL_EVIDENCIAS
  Tamanho total:       $TAMANHO_TOTAL
  Integridade OK:      $TOTAL_OK ficheiro(s)
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
log "Relatório final: $RELATORIO"
log "SHA-256 do relatório: $HASH_RELATORIO"
echo ""

# Encerrar caso
rm -f "$BASE/.caso_atual"
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
log "Relatório gerado em:  $RELATORIO"
log "SHA-256 do relatório: $HASH_RELATORIO"
echo ""
log "Estrutura completa do caso:"
log "  $BASE/$CASO/"
log "    recolha/    → COLLECTION (rede, scans, sistema, tráfego)"
log "    extracao/   → EXAMINATION (evidências extraídas)"
log "    analise/    → ANALYSIS + REPORTING (relatório final)"
echo ""
log "=== FIM DA ANALYSIS + REPORTING ==="
