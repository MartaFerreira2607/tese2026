#!/bin/bash
# =============================================================================
# FASE 1 — EXAMINATION: EXTRACÇÃO DE EVIDÊNCIAS
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: Raspberry Pi 4 + NoIR Camera Module v2
# Executar no WSL do PC forense
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/i/Mestrado/Tese/Fase1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

PI_USER="marta"
PI_HOST="192.168.1.123"
PI_KEY="$HOME/.ssh/id_rsa"
PI_DIR="/home/marta/iot_forensics"
PI_DIR_VIDEOS="$PI_DIR/videos"
PI_DIR_IMAGES="$PI_DIR/images"
TIMEOUT_SSH=5

# --- VERIFICA CASO DO SCRIPT DE COLLECTION ---
FICHEIRO_CASO="$BASE/.caso_atual"
if [ -f "$FICHEIRO_CASO" ]; then
    CASO=$(cat "$FICHEIRO_CASO")
    echo "A usar caso existente: $CASO"
else
    echo "ERRO: Nenhum caso encontrado. Corre primeiro capturar_rede_fase1.sh"
    exit 1
fi

COLLECTION="$BASE/$CASO/recolha"
DESTINO="$BASE/$CASO/extracao"

mkdir -p "$DESTINO/videos"
mkdir -p "$DESTINO/imagens"
mkdir -p "$DESTINO/metadados"
mkdir -p "$DESTINO/logs"
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

# --- FUNÇÕES SSH ---
ssh_opts() {
    local opts="-o ConnectTimeout=$TIMEOUT_SSH -o StrictHostKeyChecking=no"
    if [ -n "$PI_KEY" ] && [ -f "$PI_KEY" ]; then
        opts="$opts -i $PI_KEY -o BatchMode=yes"
    fi
    echo "$opts"
}

pi_ssh() { ssh $(ssh_opts) "$PI_USER@$PI_HOST" "$@"; }
pi_scp() { scp $(ssh_opts) "$@"; }

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
echo "   FASE 1 — EXAMINATION"
echo "   Framework NIST + SWGDE | Raspberry Pi 4 + NoIR Camera"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

FICHEIRO_CUSTODIA="$DESTINO/hashes/cadeia_custodia_examination_$TIMESTAMP.txt"
cat > "$FICHEIRO_CUSTODIA" << EOF
=============================================================
CADEIA DE CUSTÓDIA — EXAMINATION
Framework NIST Forensics Process Model + SWGDE Best Practices
Caso: $CASO
Data/Hora Início: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
Dispositivo: Raspberry Pi 4 + NoIR Camera Module v2
IP do dispositivo: $PI_HOST
=============================================================
SWGDE: Verificação de integridade SHA-256 — original vs cópia
=============================================================

EOF

fase "Fase EXAMINATION iniciada — NIST: Extracção e preservação de evidências"
fase "SWGDE: Verificação de integridade SHA-256 em cada evidência recolhida"
echo ""

log "=== INÍCIO DA EXAMINATION ==="
log "Caso:          $CASO"
log "Dispositivo:   $PI_USER@$PI_HOST"
log "Collection:    $COLLECTION"
log "Destino:       $DESTINO"
log "Investigador:  $(whoami)"
echo ""

# -----------------------------------------------------------------------------
# 1. HASHES NA ORIGEM — SWGDE (obrigatório ANTES de copiar)
# -----------------------------------------------------------------------------
fase "SWGDE — Hashes na ORIGEM antes de copiar evidências"
log "--- PASSO 1: Hashes SHA-256 na origem (Raspberry Pi) ---"

FICHEIRO_HASHES_ORIGEM="$DESTINO/hashes/hashes_origem_$TIMESTAMP.sha256"
# Filtrado para focar apenas nas extensões forenses esperadas que serão extraídas nos Passos 2 e 3
pi_ssh "find $PI_DIR_VIDEOS $PI_DIR_IMAGES -maxdepth 1 -type f \( -name '*.jpg' -o -name '*.png' -o -name '*.h264' -o -name '*.mp4' \) \
    -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null" \
    > "$FICHEIRO_HASHES_ORIGEM"

TOTAL_ORIGEM=$(grep -c "^" "$FICHEIRO_HASHES_ORIGEM" 2>/dev/null || echo "0")
HASH_HASHES_ORIGEM=$(sha256sum "$FICHEIRO_HASHES_ORIGEM" | awk '{print $1}')
echo "Hashes de origem (SWGDE)" >> "$FICHEIRO_CUSTODIA"
echo "  Ficheiros indexados: $TOTAL_ORIGEM" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256 (registo):   $HASH_HASHES_ORIGEM" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "Hashes na origem: $TOTAL_ORIGEM ficheiros | SHA-256 do registo: $HASH_HASHES_ORIGEM"
echo ""

# -----------------------------------------------------------------------------
# 2. EXTRACÇÃO DE VÍDEOS — NIST: Examination
# CORRECÇÃO FORENSE: Lê o hash e o caminho diretamente da lista pré-calculada,
# evitando invocar ligações SSH secundárias internas que consomem a stdin e quebram o ciclo while.
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extracção de vídeos gravados pelo Raspberry Pi"
log "--- PASSO 2: Extracção de vídeos ---"

LISTA_VIDEOS=$(mktemp)
pi_ssh "find $PI_DIR_VIDEOS -maxdepth 1 -type f \( -name '*.h264' -o -name '*.mp4' \) -exec sha256sum {} + 2>/dev/null | sort" > "$LISTA_VIDEOS"

VIDEO_COUNT=0
while IFS= read -r linha; do
    [ -z "$linha" ] && continue
    
    HASH_ORIG=$(echo "$linha" | awk '{print $1}')
    f=$(echo "$linha" | awk '{print $2}')
    NOME=$(basename "$f")
    
    # Redirecionar stdin de pi_scp para /dev/null evita o roubo de dados do ciclo while
    pi_scp "$PI_USER@$PI_HOST:$f" "$DESTINO/videos/$NOME" < /dev/null
    
    if [ -f "$DESTINO/videos/$NOME" ]; then
        HASH_COPIA=$(sha256sum "$DESTINO/videos/$NOME" | awk '{print $1}')
        echo "Vídeo: $NOME" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256 (original): $HASH_ORIG" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256 (cópia):    $HASH_COPIA" >> "$FICHEIRO_CUSTODIA"
        if [ "$HASH_ORIG" = "$HASH_COPIA" ]; then
            echo "  Integridade:   VERIFICADA" >> "$FICHEIRO_CUSTODIA"
            log "  Extraído: $NOME ✓"
        else
            echo "  Integridade:   FALHOU" >> "$FICHEIRO_CUSTODIA"
            erro "  Falha de integridade: $NOME"
        fi
        echo "" >> "$FICHEIRO_CUSTODIA"
        VIDEO_COUNT=$((VIDEO_COUNT + 1))
    else
        aviso "Falha ao copiar: $NOME"
    fi
done < "$LISTA_VIDEOS"
rm -f "$LISTA_VIDEOS"

log "Total de vídeos extraídos: $VIDEO_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 3. EXTRACÇÃO DE IMAGENS — NIST: Examination
# CORRECÇÃO FORENSE: Mesma lógica aplicada às imagens para blindar a integridade do loop.
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extracção de imagens gravadas pelo Raspberry Pi"
log "--- PASSO 3: Extracção de imagens ---"

LISTA_IMAGENS=$(mktemp)
pi_ssh "find $PI_DIR_IMAGES -maxdepth 1 -type f \( -name '*.jpg' -o -name '*.png' \) -exec sha256sum {} + 2>/dev/null | sort" > "$LISTA_IMAGENS"

IMG_COUNT=0
while IFS= read -r linha; do
    [ -z "$linha" ] && continue
    
    HASH_ORIG=$(echo "$linha" | awk '{print $1}')
    f=$(echo "$linha" | awk '{print $2}')
    NOME=$(basename "$f")
    
    pi_scp "$PI_USER@$PI_HOST:$f" "$DESTINO/imagens/$NOME" < /dev/null
    
    if [ -f "$DESTINO/imagens/$NOME" ]; then
        HASH_COPIA=$(sha256sum "$DESTINO/imagens/$NOME" | awk '{print $1}')
        echo "Imagem: $NOME" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256 (original): $HASH_ORIG" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256 (cópia):    $HASH_COPIA" >> "$FICHEIRO_CUSTODIA"
        if [ "$HASH_ORIG" = "$HASH_COPIA" ]; then
            echo "  Integridade:   VERIFICADA" >> "$FICHEIRO_CUSTODIA"
            log "  Extraída: $NOME ✓"
        else
            echo "  Integridade:   FALHOU" >> "$FICHEIRO_CUSTODIA"
            erro "  Falha de integridade: $NOME"
        fi
        echo "" >> "$FICHEIRO_CUSTODIA"
        IMG_COUNT=$((IMG_COUNT + 1))
    else
        aviso "Falha ao copiar: $NOME"
    fi
done < "$LISTA_IMAGENS"
rm -f "$LISTA_IMAGENS"

log "Total de imagens extraídas: $IMG_COUNT"
echo ""

# -----------------------------------------------------------------------------
# 4. VERIFICAÇÃO GLOBAL DE INTEGRIDADE — SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE — Verificação global de integridade origem vs destino"
log "--- PASSO 4: Comparação de hashes origem vs destino ---"

FICHEIRO_HASHES_DESTINO="$DESTINO/hashes/hashes_destino_$TIMESTAMP.sha256"
find "$DESTINO/videos" "$DESTINO/imagens" \
    -maxdepth 1 -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum \
    > "$FICHEIRO_HASHES_DESTINO"

TOTAL_DESTINO=$(grep -c "^" "$FICHEIRO_HASHES_DESTINO" 2>/dev/null || echo "0")

awk '{print $1}' "$FICHEIRO_HASHES_ORIGEM" | sort > /tmp/h_orig_$TIMESTAMP.txt
awk '{print $1}' "$FICHEIRO_HASHES_DESTINO" | sort > /tmp/h_dest_$TIMESTAMP.txt

FICHEIRO_VERIFICACAO="$DESTINO/hashes/resultado_verificacao_$TIMESTAMP.txt"
if diff -q /tmp/h_orig_$TIMESTAMP.txt /tmp/h_dest_$TIMESTAMP.txt > /dev/null 2>&1; then
    RESULTADO_INTEGRIDADE="VERIFICADA"
    log "INTEGRIDADE CONFIRMADA — hashes idênticos. ✓"
else
    RESULTADO_INTEGRIDADE="FALHOU"
    erro "ATENÇÃO: Diferenças nos hashes detectadas!"
    aviso "SWGDE — Árvore de decisão:"
    aviso "  Erro de transmissão? → Repetir extracção do ficheiro afectado."
    aviso "  Adulteração?         → Isolar ficheiro e documentar."
    diff /tmp/h_orig_$TIMESTAMP.txt /tmp/h_dest_$TIMESTAMP.txt >> "$FICHEIRO_VERIFICACAO"
fi

cat >> "$FICHEIRO_VERIFICACAO" << EOF
=============================================================
RESULTADO DA VERIFICAÇÃO DE INTEGRIDADE — SWGDE
Caso: $CASO | $(date '+%Y-%m-%d %H:%M:%S UTC')
=============================================================
Resultado:            $RESULTADO_INTEGRIDADE
Ficheiros na origem:  $TOTAL_ORIGEM
Ficheiros no destino: $TOTAL_DESTINO
=============================================================
EOF

echo "Verificação global de integridade" >> "$FICHEIRO_CUSTODIA"
echo "  Resultado:  $RESULTADO_INTEGRIDADE" >> "$FICHEIRO_CUSTODIA"
echo "  Origem:     $TOTAL_ORIGEM ficheiros" >> "$FICHEIRO_CUSTODIA"
echo "  Destino:    $TOTAL_DESTINO ficheiros" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"

rm -f /tmp/h_orig_$TIMESTAMP.txt /tmp/h_dest_$TIMESTAMP.txt
echo ""

# -----------------------------------------------------------------------------
# 5. METADADOS EXIF — NIST: Examination
# -----------------------------------------------------------------------------
fase "NIST — Examination: Extracção de metadados com ExifTool"
log "--- PASSO 5: Metadados EXIF ---"

if command -v exiftool > /dev/null 2>&1; then
    mapfile -d '' imgs < <(find "$DESTINO/imagens" -maxdepth 1 -type f -print0 2>/dev/null | sort -z)
    mapfile -d '' vids < <(find "$DESTINO/videos" -maxdepth 1 -type f -print0 2>/dev/null | sort -z)

    if [ ${#imgs[@]} -gt 0 ]; then
        FICHEIRO_META_IMG="$DESTINO/metadados/metadados_imagens_$TIMESTAMP.txt"
        FICHEIRO_META_IMG_CSV="$DESTINO/metadados/metadados_imagens_$TIMESTAMP.csv"
        exiftool "${imgs[@]}" > "$FICHEIRO_META_IMG"
        exiftool -csv "${imgs[@]}" > "$FICHEIRO_META_IMG_CSV"
        HASH_META_IMG=$(sha256sum "$FICHEIRO_META_IMG" | awk '{print $1}')
        HASH_META_IMG_CSV=$(sha256sum "$FICHEIRO_META_IMG_CSV" | awk '{print $1}')
        echo "Metadados EXIF imagens (TXT)" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256: $HASH_META_IMG" >> "$FICHEIRO_CUSTODIA"
        echo "" >> "$FICHEILD_CUSTODIA"
        echo "Metadados EXIF imagens (CSV)" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256: $HASH_META_IMG_CSV" >> "$FICHEIRO_CUSTODIA"
        echo "" >> "$FICHEIRO_CUSTODIA"
        log "Metadados imagens TXT → SHA-256: $HASH_META_IMG"
        log "Metadados imagens CSV → SHA-256: $HASH_META_IMG_CSV"
    else
        aviso "Sem imagens para extrair metadados."
    fi

    if [ ${#vids[@]} -gt 0 ]; then
        FICHEIRO_META_VID="$DESTINO/metadados/metadados_videos_$TIMESTAMP.txt"
        FICHEIRO_META_VID_CSV="$DESTINO/metadados/metadados_videos_$TIMESTAMP.csv"
        exiftool "${vids[@]}" > "$FICHEIRO_META_VID"
        exiftool -csv "${vids[@]}" > "$FICHEIRO_META_VID_CSV"
        HASH_META_VID=$(sha256sum "$FICHEIRO_META_VID" | awk '{print $1}')
        HASH_META_VID_CSV=$(sha256sum "$FICHEIRO_META_VID_CSV" | awk '{print $1}')
        echo "Metadados EXIF vídeos (TXT)" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256: $HASH_META_VID" >> "$FICHEIRO_CUSTODIA"
        echo "" >> "$FICHEIRO_CUSTODIA"
        echo "Metadados EXIF vídeos (CSV)" >> "$FICHEIRO_CUSTODIA"
        echo "  SHA-256: $HASH_META_VID_CSV" >> "$FICHEIRO_CUSTODIA"
        echo "" >> "$FICHEIRO_CUSTODIA"
        log "Metadados vídeos TXT → SHA-256: $HASH_META_VID"
        log "Metadados vídeos CSV → SHA-256: $HASH_META_VID_CSV"
    else
        aviso "Sem vídeos para extrair metadados."
    fi
else
    aviso "ExifTool não instalado. Instalar: sudo apt install libimage-exiftool-perl"
fi
echo ""

# -----------------------------------------------------------------------------
# 6. INFORMAÇÕES DO SISTEMA — SWGDE
# -----------------------------------------------------------------------------
fase "SWGDE — Documentação do ambiente de extracção"
log "--- PASSO 6: Informações do sistema ---"

FICHEIRO_SISTEMA="$DESTINO/info_sistema_$TIMESTAMP.txt"
cat > "$FICHEIRO_SISTEMA" << EOF
=============================================================
INFORMAÇÕES DO SISTEMA — EXAMINATION
Framework NIST + SWGDE
Caso: $CASO
Data/Hora: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
=============================================================
SO (WSL): $(uname -a)
DATA/HORA UTC: $(date -u)

INTERFACES DE REDE:
$(ip addr)

FERRAMENTAS:
  SSH/SCP:   $(ssh -V 2>&1 | head -1)
  ExifTool:  $(exiftool -ver 2>/dev/null || echo "não instalado")
  tshark:    $(tshark --version 2>/dev/null | head -1 || echo "não instalado")
=============================================================
EOF

HASH_SISTEMA=$(sha256sum "$FICHEIRO_SISTEMA" | awk '{print $1}')
echo "Informações do sistema" >> "$FICHEIRO_CUSTODIA"
echo "  SHA-256: $HASH_SISTEMA" >> "$FICHEIRO_CUSTODIA"
echo "" >> "$FICHEIRO_CUSTODIA"
log "Info sistema → SHA-256: $HASH_SISTEMA"
echo ""

# Fechar cadeia de custódia
cat >> "$FICHEIRO_CUSTODIA" << EOF
=============================================================
Data/Hora Fim: $(date '+%Y-%m-%d %H:%M:%S UTC')
SWGDE: Examination concluída. Todos os ficheiros verificados.
Próxima fase: Analysis
=============================================================
EOF

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
log "Vídeos extraídos:   $VIDEO_COUNT"
log "Imagens extraídas:  $IMG_COUNT"
log "Integridade:        $RESULTADO_INTEGRIDADE"
echo ""
log "Estrutura em: $DESTINO"
log "  videos/      → Vídeos do Raspberry Pi"
log "  imagens/     → Imagens do Raspberry Pi"
log "  metadados/   → Metadados ExifTool (TXT + CSV)"
log "  hashes/      → Hashes origem/destino + cadeia de custódia SWGDE"
echo ""
log "Próximo passo: correr analisar_evidencias_fase1.sh (Analysis + Reporting)"
log "=== FIM DA EXAMINATION ==="
