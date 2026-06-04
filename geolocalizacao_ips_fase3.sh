#!/bin/bash
# =============================================================================
# FASE 3: GEOLOCALIZAÇÃO DE IPs — ip-api.com
# Mestrado em Segurança de Informação e Direito no Ciberespaço
# Investigação Forense de Dispositivos na Internet das Coisas
# Framework: NIST Forensics Process Model + SWGDE Best Practices
# Dispositivo: TP-Link Tapo Pan/Tilt Wi-Fi Camera (cloud-connected)
# API: https://ip-api.com (gratuita, sem autenticação, max 45 req/min)
# =============================================================================

# --- CONFIGURAÇÕES ---
BASE="/mnt/i/Mestrado/Tese/Fase3"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- VERIFICA CASO EXISTENTE ---
FICHEIRO_CASO="$BASE/.caso_atual"
if [ -f "$FICHEIRO_CASO" ]; then
    CASO=$(cat "$FICHEIRO_CASO")
    echo "A usar caso existente: $CASO"
else
    echo ""
    echo "Nenhum caso ativo encontrado."
    echo ""
    echo "Casos disponíveis em $BASE:"
    ls "$BASE" | grep "^CASO_" | sort -r | head -10
    echo ""
    read -p "    Introduz o nome do caso (ex: CASO_20260528_232719): " CASO </dev/tty
fi

DESTINO_ANALISE="$BASE/$CASO/analise"
DESTINO_GEO="$DESTINO_ANALISE/geolocalizacao"
mkdir -p "$DESTINO_GEO"

LOG="$DESTINO_GEO/log_geolocalizacao_$TIMESTAMP.txt"

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
geo()   { echo -e "${CIANO}[GEO]${NC} $1" | tee -a "$LOG"; }

# Localiza ficheiro de IPs de destino
FICHEIRO_IPS=$(ls "$DESTINO_ANALISE/rede/ips_destino_"*.txt 2>/dev/null | head -1)
if [ -z "$FICHEIRO_IPS" ]; then
    erro "Ficheiro ips_destino_*.txt nao encontrado em $DESTINO_ANALISE/rede/"
    erro "Corre primeiro analisar_evidencias_fase3.sh"
    exit 1
fi

# =============================================================================
# INÍCIO
# =============================================================================
clear
echo "============================================================"
echo "   FASE 3: GEOLOCALIZAÇÃO DE IPs"
echo "   API: https://ip-api.com"
echo "   Framework NIST + SWGDE | Tapo Pan/Tilt (cloud-connected)"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

fase "NIST - Analysis: Geolocalizacao dos IPs contactados pela camera"
fase "Fonte: ip-api.com (gratuita, sem autenticacao, max 45 req/min)"
echo ""
log "=== INICIO DA GEOLOCALIZACAO ==="
log "Caso:       $CASO"
log "IPs fonte:  $FICHEIRO_IPS"
log "Destino:    $DESTINO_GEO"
echo ""

# Verifica ligação à internet e à API
log "A verificar ligacao a ip-api.com..."
TESTE=$(curl -s --max-time 5 "http://ip-api.com/json/8.8.8.8?fields=status" 2>/dev/null)
if echo "$TESTE" | grep -q '"success"'; then
    log "API ip-api.com acessivel."
else
    erro "Nao foi possivel aceder a ip-api.com."
    erro "Verifica a ligacao a internet e tenta novamente."
    exit 1
fi
echo ""

# Ficheiro de resultados detalhado
FICHEIRO_GEO="$DESTINO_GEO/geolocalizacao_ips_$TIMESTAMP.txt"
cat > "$FICHEIRO_GEO" << EOF
=============================================================
GEOLOCALIZAÇÃO DE IPs — ip-api.com
Framework NIST + SWGDE
Caso: $CASO
Data/Hora: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
Fonte: https://ip-api.com
Nota: IPs privados/reservados nao sao geolocalizaveis
=============================================================

EOF

# Ficheiro CSV para análise posterior
FICHEIRO_CSV="$DESTINO_GEO/geolocalizacao_ips_$TIMESTAMP.csv"
echo "IP,Status,Pais,CodPais,Regiao,Cidade,ISP,Organizacao,ASN,Latitude,Longitude,Fuso,Mandado_Jurisdicao" > "$FICHEIRO_CSV"

# Relatório de geolocalização
RELATORIO_GEO="$DESTINO_GEO/relatorio_geolocalizacao_$CASO.txt"
cat > "$RELATORIO_GEO" << EOF
=============================================================
RELATÓRIO DE GEOLOCALIZAÇÃO DE IPs
Framework NIST Forensics Process Model + SWGDE Best Practices
=============================================================
Caso:        $CASO
Data/Hora:   $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
Dispositivo: TP-Link Tapo Pan/Tilt Wi-Fi Camera
API:         https://ip-api.com
=============================================================

EOF

# =============================================================================
# GEOLOCALIZAÇÃO DE CADA IP
# =============================================================================
fase "A processar IPs do ficheiro: $(basename $FICHEIRO_IPS)"
echo ""

TOTAL_IPS=$(awk 'NF>=2' "$FICHEIRO_IPS" | wc -l)
CONTADOR=0
IPS_UE=0
IPS_FORA_UE=0
IPS_PRIVADOS=0

# Lista de países da UE para verificação de jurisdição
UE_PAISES="AT BE BG CY CZ DE DK EE ES FI FR GR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK"

awk 'NF>=2 {print $2}' "$FICHEIRO_IPS" | while read IP; do
    if [ -z "$IP" ]; then continue; fi

    CONTADOR=$((CONTADOR + 1))
    geo "[$CONTADOR/$TOTAL_IPS] A geolocalizar: $IP"

    # Verifica se é IP privado/reservado
    if echo "$IP" | grep -qE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.|239\.|224\.)"; then
        geo "  -> IP privado/reservado — nao geolocalizavel"

        echo "IP: $IP" >> "$FICHEIRO_GEO"
        echo "  Tipo:   IP privado ou reservado (RFC 1918 / Multicast)" >> "$FICHEIRO_GEO"
        echo "  Nota:   Nao geolocalizavel via API publica" >> "$FICHEIRO_GEO"
        echo "" >> "$FICHEIRO_GEO"

        echo "$IP,privado,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$FICHEIRO_CSV"
        continue
    fi

    # Consulta a API ip-api.com
    # Campos: status,country,countryCode,regionName,city,isp,org,as,lat,lon,timezone,query
    RESPOSTA=$(curl -s --max-time 10 \
        "http://ip-api.com/json/$IP?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,timezone,query" \
        2>/dev/null)

    if [ -z "$RESPOSTA" ]; then
        aviso "  Sem resposta da API para $IP"
        echo "$IP,erro,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A,N/A" >> "$FICHEIRO_CSV"
        sleep 1
        continue
    fi

    # Extrai campos da resposta JSON com python3
    STATUS=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','N/A'))" 2>/dev/null)
    PAIS=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('country','N/A'))" 2>/dev/null)
    COD_PAIS=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('countryCode','N/A'))" 2>/dev/null)
    REGIAO=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('regionName','N/A'))" 2>/dev/null)
    CIDADE=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('city','N/A'))" 2>/dev/null)
    ISP=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('isp','N/A'))" 2>/dev/null)
    ORG=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('org','N/A'))" 2>/dev/null)
    ASN=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('as','N/A'))" 2>/dev/null)
    LAT=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('lat','N/A'))" 2>/dev/null)
    LON=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('lon','N/A'))" 2>/dev/null)
    FUSO=$(echo "$RESPOSTA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('timezone','N/A'))" 2>/dev/null)

    # Determina jurisdição (UE ou fora da UE)
    if echo "$UE_PAISES" | grep -qw "$COD_PAIS"; then
        JURISDICAO="UE — RGPD aplicavel, mandado judicial portugues suficiente"
        IPS_UE=$((IPS_UE + 1))
    else
        JURISDICAO="Fora da UE — pode requerer MLAT"
        IPS_FORA_UE=$((IPS_FORA_UE + 1))
    fi

    # Guarda no ficheiro detalhado
    echo "IP: $IP" >> "$FICHEIRO_GEO"
    echo "  Status:       $STATUS" >> "$FICHEIRO_GEO"
    echo "  Pais:         $PAIS ($COD_PAIS)" >> "$FICHEIRO_GEO"
    echo "  Regiao:       $REGIAO" >> "$FICHEIRO_GEO"
    echo "  Cidade:       $CIDADE" >> "$FICHEIRO_GEO"
    echo "  ISP:          $ISP" >> "$FICHEIRO_GEO"
    echo "  Organizacao:  $ORG" >> "$FICHEIRO_GEO"
    echo "  ASN:          $ASN" >> "$FICHEIRO_GEO"
    echo "  Coordenadas:  $LAT, $LON" >> "$FICHEIRO_GEO"
    echo "  Fuso horario: $FUSO" >> "$FICHEIRO_GEO"
    echo "  Jurisdicao:   $JURISDICAO" >> "$FICHEIRO_GEO"
    echo "" >> "$FICHEIRO_GEO"

    # Guarda no CSV
    echo "$IP,$STATUS,$PAIS,$COD_PAIS,$REGIAO,$CIDADE,$ISP,$ORG,$ASN,$LAT,$LON,$FUSO,$JURISDICAO" >> "$FICHEIRO_CSV"

    # Mostra no terminal
    geo "  Pais:        $PAIS ($COD_PAIS)"
    geo "  Cidade:      $CIDADE, $REGIAO"
    geo "  ISP/Org:     $ORG"
    geo "  Coordenadas: $LAT, $LON"
    geo "  Jurisdicao:  $JURISDICAO"
    echo ""

    # Adiciona ao relatório
    echo "  IP: $IP" >> "$RELATORIO_GEO"
    echo "    Pais:         $PAIS ($COD_PAIS)" >> "$RELATORIO_GEO"
    echo "    Regiao:       $REGIAO / $CIDADE" >> "$RELATORIO_GEO"
    echo "    ISP:          $ISP" >> "$RELATORIO_GEO"
    echo "    Organizacao:  $ORG" >> "$RELATORIO_GEO"
    echo "    ASN:          $ASN" >> "$RELATORIO_GEO"
    echo "    Coordenadas:  $LAT, $LON" >> "$RELATORIO_GEO"
    echo "    Fuso horario: $FUSO" >> "$RELATORIO_GEO"
    echo "    Jurisdicao:   $JURISDICAO" >> "$RELATORIO_GEO"
    echo "" >> "$RELATORIO_GEO"

    # Pausa para respeitar limite da API (45 req/min)
    sleep 1.5
done

# =============================================================================
# SUMÁRIO DE JURISDIÇÕES
# =============================================================================
echo "" >> "$RELATORIO_GEO"
cat >> "$RELATORIO_GEO" << EOF
=============================================================
SUMÁRIO DE JURISDIÇÕES
=============================================================

Nota: A jurisdição determina o tipo de mandado judicial necessário
para solicitar a preservação e divulgação de dados ao fornecedor.

Servidores na UE:
  O RGPD é aplicável. Um mandado judicial emitido por autoridade
  competente portuguesa é suficiente para solicitar dados.
  Contacto: autoridade de proteção de dados do país do servidor.

Servidores fora da UE:
  Pode ser necessário recorrer ao mecanismo de Auxílio Judiciário
  Mútuo Internacional (MLAT) ou a acordos bilaterais existentes.

=============================================================
FIM DO RELATÓRIO DE GEOLOCALIZAÇÃO
$(date '+%Y-%m-%d %H:%M:%S UTC')
=============================================================
EOF

# Hashes de integridade SWGDE
HASH_GEO=$(sha256sum "$FICHEIRO_GEO" | awk '{print $1}')
HASH_CSV=$(sha256sum "$FICHEIRO_CSV" | awk '{print $1}')
HASH_REL=$(sha256sum "$RELATORIO_GEO" | awk '{print $1}')

# Cadeia de custódia
FICHEIRO_CUSTODIA="$DESTINO_GEO/cadeia_custodia_geolocalizacao_$TIMESTAMP.txt"
cat > "$FICHEIRO_CUSTODIA" << EOF
=============================================================
CADEIA DE CUSTÓDIA — GEOLOCALIZAÇÃO
Framework NIST + SWGDE
Caso: $CASO
Data/Hora: $(date '+%Y-%m-%d %H:%M:%S UTC')
Investigador: $(whoami)
API utilizada: https://ip-api.com
=============================================================

[1] Resultados detalhados de geolocalização
    Ficheiro: $(basename $FICHEIRO_GEO)
    SHA-256:  $HASH_GEO

[2] Dados em formato CSV
    Ficheiro: $(basename $FICHEIRO_CSV)
    SHA-256:  $HASH_CSV

[3] Relatório de geolocalização
    Ficheiro: $(basename $RELATORIO_GEO)
    SHA-256:  $HASH_REL

=============================================================
SWGDE: Resultados obtidos via API pública ip-api.com.
Dados preservados com hashes SHA-256 para garantir integridade.
=============================================================
EOF

log "Ficheiro detalhado: $FICHEIRO_GEO"
log "SHA-256: $HASH_GEO"
log "Ficheiro CSV: $FICHEIRO_CSV"
log "SHA-256: $HASH_CSV"
log "Relatorio: $RELATORIO_GEO"
log "SHA-256: $HASH_REL"
echo ""

# =============================================================================
# SUMÁRIO FINAL
# =============================================================================
echo "============================================================"
echo "   GEOLOCALIZAÇÃO CONCLUÍDA — $CASO"
echo "   $(date '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
log "=== SUMÁRIO FINAL ==="
log "Total de IPs processados: $TOTAL_IPS"
echo ""
log "Estrutura em: $DESTINO_GEO"
log "  geolocalizacao_ips_*.txt     -> Resultados detalhados"
log "  geolocalizacao_ips_*.csv     -> Dados em CSV"
log "  relatorio_geolocalizacao_*   -> Relatorio forense"
log "  cadeia_custodia_*            -> Cadeia de custodia SWGDE"
echo ""
log "=== FIM DA GEOLOCALIZAÇÃO ==="
