#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
ROOT_DIR="$(cd "${KIT_DIR}/.." && pwd -P)"

IMAGE="${AUDIT_DOCKER_IMAGE:-owasp-audit:latest}"
PROJECT="${AUDIT_PROJECT:-}"
PRODUCT="${AUDIT_PRODUCT_NAME:-}"
SETTINGS_MODULE="${AUDIT_DJANGO_SETTINGS_MODULE:-}"
DJANGO_PREFIX="${AUDIT_DJANGO_COMMAND_PREFIX:-poetry run python}"
TARGET_URL="${AUDIT_TARGET_URL:-}"
OUTPUT_DIR="${AUDIT_OUTPUT_DIR:-}"
RUN_DAST="${AUDIT_RUN_DAST:-true}"
RUN_ZAP="${AUDIT_RUN_ZAP:-true}"
RUN_NUCLEI="${AUDIT_RUN_NUCLEI:-true}"
RUN_DJANGO_CHECKS="${AUDIT_RUN_DJANGO_CHECKS:-auto}"
RUN_TRUFFLEHOG="${AUDIT_RUN_TRUFFLEHOG:-false}"
DAST_AUTHORIZED="${AUDIT_DAST_AUTHORIZED:-false}"
DD_API_TOKEN="${DD_API_TOKEN:-}"
DD_URL="${DD_URL:-http://localhost:8080}"
SKIP_DD_IMPORT="${SKIP_DD_IMPORT:-false}"
OPEN_DD="${AUDIT_OPEN_DEFECTDOJO:-false}"
BUILD_IMAGE="true"
GENERATE_ONLY="false"

TOOL_N=0
TOOL_TOTAL=0

usage() {
    cat <<'USAGE'
OWASP Django Audit Kit — Runner parametrizable.

Uso:
  bash audit-kit/scripts/run_owasp_audit.sh --project PATH --product NAME [opciones]

Obligatorios:
  --project PATH               Ruta absoluta/relativa al proyecto Django
  --product NAME               Nombre del producto para trazabilidad

Opcionales:
  --settings MODULE            DJANGO_SETTINGS_MODULE para manage.py check --deploy
  --django-command-prefix CMD  Prefijo antes de manage.py (defecto: poetry run python)
  --target URL                 URL staging/prod autorizada para DAST pasivo
  --output DIR                 Directorio de salida (defecto: audit-kit/runs/<slug>-<timestamp>)
  --image NAME                 Imagen Docker toolbox (defecto: owasp-audit:latest)
  --dd-token TOKEN             API token de DefectDojo para auto-importación
  --dd-url URL                 URL de DefectDojo (defecto: http://localhost:8080)
  --skip-dast                  Omitir verificaciones contra el target
  --skip-zap                   Omitir ZAP baseline
  --skip-nuclei                Omitir Nuclei
  --skip-django-checks         Omitir manage.py check y relacionados
  --skip-dd-import             No importar artefactos a DefectDojo al finalizar
  --run-trufflehog             Ejecutar TruffleHog (produce evidencia con secretos)
  --authorize-dast             Confirma autorización explícita para DAST pasivo/no autenticado
  --open-defectdojo            Abrir DefectDojo al finalizar si la importación fue exitosa
  --generate-only              Solo estructura e inventario, sin escáneres
  --no-build                   No reconstruir imagen Docker si no existe
  --help                       Esta ayuda

Las variables de entorno duplican estos flags con prefijo AUDIT_*.
Ver audit-kit/audit.env.example.
USAGE
}

die() {
    printf '\n[ERROR] %s\n' "$1" >&2
    exit 1
}

is_true() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|y|si) return 0 ;;
        *) return 1 ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) PROJECT="$2"; shift 2 ;;
        --product) PRODUCT="$2"; shift 2 ;;
        --settings) SETTINGS_MODULE="$2"; shift 2 ;;
        --django-command-prefix) DJANGO_PREFIX="$2"; shift 2 ;;
        --target) TARGET_URL="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --image) IMAGE="$2"; shift 2 ;;
        --dd-token) DD_API_TOKEN="$2"; shift 2 ;;
        --dd-url) DD_URL="$2"; shift 2 ;;
        --skip-dast) RUN_DAST="false"; shift ;;
        --skip-zap) RUN_ZAP="false"; shift ;;
        --skip-nuclei) RUN_NUCLEI="false"; shift ;;
        --skip-django-checks) RUN_DJANGO_CHECKS="false"; shift ;;
        --skip-dd-import) SKIP_DD_IMPORT="true"; shift ;;
        --run-trufflehog) RUN_TRUFFLEHOG="true"; shift ;;
        --authorize-dast) DAST_AUTHORIZED="true"; shift ;;
        --open-defectdojo) OPEN_DD="true"; shift ;;
        --generate-only) GENERATE_ONLY="true"; shift ;;
        --no-build) BUILD_IMAGE="false"; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "argumento desconocido: $1" ;;
    esac
done

[[ -n "$PROJECT" ]] || die "--project es obligatorio"
[[ -n "$PRODUCT" ]] || die "--product es obligatorio"
[[ -d "$PROJECT" ]] || die "el directorio del proyecto no existe: $PROJECT"

PROJECT="$(cd "$PROJECT" && pwd -P)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SLUG="$(printf '%s' "$PRODUCT" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//;s/-$//')"
[[ -n "$SLUG" ]] || SLUG="django-project"

if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="${KIT_DIR}/runs/${SLUG}-${TIMESTAMP}"
fi
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd -P)"
REPORTS_DIR="${OUTPUT_DIR}/reports"
STATUS_DIR="${REPORTS_DIR}/status"

mkdir -p \
    "${REPORTS_DIR}/F1" "${REPORTS_DIR}/F2" "${REPORTS_DIR}/F3" \
    "${REPORTS_DIR}/F4" "${REPORTS_DIR}/F5" "${REPORTS_DIR}/F6" \
    "${REPORTS_DIR}/F7" "${REPORTS_DIR}/F8" \
    "$STATUS_DIR"

if [[ -d "${KIT_DIR}/runs" ]]; then
    ln -sfn "$(basename "$OUTPUT_DIR")" "${KIT_DIR}/runs/latest"
fi

python3 - "$PROJECT" "$PRODUCT" "$SETTINGS_MODULE" "$TARGET_URL" "$OUTPUT_DIR" "$TIMESTAMP" > "${REPORTS_DIR}/metadata.json" <<'PY'
import json, sys
p = sys.argv[1:]
print(json.dumps({"project":p[0],"product":p[1],"settings_module":p[2],"target_url":p[3],"output_dir":p[4],"timestamp":p[5]},indent=2))
PY

if [[ "$GENERATE_ONLY" == "false" && "$BUILD_IMAGE" == "true" ]]; then
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        printf '\n[build] Compilando toolbox %s...\n' "$IMAGE"
        docker build -t "$IMAGE" "$ROOT_DIR" || die "falló la compilación de la imagen Docker"
    fi
fi

write_status() {
    local name="$1" kind="$2" rc="$3" command="$4"
    local sf="${STATUS_DIR}/${name}.status"
    local lf="${STATUS_DIR}/${name}.log"
    { printf 'tool=%s\nkind=%s\nexit_code=%s\nlog=status/%s.log\ncommand=%s\n' "$name" "$kind" "$rc" "$name" "$command"; } > "$sf"
    [[ -e "$lf" ]] || printf '%s\n' "$command" > "$lf"
}

progress() {
    TOOL_N=$((TOOL_N + 1))
    printf '  [%s/%s] %s ... ' "$TOOL_N" "$TOOL_TOTAL" "$1"
}

progress_done() {
    local rc="$1"
    if [[ "$rc" == "0" ]]; then
        printf 'ok\n'
    elif [[ "$rc" == "1" ]]; then
        printf 'findings\n'
    else
        printf 'exit %s\n' "$rc"
    fi
}

run_toolbox() {
    local name="$1" command="$2" rc
    progress "$name"
    docker run --rm \
        -e "AUDIT_TARGET_URL=${TARGET_URL}" \
        -e "RUFF_CACHE_DIR=/tmp/ruff-cache" \
        -v "${PROJECT}:/workspace/project:ro" \
        -v "${REPORTS_DIR}:/workspace/reports:rw" \
        -w /workspace/project \
        "$IMAGE" -lc "$command" > "${STATUS_DIR}/${name}.log" 2>&1
    rc=$?
    progress_done "$rc"
    write_status "$name" "toolbox" "$rc" "$command"
    return 0
}

run_host() {
    local name="$1" command="$2" rc
    progress "$name"
    bash -lc "$command" > "${STATUS_DIR}/${name}.log" 2>&1
    rc=$?
    progress_done "$rc"
    write_status "$name" "host" "$rc" "$command"
    return 0
}

run_zap() {
    local rc
    progress "zap-baseline"
    docker run --rm \
        -v "${REPORTS_DIR}/F6:/zap/wrk:rw" \
        ghcr.io/zaproxy/zaproxy:stable \
        zap-baseline.py -t "$TARGET_URL" -J zap-baseline.json -x zap-baseline.xml -I \
        > "${STATUS_DIR}/zap-baseline.log" 2>&1
    rc=$?
    progress_done "$rc"
    write_status "zap-baseline" "docker" "$rc" "zap-baseline.py -t ${TARGET_URL}"
    return 0
}

printf '\n═══ OWASP Django Audit Kit ═══\n'
printf 'Producto : %s\n' "$PRODUCT"
printf 'Proyecto : %s\n' "$PROJECT"
printf 'Target   : %s\n' "${TARGET_URL:-no especificado}"
printf 'Salida   : %s\n' "$OUTPUT_DIR"
printf 'DefectDojo: %s\n\n' "${DD_URL}"

if [[ "$GENERATE_ONLY" == "true" ]]; then
    printf 'Modo generate-only. No se ejecutarán escáneres.\n'
    write_status "scanners" "skipped" "0" "generate-only"
else
    TOOL_TOTAL=13
    if [[ "$RUN_TRUFFLEHOG" == "true" ]]; then TOOL_TOTAL=$((TOOL_TOTAL + 1)); fi
    if [[ "$RUN_DJANGO_CHECKS" != "false" && -n "$SETTINGS_MODULE" ]]; then TOOL_TOTAL=$((TOOL_TOTAL + 4)); fi
    if [[ "$RUN_DAST" == "true" && -n "$TARGET_URL" ]] && is_true "$DAST_AUTHORIZED"; then
        TOOL_TOTAL=$((TOOL_TOTAL + 3))
        if [[ "$RUN_ZAP" == "true" ]]; then TOOL_TOTAL=$((TOOL_TOTAL + 1)); fi
        if [[ "$RUN_NUCLEI" == "true" ]]; then TOOL_TOTAL=$((TOOL_TOTAL + 1)); fi
    fi

    printf 'Ejecutando %s herramientas:\n\n' "$TOOL_TOTAL"

    run_toolbox "tool-versions" '(
python --version
bandit --version || true
ruff --version || true
djlint --version || true
semgrep --version || true
pip-audit --version || true
detect-secrets --version || true
checkov --version || true
trivy --version || true
grype version || true
syft version || true
gitleaks version || true
osv-scanner --version || true
sslyze --version || true
wapiti --version || true
arjun --version || true
testssl --version || true
) > /workspace/reports/F1/tool-versions.txt'

    run_toolbox "bandit"           'bandit -r . -f json -o /workspace/reports/F4/bandit.json'
    run_toolbox "ruff-security"    'ruff check --select S --output-format json --no-cache . > /workspace/reports/F4/ruff-security.json'
    run_toolbox "semgrep-django"   'semgrep --config p/python --config p/django --json --output /workspace/reports/F4/semgrep-django.json .'
    run_toolbox "djlint"           'djlint . --profile django --lint > /workspace/reports/F4/djlint.txt || rc=$?; exit ${rc:-0}'
    run_toolbox "detect-secrets"   'detect-secrets scan --all-files --exclude-files "(^|/)(.git|.venv|venv|node_modules|staticfiles|media|audit-kit/runs)/" > /workspace/reports/F4/detect-secrets.json'
    run_toolbox "gitleaks"         'gitleaks dir . --report-format json --report-path /workspace/reports/F4/gitleaks.json --no-banner --redact=20 || rc=$?; [ -f /workspace/reports/F4/gitleaks.json ] || printf "[]\n" > /workspace/reports/F4/gitleaks.json; exit ${rc:-0}'
    run_toolbox "trivy"            'trivy fs --scanners vuln,misconfig --format json --output /workspace/reports/F4/trivy.json .'
    run_toolbox "grype"            'grype dir:. -o json > /workspace/reports/F4/grype.json'
    run_toolbox "syft-sbom"        'syft dir:. -o cyclonedx-json > /workspace/reports/F4/sbom-cyclonedx.json'
    run_toolbox "checkov"          'checkov -d . -o json --quiet > /workspace/reports/F4/checkov.json || rc=$?; [ -s /workspace/reports/F4/checkov.json ] || printf "{\"summary\":{\"passed\":0,\"failed\":0,\"skipped\":0}}\n" > /workspace/reports/F4/checkov.json; exit ${rc:-0}'
    run_toolbox "osv-scanner"      'if [ -f requirements.txt ] || [ -f pyproject.toml ] || [ -f poetry.lock ] || [ -f Pipfile.lock ] || [ -f package-lock.json ] || [ -f pnpm-lock.yaml ] || [ -f yarn.lock ] || [ -f go.mod ] || [ -f Cargo.lock ]; then osv-scanner --format json --output-file /workspace/reports/F4/osv-source.json --recursive . || rc=$?; [ -s /workspace/reports/F4/osv-source.json ] || printf "{\"results\":[]}\n" > /workspace/reports/F4/osv-source.json; exit ${rc:-0}; else printf "{\"results\":[],\"note\":\"No supported dependency manifest found\"}\n" > /workspace/reports/F4/osv-source.json; fi'
    run_toolbox "pip-audit"        'if [ -f requirements.txt ]; then pip-audit -r requirements.txt -f json -o /workspace/reports/F4/pip-audit.json; elif [ -f requirements/production.txt ]; then pip-audit -r requirements/production.txt -f json -o /workspace/reports/F4/pip-audit.json; elif [ -f requirements/base.txt ]; then pip-audit -r requirements/base.txt -f json -o /workspace/reports/F4/pip-audit.json; elif [ -f poetry.lock ]; then pip-audit --locked -f json -o /workspace/reports/F4/pip-audit.json .; else printf "{\"error\":\"No se encontró requirements.txt ni poetry.lock\"}\n" > /workspace/reports/F4/pip-audit.json; fi'

    if [[ "$RUN_TRUFFLEHOG" == "true" ]]; then
        run_toolbox "trufflehog" 'trufflehog filesystem . --json --no-update > /workspace/reports/F4/trufflehog.jsonl'
    else
        printf '  trufflehog: omitido (use --run-trufflehog para ejecutarlo)\n'
        write_status "trufflehog" "skipped" "0" "omitido; use --run-trufflehog"
    fi

    if [[ "$RUN_DJANGO_CHECKS" != "false" && -n "$SETTINGS_MODULE" ]]; then
        Q_PROJECT="$(printf '%q' "$PROJECT")"
        Q_SETTINGS="$(printf '%q' "$SETTINGS_MODULE")"
        run_host "django-check-deploy"   "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py check --deploy"
        run_host "django-check"          "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py check"
        run_host "django-showmigrations" "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py showmigrations --plan"
        run_host "django-show-urls"      "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py show_urls"
    elif [[ "$RUN_DJANGO_CHECKS" != "false" ]]; then
        printf '  django-checks: omitido (no se proporcionó --settings)\n'
        write_status "django-checks" "skipped" "0" "omitido; no DJANGO_SETTINGS_MODULE"
    fi

    if [[ "$RUN_DAST" == "true" && -n "$TARGET_URL" ]] && is_true "$DAST_AUTHORIZED"; then
        run_host "http-headers" "python3 - <<'PY' > '${REPORTS_DIR}/F6/http-headers.txt'
import os, urllib.request
url = os.environ.get('AUDIT_TARGET_URL', '${TARGET_URL}')
req = urllib.request.Request(url, method='HEAD')
sensitive = {'set-cookie', 'cookie', 'authorization', 'proxy-authorization', 'x-api-key', 'api-key'}
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        print('status:', r.status)
        for k, v in r.headers.items():
            if k.lower() in sensitive:
                v = '[REDACTED]'
            print(f'{k}: {v}')
except Exception as exc:
    print(type(exc).__name__, exc)
PY"
        run_toolbox "testssl" 'testssl --warnings batch --jsonfile /workspace/reports/F6/testssl-full.json "$AUDIT_TARGET_URL"'
        run_toolbox "sslyze" 'python - <<'"'"'PY'"'"' > /tmp/sslyze-target
from urllib.parse import urlparse
import os
parsed = urlparse(os.environ["AUDIT_TARGET_URL"])
host = parsed.hostname or os.environ["AUDIT_TARGET_URL"]
port = parsed.port or (443 if parsed.scheme == "https" else 80)
print(f"{host}:{port}")
PY
sslyze --json_out=/workspace/reports/F4/sslyze.json "$(cat /tmp/sslyze-target)"'
        if [[ "$RUN_NUCLEI" == "true" ]]; then
            run_toolbox "nuclei" 'nuclei -u "$AUDIT_TARGET_URL" -jsonl -o /workspace/reports/F6/nuclei-full.jsonl -silent || rc=$?
python - <<'"'"'PY'"'"'
import json
from pathlib import Path
src = Path("/workspace/reports/F6/nuclei-full.jsonl")
dst = Path("/workspace/reports/F6/nuclei-full.json")
items = []
if src.exists():
    for line in src.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            pass
dst.write_text(json.dumps(items, indent=2) + "\n")
PY
exit ${rc:-0}'
        else
            printf '  nuclei: omitido por --skip-nuclei\n'
            write_status "nuclei" "skipped" "0" "omitido por --skip-nuclei"
        fi
        if [[ "$RUN_ZAP" == "true" ]]; then
            run_zap
        else
            printf '  zap-baseline: omitido por --skip-zap\n'
            write_status "zap-baseline" "skipped" "0" "omitido por --skip-zap"
        fi
    elif [[ "$RUN_DAST" == "true" && -n "$TARGET_URL" ]]; then
        printf '  dast: omitido (requiere --authorize-dast para ejecutar pruebas contra el target)\n'
        write_status "dast" "skipped" "0" "omitido; falta autorización DAST explícita"
    else
        printf '  dast: omitido (sin --target o con --skip-dast)\n'
        write_status "dast" "skipped" "0" "omitido; sin --target o --skip-dast"
    fi
fi

printf '\n══════════════════════════════════════\n'
printf 'Resumen de ejecución\n'
printf '────────────────────\n'
for sf in "${STATUS_DIR}"/*.status; do
    [[ -f "$sf" ]] || continue
    name="$(basename "$sf" .status)"
    kind=""; rc=""
    while IFS='=' read -r k v; do
        case "$k" in kind) kind="$v" ;; exit_code) rc="$v" ;; esac
    done < "$sf"
    if [[ "$kind" == "skipped" ]]; then
        printf '  %-28s omitido\n' "$name"
    elif [[ "$rc" == "0" ]]; then
        printf '  %-28s ok\n' "$name"
    elif [[ "$rc" == "1" ]]; then
        printf '  %-28s hallazgos\n' "$name"
    else
        printf '  %-28s error (exit %s)\n' "$name" "$rc"
    fi
done

python3 "${SCRIPT_DIR}/summarize_artifacts.py" "$REPORTS_DIR" || true
AUDIT_DAST_AUTHORIZED="$DAST_AUTHORIZED" \
AUDIT_RUN_ZAP="$RUN_ZAP" \
AUDIT_RUN_NUCLEI="$RUN_NUCLEI" \
AUDIT_RUN_TRUFFLEHOG="$RUN_TRUFFLEHOG" \
SKIP_DD_IMPORT="$SKIP_DD_IMPORT" \
DD_API_TOKEN="$DD_API_TOKEN" \
python3 "${SCRIPT_DIR}/build_evidence_manifest.py" "$REPORTS_DIR" || true

printf '\n══════════════════════════════════════\n'
printf 'Artefactos\n'
printf '────────────────────\n'
for d in F1 F2 F3 F4 F5 F6 F7 F8; do
    count=$(find "${REPORTS_DIR}/${d}" -type f 2>/dev/null | wc -l | tr -d ' ')
    printf '  %s: %s archivos\n' "$d" "$count"
done

if [[ "$SKIP_DD_IMPORT" != "true" && -n "$DD_API_TOKEN" ]]; then
    printf '\n══════════════════════════════════════\n'
    printf 'Importando a DefectDojo (%s)\n' "$DD_URL"
    printf '────────────────────\n'
    if REPORTS_DIR="$REPORTS_DIR" \
        DD_URL="$DD_URL" \
        DD_API_TOKEN="$DD_API_TOKEN" \
        DD_PRODUCT_NAME="$PRODUCT" \
        python3 "${SCRIPT_DIR}/import_defectdojo.py"; then
        DD_IMPORT_OK="true"
        printf 'DefectDojo import status: completado\n'
    else
        DD_IMPORT_OK="false"
        printf 'DefectDojo import status: error\n'
    fi
elif [[ "$SKIP_DD_IMPORT" == "true" ]]; then
    printf '\nImportación a DefectDojo omitida por --skip-dd-import.\n'
else
    printf '\nDefectDojo: omitido. Configure --dd-token o DD_API_TOKEN para importar automáticamente.\n'
fi

if [[ "$SKIP_DD_IMPORT" != "true" && -n "$DD_API_TOKEN" && "${DD_IMPORT_OK:-false}" == "true" ]] && is_true "$OPEN_DD"; then
    printf '\n══════════════════════════════════════\n'
    printf 'Abrir DefectDojo: %s\n' "$DD_URL"
    if command -v open &>/dev/null; then
        open "$DD_URL" 2>/dev/null || true
    elif command -v xdg-open &>/dev/null; then
        xdg-open "$DD_URL" 2>/dev/null || true
    fi
fi

printf '\n══════════════════════════════════════\n'
printf 'Validaciones no automatizables requeridas\n'
printf '────────────────────\n'
cat <<'CHECKLIST'

A01 — Broken Access Control
  □ Verificar permisos a nivel de objeto por rol/tenant (deny by default).
  □ Probar IDOR en endpoints con identificadores incrementales o predecibles.
  □ Validar que usuarios sin privilegios no alcanzan vistas ni APIs de admin.
  □ Revisar CORS: verificar que no permite orígenes arbitrarios con credenciales.
  □ Confirmar que JWT o tokens de sesión se invalidan tras logout.
  □ Verificar ausencia de directory listing y archivos sensibles (.git, .env) en web root.

A02 — Security Misconfiguration
  □ Validar DEBUG=False, ALLOWED_HOSTS restringido, CORS y CSP en producción.
  □ Verificar cabeceras de seguridad HTTP (HSTS, X-Content-Type-Options, etc.).
  □ Inspeccionar Dockerfile (USER no-root, HEALTHCHECK, puertos expuestos mínimos).
  □ Confirmar que no hay cuentas default, puertos innecesarios ni features de debugging.
  □ Revisar permisos de almacenamiento cloud (S3 buckets, ACLs).
  □ Verificar que los mensajes de error no exponen stack traces ni versiones.

A03 — Software Supply Chain Failures
  □ Triar CVEs de pip-audit, OSV Scanner, Trivy y Grype por exposición real en runtime.
  □ Verificar que el SBOM (Syft/CycloneDX) cubre dependencias transitivas.
  □ Confirmar que no hay dependencias de fuentes no oficiales o no firmadas.
  □ Revisar que dependencias abandonadas (unmaintained) tienen plan de migración.
  □ Validar que el pipeline CI/CD tiene separación de deberes y secretos por entorno.
  □ Verificar actualización periódica de tooling de desarrollo (IDE, plugins, runners).

A04 — Cryptographic Failures
  □ Inspeccionar verify=False en clientes HTTP salientes (Bandit B501).
  □ Verificar que no hay HTTP plano en integraciones, webhooks ni APIs internas.
  □ Validar HSTS (max-age, includeSubDomains, preload), cookies Secure/HttpOnly/SameSite.
  □ Confirmar TLS 1.2+ sin cipher suites obsoletas (testssl.sh, SSLyze).
  □ Revisar que no hay secretos hardcodeados en código ni archivos de configuración.
  □ Validar uso de algoritmos criptográficos estándar (no MD5, SHA-1, RC4).

A05 — Injection
  □ Revisar raw SQL, exec, eval, os.system, subprocess con entrada de usuario.
  □ Inspeccionar templates Django: confirmar que no hay |safe sin sanitización previa.
  □ Validar sanitización en importación de archivos CSV, Excel, XLSX.
  □ Revisar inyección en prompts LLM: validar que no hay concatenación directa de input.
  □ Verificar path traversal en rutas de archivos y media.
  □ Confirmar que XML/JSON/YAML parsing no permite entidades externas ni tipos peligrosos.

A06 — Insecure Design
  □ Threat-model sobre flujos críticos: telecontrol, pagos, exportación de datos.
  □ Verificar rate-limiting en login, magic-link, API y restablecimiento de contraseña.
  □ Validar que existen controles de aprobación para acciones destructivas.
  □ Revisar que los límites de negocio (montos, frecuencia, roles) se validan en servidor.
  □ Confirmar que no hay confianza implícita en datos del cliente (frontend validation only).

A07 — Authentication Failures
  □ Verificar disponibilidad de MFA para cuentas admin, telecontrol y roles privilegiados.
  □ Validar rotación de sesión post-login y expiración razonable de cookies.
  □ Revisar lockout tras intentos fallidos y protección contra enumeración de usuarios.
  □ Confirmar que magic-link y restablecimiento de contraseña usan tokens de un solo uso.
  □ Verificar que OAuth/OIDC/SAML validan audiencia, issuer y firma de tokens.

A08 — Software or Data Integrity Failures
  □ Revisar serialización insegura: pickle, yaml.load, marshal.
  □ Validar que los archivos subidos tienen validación de tipo, tamaño y contenido.
  □ Confirmar procedencia de dependencias (pip hash checking, poetry lock).
  □ Verificar integridad de artefactos en CI/CD (firmado, immutabilidad, promoción).
  □ Revisar que actualizaciones automáticas no introducen código no revisado.

A09 — Security Logging and Alerting Failures
  □ Confirmar que login, logout, cambios de privilegio y acciones admin generan log.
  □ Verificar que los logs NO contienen secretos, tokens ni datos personales completos.
  □ Validar que existen alertas para eventos de seguridad (force browsing, lockout, errores 500).
  □ Revisar retención de logs, formato estructurado (JSON) y envío a SIEM si aplica.
  □ Confirmar que los logs incluyen actor, acción, timestamp, IP y resultado.

A10 — Mishandling of Exceptional Conditions
  □ Revisar que la aplicación falla cerrado (fail closed), no abierto, en transacciones.
  □ Verificar que excepciones no filtran datos sensibles en respuestas HTTP.
  □ Confirmar que hay páginas de error personalizadas (404, 500) sin información de debug.
  □ Validar que timeouts, rate-limiting y quotas previenen condiciones excepcionales.
  □ Revisar que operaciones multi-paso (transacciones, workflows) tienen rollback atómico.
  □ Verificar manejo de recursos: uploads, conexiones, archivos temporales.

CHECKLIST

printf '\nFinalizado.\n'
printf 'Artefactos crudos: %s\n' "$REPORTS_DIR"
