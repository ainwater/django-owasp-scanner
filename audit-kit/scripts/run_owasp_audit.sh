#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
KIT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
ROOT_DIR="$(cd "${KIT_DIR}/.." && pwd -P)"
SEMGREP_RULES="audit-kit/semgrep/django-drf.yml"
source "${SCRIPT_DIR}/manual_evidence.sh"

IMAGE="${AUDIT_DOCKER_IMAGE:-owasp-audit:latest}"
PROJECT="${AUDIT_PROJECT:-}"
PRODUCT="${AUDIT_PRODUCT_NAME:-}"
SETTINGS_MODULE="${AUDIT_DJANGO_SETTINGS_MODULE:-}"
DJANGO_PREFIX="${AUDIT_DJANGO_COMMAND_PREFIX:-poetry run python}"
AUTHZ_MATRIX="${AUDIT_AUTHZ_MATRIX:-}"
IDOR_REVIEW="${AUDIT_IDOR_REVIEW:-}"
SESSION_REVIEW="${AUDIT_SESSION_REVIEW:-}"
TARGET_URL="${AUDIT_TARGET_URL:-}"
OPENAPI_SPEC="${AUDIT_OPENAPI_SPEC:-}"
API_BASE_URL="${AUDIT_API_BASE_URL:-}"
AUTH_HEADER_NAME="${AUDIT_AUTH_HEADER_NAME:-}"
AUTH_HEADER_VALUE="${AUDIT_AUTH_HEADER_VALUE:-}"
API_FUZZING_REVIEW="${AUDIT_API_FUZZING_REVIEW:-}"
SCHEMATHESIS_MAX_EXAMPLES="${AUDIT_SCHEMATHESIS_MAX_EXAMPLES:-0}"
OUTPUT_DIR="${AUDIT_OUTPUT_DIR:-}"
RUN_DAST="${AUDIT_RUN_DAST:-true}"
RUN_ZAP="${AUDIT_RUN_ZAP:-true}"
RUN_NUCLEI="${AUDIT_RUN_NUCLEI:-true}"
RUN_DJANGO_CHECKS="${AUDIT_RUN_DJANGO_CHECKS:-auto}"
RUN_TRUFFLEHOG="${AUDIT_RUN_TRUFFLEHOG:-false}"
COVERAGE_THRESHOLD="${AUDIT_COVERAGE_THRESHOLD:-80}"
DAST_AUTHORIZED="${AUDIT_DAST_AUTHORIZED:-false}"
ACTIVE_DAST_AUTHORIZED="${AUDIT_ACTIVE_DAST_AUTHORIZED:-false}"
DRY_RUN="${AUDIT_DRY_RUN:-false}"
DD_API_TOKEN="${DD_API_TOKEN:-}"
DD_URL="${DD_URL:-http://localhost:8080}"
SKIP_DD_IMPORT="${SKIP_DD_IMPORT:-false}"
OPEN_DD="${AUDIT_OPEN_DEFECTDOJO:-false}"
BUILD_IMAGE="true"
GENERATE_ONLY="false"

TOOL_N=0
TOOL_TOTAL=0
django_rc=0
web_policies_rc=0

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
  --django-command-prefix CMD  Prefijo seguro antes de manage.py, sin operadores de shell
  --authz-matrix PATH          Matriz A01 rol/tenant/objeto con resultados esperados/observados
  --idor-review PATH           Revision manual IDOR/A01 validada por el auditor
  --session-review PATH        Revision JSON de logout, rotacion, enumeracion, MFA y brute force
  --target URL                 URL staging/prod autorizada para DAST pasivo
  --openapi-spec PATH          Especificación OpenAPI privada para fuzzing autenticado
  --api-base-url URL           Base URL autenticada para APIs
  --auth-header-name NAME      Nombre del header de autenticación
  --auth-header-value VALUE    Valor del header de autenticación (no se persiste)
  --api-fuzzing-review PATH    Resultado JSON privado de Schemathesis/API fuzzing
  --schemathesis-max-examples N Numero de ejemplos activos; requiere --authorize-active-dast
  --output DIR                 Directorio de salida (defecto: audit-kit/runs/<slug>-<timestamp>)
  --image NAME                 Imagen Docker toolbox (defecto: owasp-audit:latest)
  --dd-token TOKEN             API token de DefectDojo para auto-importación
  --dd-url URL                 URL de DefectDojo (defecto: http://localhost:8080)
  --skip-dast                  Omitir verificaciones contra el target
  --skip-zap                   Omitir ZAP baseline
  --skip-nuclei                Omitir Nuclei
  --skip-django-checks         Omitir introspección Django y manage.py checks
  --skip-dd-import             No importar artefactos a DefectDojo al finalizar
  --run-trufflehog             Ejecutar TruffleHog (produce evidencia con secretos)
  --coverage-threshold N       Umbral minimo de cobertura requerida (0-100, defecto: 80)
  --authorize-dast             Confirma autorización explícita para DAST pasivo/no autenticado
  --authorize-active-dast      Confirma autorización explícita para DAST activo (mutaciones)
  --open-defectdojo            Abrir DefectDojo al finalizar si la importación fue exitosa
  --generate-only              Solo estructura e inventario, sin escáneres
  --no-build                   No reconstruir imagen Docker si no existe
  --dry-run                    Ejecuta solo verificaciones de alistamiento (sin escáneres)
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

resolve_evidence_path() {
    local raw_path="$1" missing_message="$2"
    [[ -f "$raw_path" ]] || die "${missing_message}: $raw_path"
    local normalized_path resolved_path
    normalized_path="$(cd "$(dirname -- "$raw_path")" && pwd -P)/$(basename -- "$raw_path")"
    resolved_path="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$normalized_path")"
    case "$resolved_path" in
        "${KIT_DIR}/templates/"*) die "no uses templates del audit kit como evidencia: $normalized_path" ;;
    esac
    printf '%s\n' "$normalized_path"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) [[ $# -ge 2 ]] || die "--project requiere PATH"; PROJECT="$2"; shift 2 ;;
        --product) [[ $# -ge 2 ]] || die "--product requiere NAME"; PRODUCT="$2"; shift 2 ;;
        --settings) [[ $# -ge 2 ]] || die "--settings requiere MODULE"; SETTINGS_MODULE="$2"; shift 2 ;;
        --django-command-prefix) [[ $# -ge 2 ]] || die "--django-command-prefix requiere CMD"; DJANGO_PREFIX="$2"; shift 2 ;;
        --authz-matrix) [[ $# -ge 2 ]] || die "--authz-matrix requiere PATH"; AUTHZ_MATRIX="$2"; shift 2 ;;
        --idor-review) [[ $# -ge 2 ]] || die "--idor-review requiere PATH"; IDOR_REVIEW="$2"; shift 2 ;;
        --session-review) [[ $# -ge 2 ]] || die "--session-review requiere PATH"; SESSION_REVIEW="$2"; shift 2 ;;
        --target) [[ $# -ge 2 ]] || die "--target requiere URL"; TARGET_URL="$2"; shift 2 ;;
        --openapi-spec) [[ $# -ge 2 ]] || die "--openapi-spec requiere PATH"; OPENAPI_SPEC="$2"; shift 2 ;;
        --api-base-url) [[ $# -ge 2 ]] || die "--api-base-url requiere URL"; API_BASE_URL="$2"; shift 2 ;;
        --auth-header-name) [[ $# -ge 2 ]] || die "--auth-header-name requiere NAME"; AUTH_HEADER_NAME="$2"; shift 2 ;;
        --auth-header-value) [[ $# -ge 2 ]] || die "--auth-header-value requiere VALUE"; AUTH_HEADER_VALUE="$2"; shift 2 ;;
        --api-fuzzing-review) [[ $# -ge 2 ]] || die "--api-fuzzing-review requiere PATH"; API_FUZZING_REVIEW="$2"; shift 2 ;;
        --schemathesis-max-examples) [[ $# -ge 2 ]] || die "--schemathesis-max-examples requiere N"; SCHEMATHESIS_MAX_EXAMPLES="$2"; shift 2 ;;
        --output) [[ $# -ge 2 ]] || die "--output requiere DIR"; OUTPUT_DIR="$2"; shift 2 ;;
        --image) [[ $# -ge 2 ]] || die "--image requiere NAME"; IMAGE="$2"; shift 2 ;;
        --dd-token) [[ $# -ge 2 ]] || die "--dd-token requiere TOKEN"; DD_API_TOKEN="$2"; shift 2 ;;
        --dd-url) [[ $# -ge 2 ]] || die "--dd-url requiere URL"; DD_URL="$2"; shift 2 ;;
        --skip-dast) RUN_DAST="false"; shift ;;
        --skip-zap) RUN_ZAP="false"; shift ;;
        --skip-nuclei) RUN_NUCLEI="false"; shift ;;
        --skip-django-checks) RUN_DJANGO_CHECKS="false"; shift ;;
        --skip-dd-import) SKIP_DD_IMPORT="true"; shift ;;
        --run-trufflehog) RUN_TRUFFLEHOG="true"; shift ;;
        --coverage-threshold) [[ $# -ge 2 ]] || die "--coverage-threshold requiere N"; COVERAGE_THRESHOLD="$2"; shift 2 ;;
        --authorize-dast) DAST_AUTHORIZED="true"; shift ;;
        --authorize-active-dast) ACTIVE_DAST_AUTHORIZED="true"; shift ;;
        --open-defectdojo) OPEN_DD="true"; shift ;;
        --generate-only) GENERATE_ONLY="true"; shift ;;
        --no-build) BUILD_IMAGE="false"; shift ;;
        --dry-run) DRY_RUN="true"; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "argumento desconocido: $1" ;;
    esac
done

[[ -n "$PROJECT" ]] || die "--project es obligatorio"
[[ -n "$PRODUCT" ]] || die "--product es obligatorio"
[[ -d "$PROJECT" ]] || die "el directorio del proyecto no existe: $PROJECT"
if [[ -n "$AUTHZ_MATRIX" ]]; then
    AUTHZ_MATRIX="$(resolve_evidence_path "$AUTHZ_MATRIX" "la matriz de autorización no existe")"
fi
if [[ -n "$IDOR_REVIEW" ]]; then
    IDOR_REVIEW="$(resolve_evidence_path "$IDOR_REVIEW" "la revisión IDOR no existe")"
fi
if [[ -n "$SESSION_REVIEW" ]]; then
    SESSION_REVIEW="$(resolve_evidence_path "$SESSION_REVIEW" "la revisión de sesión no existe")"
fi
if [[ -n "$OPENAPI_SPEC" ]]; then
    OPENAPI_SPEC="$(resolve_evidence_path "$OPENAPI_SPEC" "la especificación OpenAPI no existe")"
fi
if [[ -n "$API_FUZZING_REVIEW" ]]; then
    API_FUZZING_REVIEW="$(resolve_evidence_path "$API_FUZZING_REVIEW" "la revisión de API fuzzing no existe")"
fi
[[ "$SCHEMATHESIS_MAX_EXAMPLES" =~ ^[0-9]+$ ]] || die "--schemathesis-max-examples debe ser entero mayor o igual a 0"
if has_pr5_configuration; then
    is_true "$DAST_AUTHORIZED" || die "PR5 requiere --authorize-dast para DAST/API fuzzing autenticado"
fi
if (( 10#$SCHEMATHESIS_MAX_EXAMPLES > 0 )); then
    is_true "$DAST_AUTHORIZED" || die "PR5 requiere --authorize-dast para DAST/API fuzzing autenticado"
    is_true "$ACTIVE_DAST_AUTHORIZED" || die "fuzzing activo requiere --authorize-active-dast"
fi
if has_api_fuzzing_review; then
    api_fuzz_active_dast="$(api_fuzzing_review_requires_active_dast)"
    if [[ "$api_fuzz_active_dast" == "true" ]]; then
        is_true "$ACTIVE_DAST_AUTHORIZED" || die "api-fuzzing-review con active_dast=true requiere --authorize-active-dast"
    fi
fi
[[ "$COVERAGE_THRESHOLD" =~ ^[0-9]+$ ]] || die "--coverage-threshold debe ser entero entre 0 y 100"
COVERAGE_THRESHOLD_NUM=$((10#$COVERAGE_THRESHOLD))
(( COVERAGE_THRESHOLD_NUM >= 0 && COVERAGE_THRESHOLD_NUM <= 100 )) || die "--coverage-threshold debe estar entre 0 y 100"
COVERAGE_THRESHOLD="$COVERAGE_THRESHOLD_NUM"
case "$DJANGO_PREFIX" in
    *[!A-Za-z0-9_./\ -]*) die "--django-command-prefix contiene caracteres no permitidos" ;;
esac

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

if [[ "$DRY_RUN" != "true" && "$GENERATE_ONLY" == "false" && "$BUILD_IMAGE" == "true" ]]; then
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

print_execution_summary() {
    printf '\n══════════════════════════════════════\n'
    printf 'Resumen de ejecución\n'
    printf '────────────────────\n'
    local sf name kind rc k v
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

should_run_django() {
    [[ "$RUN_DJANGO_CHECKS" != "false" && -n "$SETTINGS_MODULE" ]]
}

run_toolbox() {
    local name="$1" command="$2" rc
    progress "$name"
    docker run --rm \
        -e "AUDIT_TARGET_URL=${TARGET_URL}" \
        -e "RUFF_CACHE_DIR=/tmp/ruff-cache" \
        -v "${PROJECT}:/workspace/project:ro" \
        -v "${KIT_DIR}/semgrep:/workspace/audit-kit-semgrep:ro" \
        -v "${REPORTS_DIR}:/workspace/reports:rw" \
        -w /workspace/project \
        "$IMAGE" -lc "$command" > "${STATUS_DIR}/${name}.log" 2>&1
    rc=$?
    progress_done "$rc"
    write_status "$name" "toolbox" "$rc" "$command"
    return 0
}

run_host() {
    local name="$1" command="$2" status_command="${3:-$1 (sanitized; see status/$1.log)}" rc
    local log_path tmp_log
    log_path="${STATUS_DIR}/${name}.log"
    progress "$name"
    bash -lc "$command" > "$log_path" 2>&1
    rc=$?
    tmp_log="${log_path}.tmp"
    { printf 'command=%s\n' "$status_command"; cat "$log_path"; } > "$tmp_log"
    mv "$tmp_log" "$log_path"
    progress_done "$rc"
    write_status "$name" "host" "$rc" "$status_command"
    return "$rc"
}

update_final_rc() {
    local candidate="$1"
    if [[ "$final_rc" == "0" && "$candidate" != "0" ]]; then
        final_rc="$candidate"
    fi
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

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

print_host_status() {
    local docker_bin="MISSING" docker_daemon="MISSING" image_status="MISSING" py_status="MISSING" requests_status="MISSING" out_status="MISSING"

    if has_cmd docker; then
        docker_bin="READY"
        if docker info >/dev/null 2>&1; then
            docker_daemon="READY"
            if docker image inspect "$IMAGE" >/dev/null 2>&1; then
                image_status="READY"
            else
                image_status="CONFIGURING"
            fi
        else
            docker_daemon="MISSING"
        fi
    fi

    if has_cmd python3; then
        local py_out
        py_out=$(python3 - <<'PY'
import sys
try:
    import requests  # noqa: F401
    req = "READY"
except Exception:
    req = "MISSING"
ver = sys.version_info
ver_ok = "READY" if (ver.major, ver.minor) >= (3, 12) else "MISSING"
print(f"{ver_ok},{req}")
PY
)
        py_status="${py_out%%,*}"
        requests_status="${py_out##*,}"
    fi

    if [[ -w "$OUTPUT_DIR" ]]; then
        out_status="READY"
    elif [[ -d "$OUTPUT_DIR" ]]; then
        out_status="CONFIGURING"
    fi

    printf 'Host/tooling:\n'
    printf '  docker client : %s\n' "$docker_bin"
    printf '  docker daemon : %s\n' "$docker_daemon"
    printf '  docker image  : %s (%s)\n' "$image_status" "$IMAGE"
    printf '  python>=3.12  : %s\n' "$py_status"
    printf '  python requests: %s\n' "$requests_status"
    printf '  output writable: %s\n' "$out_status"
}

run_dry_run() {
    local rows=()
    local plan=()

    local project_exists="MISSING" manage_py="MISSING" settings_arg="MISSING" docker_ready="MISSING" image_ready="MISSING" model_ready="MISSING" schema_ready="MISSING" output_ready="MISSING"
    [[ -d "$PROJECT" ]] && project_exists="READY"
    [[ -f "$PROJECT/manage.py" ]] && manage_py="READY"
    [[ -n "$SETTINGS_MODULE" ]] && settings_arg="READY"
    if has_cmd docker && docker info >/dev/null 2>&1; then docker_ready="READY"; fi
    if [[ "$docker_ready" == "READY" ]] && docker image inspect "$IMAGE" >/dev/null 2>&1; then image_ready="READY"; else [[ "$docker_ready" == "READY" ]] && image_ready="CONFIGURING"; fi

    if has_cmd python3; then
        python_ready=$(python3 - <<'PY'
import sys
v = sys.version_info
print("READY" if (v.major, v.minor) >= (3, 12) else "MISSING")
PY
)
    fi
    [[ -f "${KIT_DIR}/owasp-top10-2025.json" ]] && model_ready="READY"
    [[ -f "${KIT_DIR}/evidence-schema.json" ]] && schema_ready="READY"
    [[ -w "$OUTPUT_DIR" ]] && output_ready="READY"

    local dast_target="MISSING" dast_auth="MISSING"
    [[ -n "$TARGET_URL" ]] && dast_target="READY"
    is_true "$DAST_AUTHORIZED" && dast_auth="READY"

    add_item() {
        rows+=("$1|$2|$3")
    }

    local cov_status="READY" cov_hint="-"
    if ! [[ "$model_ready" == READY && "$schema_ready" == READY && "$output_ready" == READY ]]; then
        cov_status="MISSING"
        cov_hint="need model+schema+output dir"
    fi
    add_item "1 Coverage Engine" "$cov_status" "$cov_hint"

    local intro_status="MISSING" intro_hint="manage.py not found"
    if [[ "$RUN_DJANGO_CHECKS" == "false" ]]; then intro_status="SKIPPED"; intro_hint="--skip-django-checks";
    elif [[ "$manage_py" == READY && "$settings_arg" == READY ]]; then intro_status="READY"; intro_hint="-";
    elif [[ "$manage_py" == READY ]]; then intro_status="CONFIGURING"; intro_hint="add --settings"; fi
    add_item "2 Django Introspection" "$intro_status" "$intro_hint"

    local sast_status="MISSING" sast_hint="docker unavailable"
    if [[ "$docker_ready" == READY ]]; then
        if [[ "$image_ready" == READY ]]; then sast_status="READY"; sast_hint="-"
        else sast_status="CONFIGURING"; sast_hint="build image $IMAGE"; fi
    fi
    add_item "3 Custom SAST Rules" "$sast_status" "$sast_hint"

    local authz_info authz_status authz_hint
    authz_info="$(manual_evidence_readiness authz "$output_ready")"
    IFS='|' read -r authz_status authz_hint <<<"$authz_info"
    local pr4_status="MISSING" pr4_hint="add --authz-matrix, --idor-review, --session-review"

    local idor_info idor_status idor_hint
    idor_info="$(manual_evidence_readiness idor "$output_ready")"
    IFS='|' read -r idor_status idor_hint <<<"$idor_info"

    local session_info session_status session_hint
    session_info="$(manual_evidence_readiness session "$output_ready")"
    IFS='|' read -r session_status session_hint <<<"$session_info"
    if [[ "$authz_status" == READY && "$idor_status" == READY && "$session_status" == READY ]]; then
        pr4_status="READY"; pr4_hint="-"
    elif [[ "$output_ready" == READY ]]; then
        pr4_status="CONFIGURING"
    fi
    add_item "4 Authz & Session" "$pr4_status" "$pr4_hint"
    add_item "4a A01 Authz Matrix" "$authz_status" "$authz_hint"
    add_item "4b A01 IDOR Review" "$idor_status" "$idor_hint"
    add_item "4c A01 Session Security" "$session_status" "$session_hint"

    local dast_status="MISSING" dast_hint="set --target and --authorize-dast"
    if [[ "$dast_target" == READY && "$dast_auth" == READY ]]; then
        dast_status="READY"; dast_hint="target: ${TARGET_URL}"
    elif [[ "$dast_target" == READY ]]; then
        dast_status="CONFIGURING"; dast_hint="add --authorize-dast"
    fi
    add_item "5 DAST Auth & API Fuzzing" "$dast_status" "$dast_hint"

    local api_fuzz_info api_fuzz_status api_fuzz_hint
    api_fuzz_info="$(manual_evidence_readiness api_fuzzing "$output_ready")"
    IFS='|' read -r api_fuzz_status api_fuzz_hint <<<"$api_fuzz_info"
    add_item "5a API Fuzzing" "$api_fuzz_status" "$api_fuzz_hint"

    local headers_status="$dast_status" headers_hint="$dast_hint"
    add_item "6 Headers & Web Policies" "$headers_status" "$headers_hint"

    add_item "7 Logging & Resilience" "$( [[ "$manage_py" == READY ]] && echo CONFIGURING || echo MISSING )" "add logs/errors evidence"

    add_item "8 Threat Model & Uploads" "$( [[ "$manage_py" == READY ]] && echo CONFIGURING || echo MISSING )" "add threat/upload evidence"

    local supply_status="MISSING" supply_hint="docker unavailable"
    if [[ "$docker_ready" == READY ]]; then
        if [[ "$image_ready" == READY ]]; then supply_status="READY"; supply_hint="-"
        else supply_status="CONFIGURING"; supply_hint="build image $IMAGE"; fi
    fi
    add_item "9 Supply Chain & DD" "$supply_status" "$supply_hint"

    local dd_status="MISSING" dd_hint="import_defectdojo.py missing"
    if [[ -f "${SCRIPT_DIR}/import_defectdojo.py" ]]; then
        if [[ -n "$DD_API_TOKEN" ]]; then dd_status="READY"; dd_hint="-"
        else dd_status="CONFIGURING"; dd_hint="set DD_API_TOKEN or --dd-token"; fi
    fi
    add_item "9a DefectDojo Import" "$dd_status" "$dd_hint"

    add_item "10 Final Report" "$( [[ "$manage_py" == READY ]] && echo CONFIGURING || echo MISSING )" "add final report generator"

    plan+=("tool-versions (toolbox)")
    plan+=("bandit (toolbox)")
    plan+=("ruff-security (toolbox)")
    plan+=("semgrep-django (toolbox: ${SEMGREP_RULES})")
    plan+=("djlint (toolbox)")
    plan+=("detect-secrets (toolbox)")
    plan+=("gitleaks (toolbox)")
    plan+=("trivy (toolbox)")
    plan+=("grype (toolbox)")
    plan+=("syft-sbom (toolbox)")
    plan+=("checkov (toolbox)")
    plan+=("osv-scanner (toolbox)")
    plan+=("pip-audit (toolbox)")
    if [[ "$RUN_TRUFFLEHOG" == "true" ]]; then
        plan+=("trufflehog (toolbox)")
    fi
    if should_run_django; then
        plan+=("django-introspection (host)")
        plan+=("django-check-deploy (host)")
        plan+=("django-check (host)")
        plan+=("django-showmigrations (host)")
        plan+=("django-show-urls (host)")
    fi
    local manual_key
    while IFS= read -r manual_key; do
        if manual_evidence_enabled "$manual_key"; then
            plan+=("$(manual_evidence_plan_label "$manual_key")")
        fi
    done < <(manual_evidence_keys)
    if [[ "$RUN_DAST" == "true" && -n "$TARGET_URL" ]] && is_true "$DAST_AUTHORIZED"; then
        plan+=("http-headers (host)")
        plan+=("web-policies (host)")
        plan+=("testssl (toolbox)")
        plan+=("sslyze (toolbox)")
        if [[ "$RUN_NUCLEI" == "true" ]]; then plan+=("nuclei (toolbox)"); fi
        if [[ "$RUN_ZAP" == "true" ]]; then plan+=("zap-baseline (docker)"); fi
    fi
    if [[ "$SKIP_DD_IMPORT" != "true" && -n "$DD_API_TOKEN" ]]; then
        plan+=("import_defectdojo (host)")
    fi
    plan+=("coverage-gates threshold=${COVERAGE_THRESHOLD} (host)")

    print_host_status

    printf '\nReadiness (ready/configuring/missing)\n'
    printf '  %-26s %-12s %s\n' "Item" "Status" "Hint"
    printf '  %s\n' "---------------------------------------------------------------"
    local row
    for row in "${rows[@]}"; do
        IFS='|' read -r item status hint <<<"$row"
        [[ -z "$hint" ]] && hint="-"
        printf '  %-26s %-12s %s\n' "$item" "$status" "$hint"
    done

    printf '\nPlanned tool sequence (would run on full run):\n'
    if [[ ${#plan[@]} -eq 0 ]]; then
        printf '  (no tools scheduled under current flags)\n'
    else
        local p
        for p in "${plan[@]}"; do
            printf '  - %s\n' "$p"
        done
    fi

    printf '\nUsage examples:\n'
    printf '  ./audit-kit/scripts/run_owasp_audit.sh --project /abs/path --product "Name" --dry-run\n'
    printf '  ./audit-kit/scripts/run_owasp_audit.sh --project /abs/path --product "Name" --settings config.settings --django-command-prefix "poetry run python" --dry-run\n'
    printf '  ./audit-kit/scripts/run_owasp_audit.sh --project /abs/path --product "Name" --target https://staging.example.com --authorize-dast --dry-run\n'
    exit 0
}

if is_true "$DRY_RUN"; then
    run_dry_run
fi

printf '\n═══ OWASP Django Audit Kit ═══\n'
printf 'Producto : %s\n' "$PRODUCT"
printf 'Proyecto : %s\n' "$PROJECT"
printf 'Target   : %s\n' "${TARGET_URL:-no especificado}"
printf 'Salida   : %s\n' "$OUTPUT_DIR"
printf 'Coverage threshold : %s%%\n' "$COVERAGE_THRESHOLD"
printf 'DefectDojo: %s\n\n' "${DD_URL}"

if [[ "$GENERATE_ONLY" == "true" ]]; then
    printf 'Modo generate-only. No se ejecutarán escáneres.\n'
    write_status "scanners" "skipped" "0" "generate-only"
    if should_run_django; then TOOL_TOTAL=$((TOOL_TOTAL + 1)); fi
    while IFS= read -r manual_key; do
        if manual_evidence_enabled "$manual_key"; then TOOL_TOTAL=$((TOOL_TOTAL + 1)); fi
    done < <(manual_evidence_keys)
else
    TOOL_TOTAL=13
    if [[ "$RUN_TRUFFLEHOG" == "true" ]]; then TOOL_TOTAL=$((TOOL_TOTAL + 1)); fi
    if should_run_django; then TOOL_TOTAL=$((TOOL_TOTAL + 5)); fi
    while IFS= read -r manual_key; do
        if manual_evidence_enabled "$manual_key"; then TOOL_TOTAL=$((TOOL_TOTAL + 1)); fi
    done < <(manual_evidence_keys)
    if [[ "$RUN_DAST" == "true" && -n "$TARGET_URL" ]] && is_true "$DAST_AUTHORIZED"; then
        TOOL_TOTAL=$((TOOL_TOTAL + 4))
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
    run_toolbox "semgrep-django"   'semgrep --config p/python --config p/django --config /workspace/audit-kit-semgrep/django-drf.yml --json --output /workspace/reports/F4/semgrep-django.json .'
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

    if should_run_django; then
        Q_PROJECT="$(printf '%q' "$PROJECT")"
        Q_SETTINGS="$(printf '%q' "$SETTINGS_MODULE")"
        run_host "django-check-deploy"   "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py check --deploy"; rc=$?; [[ "$django_rc" == "0" && "$rc" != "0" ]] && django_rc="$rc"
        run_host "django-check"          "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py check"; rc=$?; [[ "$django_rc" == "0" && "$rc" != "0" ]] && django_rc="$rc"
        run_host "django-showmigrations" "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py showmigrations --plan"; rc=$?; [[ "$django_rc" == "0" && "$rc" != "0" ]] && django_rc="$rc"
        run_host "django-show-urls"      "cd ${Q_PROJECT} && export DJANGO_SETTINGS_MODULE=${Q_SETTINGS} && ${DJANGO_PREFIX} manage.py show_urls"; rc=$?; [[ "$django_rc" == "0" && "$rc" != "0" ]] && django_rc="$rc"
    elif [[ "$RUN_DJANGO_CHECKS" != "false" ]]; then
        printf '  django-checks: omitido (no se proporcionó --settings)\n'
        write_status "django-checks" "skipped" "0" "omitido; no DJANGO_SETTINGS_MODULE"
    fi

    if [[ "$RUN_DAST" == "true" && -n "$TARGET_URL" ]] && is_true "$DAST_AUTHORIZED"; then
        run_host "http-headers" "AUDIT_TARGET_URL=$(printf '%q' "$TARGET_URL") python3 - <<'PY' > '${REPORTS_DIR}/F6/http-headers.txt'
import os, urllib.request
url = os.environ['AUDIT_TARGET_URL']
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
        run_host "web-policies" "python3 $(printf '%q' "${SCRIPT_DIR}/http_headers.py") $(printf '%q' "$TARGET_URL") $(printf '%q' "${REPORTS_DIR}/F6/http-headers.txt") $(printf '%q' "$REPORTS_DIR")"
        web_policies_rc="$?"
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

if should_run_django; then
    Q_PROJECT="$(printf '%q' "$PROJECT")"
    Q_SETTINGS="$(printf '%q' "$SETTINGS_MODULE")"
    Q_REPORTS="$(printf '%q' "$REPORTS_DIR")"
    Q_INTROSPECT="$(printf '%q' "${SCRIPT_DIR}/django_introspection.py")"
    run_host "django-introspection" "cd ${Q_PROJECT} && ${DJANGO_PREFIX} ${Q_INTROSPECT} ${Q_PROJECT} ${Q_SETTINGS} ${Q_REPORTS}"
    introspection_rc="$?"
else
    printf '  django-introspection: omitido (sin --settings o --skip-django-checks)\n'
    write_status "django-introspection" "skipped" "0" "omitido; sin --settings o --skip-django-checks"
    introspection_rc="0"
fi

authz_rc="0"
idor_rc="0"
session_rc="0"
api_fuzz_rc="0"
while IFS= read -r manual_key; do
    run_or_skip_manual_evidence "$manual_key"
    rc="$?"
    case "$manual_key" in
        authz) authz_rc="$rc" ;;
        idor) idor_rc="$rc" ;;
        session) session_rc="$rc" ;;
        api_fuzzing) api_fuzz_rc="$rc" ;;
    esac
done < <(manual_evidence_keys)

python3 "${SCRIPT_DIR}/summarize_artifacts.py" "$REPORTS_DIR" 2> "${STATUS_DIR}/summarize-artifacts.log"
summarize_rc=$?
write_status "summarize-artifacts" "host" "$summarize_rc" "summarize_artifacts.py $REPORTS_DIR"
if [[ "$summarize_rc" != "0" ]]; then
    printf '\n[ERROR] summarize-artifacts failed (exit %s)\n' "$summarize_rc" >&2
fi
final_rc="$introspection_rc"
update_final_rc "$django_rc"
update_final_rc "$authz_rc"
update_final_rc "$idor_rc"
update_final_rc "$session_rc"
update_final_rc "$api_fuzz_rc"
update_final_rc "$summarize_rc"
AUDIT_DAST_AUTHORIZED="$DAST_AUTHORIZED" \
AUDIT_ACTIVE_DAST_AUTHORIZED="$ACTIVE_DAST_AUTHORIZED" \
AUDIT_RUN_ZAP="$RUN_ZAP" \
AUDIT_RUN_NUCLEI="$RUN_NUCLEI" \
AUDIT_RUN_TRUFFLEHOG="$RUN_TRUFFLEHOG" \
AUDIT_COVERAGE_THRESHOLD="$COVERAGE_THRESHOLD" \
SKIP_DD_IMPORT="$SKIP_DD_IMPORT" \
DD_API_TOKEN="$DD_API_TOKEN" \
python3 "${SCRIPT_DIR}/build_evidence_manifest.py" "$REPORTS_DIR" > "${STATUS_DIR}/evidence-manifest.log" 2>&1
manifest_rc=$?
write_status "evidence-manifest" "host" "$manifest_rc" "build_evidence_manifest.py $REPORTS_DIR"
if [[ "$manifest_rc" != "0" ]]; then
    printf '\n[ERROR] evidence-manifest generation failed (exit %s)\n' "$manifest_rc" >&2
fi
update_final_rc "$manifest_rc"
coverage_rc="2"
coverage_status="unknown"
coverage_percent="unknown"
if [[ -f "${REPORTS_DIR}/gates.json" ]]; then
    coverage_info="$(python3 - "${REPORTS_DIR}/gates.json" <<'PY'
import json
import sys
data = json.loads(open(sys.argv[1]).read())
print(f"{data.get('status', 'unknown')} {data.get('coverage_percent', 'unknown')}")
PY
)"
    coverage_status="${coverage_info%% *}"
    coverage_percent="${coverage_info#* }"
    [[ "$coverage_status" == "pass" ]] && coverage_rc="0" || coverage_rc="1"
fi
write_status "coverage-gates" "host" "$coverage_rc" "coverage threshold ${COVERAGE_THRESHOLD}; status ${coverage_status}; coverage ${coverage_percent}%"
if [[ "$coverage_rc" == "0" ]]; then
    printf 'Coverage gates: pass (%s%%/%s%%)\n' "$coverage_percent" "$COVERAGE_THRESHOLD"
else
    printf '\n[ERROR] Coverage gates: %s (%s%%/%s%%)\n' "$coverage_status" "$coverage_percent" "$COVERAGE_THRESHOLD" >&2
fi
update_final_rc "$coverage_rc"

print_execution_summary

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
exit "$final_rc"
