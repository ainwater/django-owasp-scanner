# OWASP Django Audit Workspace

Workspace para auditorias OWASP Top 10:2025 sobre proyectos Django. Utilizando DefectDojo: el kit ejecuta scanners, conserva artefactos técnicos crudos e importa resultados compatibles a DefectDojo.


## Ejecucion Rapida

Estos pasos permiten ejecutar el toolkit contra un proyecto Django local e importar los resultados a DefectDojo local.

### 1. Preparar DefectDojo local

Crear `defectdojo/.env` con permisos privados y valores generados localmente:

```bash
cd defectdojo
umask 077
DD_DATABASE_PASSWORD="$(openssl rand -hex 24)"
{
  printf 'DD_DATABASE_PASSWORD=%s\n' "$DD_DATABASE_PASSWORD"
  printf 'DD_DATABASE_URL=postgresql://defectdojo:%s@postgres:5432/defectdojo\n' "$DD_DATABASE_PASSWORD"
  printf 'DD_SECRET_KEY=%s\n' "$(openssl rand -hex 50)"
  printf 'DD_CREDENTIAL_AES_256_KEY=%s\n' "$(openssl rand -hex 32)"
  printf 'DD_ALLOWED_HOSTS=localhost,127.0.0.1\n'
} > .env
docker compose up -d
cd ..
```

DefectDojo queda disponible en `http://localhost:8080` y `https://localhost:8443`.

### 2. Obtener token API de DefectDojo

```bash
DD_API_TOKEN="$(
  cd defectdojo &&
  docker compose exec -T uwsgi python manage.py shell -c \
    "from django.contrib.auth import get_user_model; from rest_framework.authtoken.models import Token; u=get_user_model().objects.get(username='admin'); t,_=Token.objects.get_or_create(user=u); print(t.key)"
)"
```

Usar solo `DD_API_TOKEN`.

### 3. Crear archivo privado del proyecto Django

Crear un archivo fuera del repositorio, por ejemplo `/ruta/privada/audit.env`:

```bash
umask 077
cat > /ruta/privada/audit.env <<'EOF'
AUDIT_PROJECT="/ruta/absoluta/al/repositorio-django"
AUDIT_PRODUCT_NAME="Nombre del Producto"
AUDIT_DJANGO_SETTINGS_MODULE="config.settings"
AUDIT_DJANGO_COMMAND_PREFIX="poetry run python"
AUDIT_RUN_DAST=false
DD_URL="http://localhost:8080"
EOF
printf 'DD_API_TOKEN=%s\n' "$DD_API_TOKEN" >> /ruta/privada/audit.env
```

Si el proyecto usa virtualenv/Poetry, usar un prefijo sin operadores de shell, por ejemplo `poetry run python` o `.venv/bin/python`. Para activar un entorno virtual, hacerlo antes de ejecutar el runner.

### 4. Ejecutar toolkit e importar a DefectDojo

```bash
set -a
. /ruta/privada/audit.env
set +a

./audit-kit/scripts/run_owasp_audit.sh \
  --project "$AUDIT_PROJECT" \
  --product "$AUDIT_PRODUCT_NAME" \
  --settings "$AUDIT_DJANGO_SETTINGS_MODULE" \
  --django-command-prefix "$AUDIT_DJANGO_COMMAND_PREFIX" \
  --dd-token "$DD_API_TOKEN"
```

El runner compila la imagen Docker si no existe, conserva artefactos crudos fuera de git en `audit-kit/runs/`, muestra progreso numerado, genera resumen técnico e importa parsers compatibles a DefectDojo.

### 5. Verificar resultados

Abrir `http://localhost:8080`, entrar al producto creado y revisar:

- Engagement `OWASP Top 10:2025 - Audit`.
- Tests importados por herramienta.
- Findings activos por severidad.
- `Validated OWASP Findings` si se agrego `$OUTPUT_DIR/reports/curated-findings.json`.

Para DAST pasivo, se debe definir `AUDIT_TARGET_URL`, cambiar `AUDIT_RUN_DAST=true` y ejecutar con `--authorize-dast` solo con autorización explícita del entorno objetivo.

## Arquitectura

```text
owasp/
|-- Dockerfile                         # Toolbox generica de auditoria Django/OWASP
|-- audit-kit/
|   |-- audit.env.example              # Variables de entorno de ejemplo
|   |-- evidence-schema.json            # Contrato versionado del manifiesto de evidencia
|   |-- owasp-top10-2025.json          # Modelo tecnico OWASP Top 10:2025 para Django
|   |-- scripts/
|   |   |-- run_owasp_audit.sh         # Runner parametrizable
|   |   |-- coverage_gates.py           # Motor de cobertura y gates OWASP
|   |   |-- django_introspection.py      # Inventario Django/DRF y URLconf
|   |   |-- build_evidence_manifest.py  # Generador de manifiesto de evidencia
|   |   |-- import_defectdojo.py       # Importador generico a DefectDojo via API token
|   |   `-- summarize_artifacts.py     # Resumen tecnico saneado de artefactos
|   `-- templates/
|       |-- curated-findings.example.json
|       `-- evidence-manifest.example.json
|-- defectdojo/
|   |-- docker-compose.yml             # DefectDojo local
|   `-- import_findings.py             # Wrapper para evidencia externa
```

## Configuracion del Proyecto Objetivo

- La ruta del proyecto Django se configura con `--project` o `AUDIT_PROJECT`.
- El nombre del producto se configura con `--product` o `AUDIT_PRODUCT_NAME`.
- El modulo de settings se configura con `--settings` o `AUDIT_DJANGO_SETTINGS_MODULE`.
- El target HTTP/HTTPS se configura con `--target` o `AUDIT_TARGET_URL`.
- Los valores reales deben vivir en un archivo privado fuera de git, por ejemplo `audit.env`, basado en `audit-kit/audit.env.example`.

## Alcance Técnico

Este repositorio es un toolkit automatizable para auditorias OWASP Top 10:2025 sobre proyectos Django. Su objetivo es ejecutar controles repetibles, conservar artefactos técnicos crudos, resumir resultados sin exponer secretos e importar evidencia compatible a DefectDojo como fuente canonica.

Automatiza gran parte de la recoleccion técnica: SAST, SCA, SBOM, IaC, secret scanning, TLS, DAST pasivo/no autenticado, checks nativos de Django, resumen técnico saneado, manifiesto de evidencia e importacion a DefectDojo. El toolkit no pretende convertir OWASP en un proceso 100% automatico: A06, A09, abuso de logica, IDOR real, controles de MFA, logging operacional y DAST autenticado requieren validacion especifica por proyecto.

Fuera de alcance por defecto: explotacion ofensiva, generacion de HTML nuevo, DAST autenticado sin autorizacion explicita, bypass de WAF/bot-detection, importacion automatica de artefactos con secretos, y uso de DefectDojo con usuario/password en vez de `DD_API_TOKEN`.

## Politica de Artefactos

- No se versionan resultados de auditoria.
- `reports/` y `audit-kit/runs/` estan ignorados por git.
- Las ejecuciones nuevas se escriben por defecto en `audit-kit/runs/<producto>-<timestamp>/reports/`.
- DefectDojo es la UI canonica de las auditorias.
- Los artefactos crudos se preservan localmente para trazabilidad/importacion, pero quedan fuera del repositorio.
- Cada ejecucion genera `coverage.json`, `gates.json` y `evidence-manifest.json`; el manifest completo valida contra `audit-kit/evidence-schema.json`.

## Requisitos

- Docker.
- Python 3.12+ en el host con `requests` disponible.
- Proyecto Django accesible en el sistema de archivos local.
- Allow-list de WAF/bot-detection si se planifica DAST autenticado.

## Construccion

```bash
docker build -t owasp-audit:latest .
```

El runner compila la imagen automaticamente si no existe. Para omitirlo: `--no-build`.

## Ejecucion

### Analisis estatico con importacion a DefectDojo

```bash
./audit-kit/scripts/run_owasp_audit.sh \
  --project /ruta/absoluta/al/proyecto-django \
  --product "Nombre del Producto" \
  --dd-token "token-de-api-de-defectdojo"
```

### Analisis completo con DAST pasivo

```bash
./audit-kit/scripts/run_owasp_audit.sh \
  --project /ruta/absoluta/al/proyecto-django \
  --product "Nombre del Producto" \
  --settings config.settings \
  --django-command-prefix "poetry run python" \
  --target https://staging.ejemplo.com \
  --authorize-dast \
  --dd-token "token-de-api-de-defectdojo"
```

### Ejecucion con archivo de entorno privado

Crear un archivo privado fuera de git, por ejemplo `/ruta/privada/audit.env`:

```bash
AUDIT_PROJECT="/ruta/absoluta/al/repositorio-django"
AUDIT_PRODUCT_NAME="Nombre del Producto"
AUDIT_DJANGO_SETTINGS_MODULE="config.settings"
AUDIT_DJANGO_COMMAND_PREFIX="poetry run python"
AUDIT_TARGET_URL="https://staging.ejemplo.com"
AUDIT_DAST_AUTHORIZED=false
DD_URL="http://localhost:8080"
DD_API_TOKEN=""
```

Para cada proyecto, esos valores se completan solo en el archivo privado o se pasan por flags (`--project`, `--product`, `--settings`, `--target`). No deben quedar rutas absolutas, hosts internos ni tokens dentro del repositorio.

Cargarlo y ejecutar:

```bash
set -a
. /ruta/privada/audit.env
set +a

./audit-kit/scripts/run_owasp_audit.sh \
  --project "$AUDIT_PROJECT" \
  --product "$AUDIT_PRODUCT_NAME" \
  --settings "$AUDIT_DJANGO_SETTINGS_MODULE" \
  --django-command-prefix "$AUDIT_DJANGO_COMMAND_PREFIX" \
  --skip-dd-import
```

Sólo análisis de código, sin DAST:

```bash
./audit-kit/scripts/run_owasp_audit.sh \
  --project "$AUDIT_PROJECT" \
  --product "$AUDIT_PRODUCT_NAME" \
  --settings "$AUDIT_DJANGO_SETTINGS_MODULE" \
  --django-command-prefix "$AUDIT_DJANGO_COMMAND_PREFIX" \
  --skip-dast
```

Matriz A01 de autorizacion e IDOR manual:

```bash
# Usa los templates solo como referencia. Completa archivos privados con evidencia real.
AUTHZ_MATRIX=/ruta/privada/authz-matrix.json
IDOR_REVIEW=/ruta/privada/A01-idor-review.md
SESSION_REVIEW=/ruta/privada/session-review.json

./audit-kit/scripts/run_owasp_audit.sh \
  --project "$AUDIT_PROJECT" \
  --product "$AUDIT_PRODUCT_NAME" \
  --authz-matrix "$AUTHZ_MATRIX" \
  --idor-review "$IDOR_REVIEW" \
  --session-review "$SESSION_REVIEW" \
  --skip-dast \
  --skip-dd-import
```

No pases los templates de `audit-kit/templates/` directamente como evidencia. Deben copiarse fuera de git, reemplazarse con casos reales y revisarse antes de ejecutar el runner.
La matriz recomendada es JSON para evitar ambigüedad de parsing; el runner mantiene soporte YAML simple para archivos existentes. Por compatibilidad con el modelo OWASP del kit, la matriz entregada por el auditor se conserva como `F2/authz-matrix.yml` aunque el archivo de entrada sea JSON.
La revision de sesion debe ser un JSON con `checks`; cada check requiere `id`, `status` (`pass`, `fail` o `not_applicable`) y `evidence`. Los controles requeridos son `logout_invalidates_session`, `session_rotation`, `enumeration_resistance`, `mfa_privileged` y `brute_force_protection`; `not_applicable` queda registrado, pero no satisface un control requerido.

Para DAST pasivo, definir `AUDIT_TARGET_URL`, coordinar autorizacion y ejecutar con `--authorize-dast`. Para importacion automatica, definir `DD_API_TOKEN` o usar `--dd-token`.

DAST autenticado + API fuzzing (PR5) con evidencia privada:

```bash
OPENAPI_SPEC=/ruta/privada/openapi.json
API_FUZZING_REVIEW=/ruta/privada/api-fuzzing-review.json
AUTH_HEADER_NAME=Authorization
AUTH_HEADER_VALUE="Bearer <privado>"

./audit-kit/scripts/run_owasp_audit.sh \
  --project "$AUDIT_PROJECT" \
  --product "$AUDIT_PRODUCT_NAME" \
  --target https://staging.ejemplo.com \
  --authorize-dast \
  --openapi-spec "$OPENAPI_SPEC" \
  --api-base-url https://staging.ejemplo.com/api \
  --auth-header-name "$AUTH_HEADER_NAME" \
  --auth-header-value "$AUTH_HEADER_VALUE" \
  --api-fuzzing-review "$API_FUZZING_REVIEW"
```

Este flujo normaliza evidencia (`F6/api-fuzzing*.json`) desde la revisión privada; como `api_fuzzing` está marcado como evidencia requerida de A05 en el modelo actual, omitir `--api-fuzzing-review` deja A05 incompleto y puede hacer fallar los gates con umbrales altos o al 100%. No ejecuta Schemathesis automáticamente en esta versión. Para evitar exposición de secretos, no pongas tokens literales en el comando: usa variables privadas o archivo de entorno fuera de git.

`--schemathesis-max-examples N` (N > 0) funciona como gate de autorización y exige `--authorize-dast` y `--authorize-active-dast`; no habilita ejecución automática de fuzzing por sí solo.

## Flujo

1. Compila la toolbox Docker si no existe.
2. Ejecuta SAST, SCA, secretos, IaC, SBOM, TLS y DAST pasivo segun parametros.
3. Si se proporciona `--authz-matrix`, valida la matriz A01 y escribe `F2/authz-matrix.yml` y `F2/authz-results.json`.
4. Si se proporciona `--idor-review`, copia la revision manual a `F5/A01-idor-review.md`.
5. Si se proporciona `--session-review`, valida controles de logout, rotacion, enumeracion, MFA y brute force, y escribe `F2/session-security.json` y `F2/session-security-results.json`.
6. Si se proporciona `--api-fuzzing-review`, normaliza evidencia de API fuzzing y escribe `F6/api-fuzzing.json` y `F6/api-fuzzing-results.json`.
7. Muestra progreso numerado y resumen tecnico por herramienta.
8. Conserva artefactos crudos en `$OUTPUT_DIR/reports/`.
9. Escribe `$OUTPUT_DIR/reports/summary.json` con conteos saneados.
10. Escribe `$OUTPUT_DIR/reports/coverage.json` y `$OUTPUT_DIR/reports/gates.json` con cobertura requerida y gates OWASP.
11. Escribe `$OUTPUT_DIR/reports/evidence-manifest.json` con artefactos, autorizaciones, cobertura y gates.
12. Imprime resumen de ejecucion con el estado de `coverage-gates`.
13. Importa a DefectDojo si existe `--dd-token` o `DD_API_TOKEN`.
14. Imprime checklist de controles no automatizables OWASP Top 10:2025.
15. Solo abre DefectDojo si se usa `--open-defectdojo`.

## Parametros

| Parametro | Obligatorio | Descripcion |
|---|---|---|
| `--project PATH` | Si | Ruta absoluta o relativa al proyecto Django |
| `--product NAME` | Si | Nombre del producto para trazabilidad |
| `--settings MODULE` | No | Modulo de settings Django para `manage.py check --deploy` |
| `--django-command-prefix CMD` | No | Prefijo seguro antes de `manage.py`, sin operadores de shell; ejemplos: `poetry run python`, `.venv/bin/python` (defecto: `poetry run python`) |
| `--authz-matrix PATH` | No | Matriz A01 rol/tenant/objeto con `expected`/`observed`; genera `F2/authz-matrix.yml` y `F2/authz-results.json` |
| `--idor-review PATH` | No | Revision manual IDOR/A01 validada; se copia a `F5/A01-idor-review.md` |
| `--session-review PATH` | No | Revision JSON de logout, rotacion, enumeracion, MFA y brute force; genera `F2/session-security.json` y `F2/session-security-results.json` |
| `--target URL` | No | URL autorizada para DAST pasivo |
| `--openapi-spec PATH` | No | Especificacion OpenAPI privada para flujo PR5 autenticado |
| `--api-base-url URL` | No | Base URL autenticada para APIs del fuzzing |
| `--auth-header-name NAME` | No | Nombre del header de autenticacion (ej. `Authorization`) |
| `--auth-header-value VALUE` | No | Valor privado del header de autenticacion (redactado en status) |
| `--api-fuzzing-review PATH` | No | Revision JSON privada de API fuzzing; genera `F6/api-fuzzing.json` y `F6/api-fuzzing-results.json` |
| `--schemathesis-max-examples N` | No | Activa ejemplos mutados si N > 0; requiere `--authorize-active-dast` |
| `--output DIR` | No | Directorio de salida (defecto: `audit-kit/runs/<slug>-<timestamp>`) |
| `--dd-token TOKEN` | No | API token de DefectDojo para importacion automatica |
| `--dd-url URL` | No | URL de DefectDojo (defecto: `http://localhost:8080`) |
| `--skip-dast` | No | Omite verificaciones contra el target |
| `--skip-zap` | No | Omite ZAP baseline |
| `--skip-nuclei` | No | Omite Nuclei |
| `--skip-django-checks` | No | Omite introspeccion Django y `manage.py check --deploy`/comandos relacionados |
| `--skip-dd-import` | No | No importa artefactos a DefectDojo |
| `--run-trufflehog` | No | Habilita TruffleHog; puede producir evidencia con secretos |
| `--coverage-threshold N` | No | Umbral minimo de evidencia requerida para gates OWASP (defecto: `80`) |
| `--authorize-dast` | No | Confirma autorizacion explicita para DAST pasivo/no autenticado contra `--target` |
| `--authorize-active-dast` | No | Confirma autorizacion explicita para DAST activo con mutaciones |
| `--open-defectdojo` | No | Abre DefectDojo al finalizar si la importacion fue exitosa |
| `--generate-only` | No | Solo crea estructura e inventario, sin scanners |
| `--no-build` | No | No construye la imagen Docker |

## Herramientas

| Categoria | Herramientas |
|---|---|
| SAST | Bandit, Ruff (`S`), Semgrep (Python/Django) |
| Templates | djLint |
| SCA | pip-audit, OSV Scanner, Trivy, Grype |
| SBOM | Syft (CycloneDX) |
| IaC | Checkov |
| Secretos | Gitleaks, detect-secrets, TruffleHog opt-in |
| DAST | ZAP baseline, Nuclei |
| TLS | testssl.sh, SSLyze |
| Django nativo | Introspeccion settings/URLs, `manage.py check --deploy`, `showmigrations`, `show_urls` |

`semgrep-django` combina los packs upstream `p/python` y `p/django` con reglas locales en `audit-kit/semgrep/django-drf.yml` para sinks Django/DRF de autenticacion, CSRF, SQL, templates y deserializacion.

## DefectDojo

### Iniciar instancia local

Crear primero `defectdojo/.env` local:

```bash
DD_DATABASE_PASSWORD="<valor-privado>"
DD_DATABASE_URL="postgresql://defectdojo:<valor-privado>@postgres:5432/defectdojo"
DD_SECRET_KEY="<valor-privado-largo>"
DD_CREDENTIAL_AES_256_KEY="<valor-hex-64-caracteres>"
DD_ALLOWED_HOSTS="localhost,127.0.0.1"
```

```bash
cd defectdojo
docker compose up -d
```

UI local: `http://localhost:8080`.

Endpoint HTTPS local: `https://localhost:8443`.

### Generar token de API

```bash
docker compose exec -T uwsgi python manage.py shell -c "from django.contrib.auth import get_user_model; from rest_framework.authtoken.models import Token; u=get_user_model().objects.get(username='admin'); t,_=Token.objects.get_or_create(user=u); print(t.key)"
```

### Importacion automatica

El runner importa automaticamente los artefactos compatibles al finalizar si se proporciona `--dd-token` o `DD_API_TOKEN`. La importacion es idempotente: no duplica tests ya existentes salvo que se defina `DD_FORCE_IMPORT=true`. No se usan flujos `DD_USERNAME` / `DD_PASSWORD`.

### Importacion manual

```bash
REPORTS_DIR=/ruta/a/reports \
DD_API_TOKEN="token-generado" \
DD_PRODUCT_NAME="Nombre del Producto" \
python3 audit-kit/scripts/import_defectdojo.py
```

### Artefactos excluidos de importacion automatica

Estos artefactos pueden contener secretos o requieren revision previa, por lo que no se importan automaticamente:

- `Gitleaks`.
- `detect-secrets`.
- `TruffleHog`.

Para hallazgos validados fuera de los parsers automaticos, usar `$OUTPUT_DIR/reports/curated-findings.json` con el esquema de `audit-kit/templates/curated-findings.example.json`. El importador los inserta como `verified=true` en el test `Validated OWASP Findings`.

## Cobertura OWASP Top 10:2025

La taxonomia canonica esta versionada en `audit-kit/owasp-top10-2025.json` y corresponde a OWASP Top 10:2025, no a mapeos 2021.

Porcentaje estimado de cobertura automatica por categoria, basado en las herramientas incluidas. La cobertura mide evidencia repetible que el toolkit puede producir sin credenciales aplicativas ni decisiones de negocio.

| # | Categoria OWASP 2025 | Auto | Herramientas que cubren | Lo que NO se automatiza |
|---|---|---|---|---|
| A01 | Broken Access Control | 35% | Django deploy checks, Semgrep, ZAP, Ruff, inventario de URLs | IDOR autenticado, escalacion de privilegios, CORS con credenciales, JWT tampering, control de acceso a nivel de objeto |
| A02 | Security Misconfiguration | 75% | Checkov, Django `check --deploy`, ZAP, Nuclei, detect-secrets | Permisos cloud, configuraciones fuera de IaC, hardening de CI/CD |
| A03 | Software Supply Chain Failures | 85% | pip-audit, OSV Scanner, Trivy, Grype, Syft | Dependencias transitivas no declaradas, componentes no mapeados, integridad del pipeline |
| A04 | Cryptographic Failures | 80% | testssl.sh, SSLyze, Bandit, detect-secrets, ZAP | TLS interno, rotacion de claves, algoritmos custom |
| A05 | Injection | 60% | Semgrep, Bandit, djLint, Ruff | GraphQL, prompts LLM, importadores CSV/XLSX custom |
| A06 | Insecure Design | 15% | Checklist guiado, inventario de endpoints, DFD operativo | Threat modeling completo, abuso de negocio, requisitos de seguridad de diseno |
| A07 | Authentication Failures | 45% | Django deploy checks, ZAP, Semgrep, cookies/headers, rate-limit evidence | MFA, rotacion de sesion, lockout real, magic-link seguro, OAuth/OIDC/SAML |
| A08 | Software or Data Integrity Failures | 60% | Bandit, Ruff, pip-audit, Syft, Semgrep, Checkov | Firmado de artefactos, integridad CI/CD, validacion funcional de uploads, dependency confusion |
| A09 | Security Logging and Alerting Failures | 15% | Checklist guiado, grep de logging, evidencia de errores/headers | Eventos auditables, redaccion de secretos en logs, alertas en SIEM |
| A10 | Mishandling of Exceptional Conditions | 40% | Django deploy checks, Bandit, ZAP, Ruff | Fail closed, race conditions, corrupcion de estado, limites de recursos |

Estimado: **55% automatico y 45% validacion especifica del proyecto**. En la practica, el toolkit automatiza la mayor parte de la evidencia tecnica repetible; lo restante corresponde a controles que no son confiables sin contexto de negocio, credenciales, entorno y autorizacion.

## Limitaciones

- DAST autenticado no es generico: requiere credenciales, sesion, CSRF y allow-list de WAF por proyecto.
- El runner no ejecuta DAST contra `--target` sin `--authorize-dast`.
- CodeQL no esta incluido por limitacion Linux arm64; el kit usa Semgrep, Bandit y Ruff.
- Wapiti esta disponible en la imagen, pero no se invoca por defecto.
- Los resultados generados quedan fuera de git; para compartir evidencia, usar DefectDojo o un paquete externo controlado.

## Variables de entorno

Ver `audit-kit/audit.env.example`. Los flags del runner tienen precedencia sobre las variables de entorno.
