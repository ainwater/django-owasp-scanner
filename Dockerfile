FROM python:3.12-slim

LABEL description="Toolbox reutilizable para auditorías OWASP Top 10:2025 sobre aplicaciones Django"
LABEL target="generic-django"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git openssl unzip bsdmainutils procps perl dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-64bit.tar.gz" \
    | tar xz -C /usr/local/bin trivy && trivy --version

RUN set -eux; ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); \
    curl -fsSL "https://github.com/anchore/grype/releases/download/v0.112.0/grype_0.112.0_linux_${ARCH}.tar.gz" \
    -o /tmp/grype.tar.gz && tar xzf /tmp/grype.tar.gz -C /usr/local/bin grype && rm /tmp/grype.tar.gz && grype version

RUN set -eux; ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v1.44.0/syft_1.44.0_linux_${ARCH}.tar.gz" \
    -o /tmp/syft.tar.gz && tar xzf /tmp/syft.tar.gz -C /usr/local/bin syft && rm /tmp/syft.tar.gz && syft version

RUN set -eux; ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/v2.3.8/osv-scanner_linux_${ARCH}" \
    -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner && osv-scanner --version

RUN set -eux; ARCH=$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/'); \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${ARCH}.tar.gz" \
    -o /tmp/gl.tar.gz && tar xzf /tmp/gl.tar.gz -C /usr/local/bin gitleaks && rm /tmp/gl.tar.gz && gitleaks version

RUN set -eux; ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.3/trufflehog_3.95.3_linux_${ARCH}.tar.gz" \
    -o /tmp/th.tar.gz && tar xzf /tmp/th.tar.gz -C /usr/local/bin trufflehog && rm /tmp/th.tar.gz && trufflehog --version

RUN set -eux; ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_${ARCH}.zip" \
    -o /tmp/sf.zip && unzip -o /tmp/sf.zip subfinder -d /usr/local/bin/ && chmod +x /usr/local/bin/subfinder && rm /tmp/sf.zip && subfinder -version

RUN set -eux; ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'); \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_${ARCH}.zip" \
    -o /tmp/nuclei.zip && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/ && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip && nuclei -version

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        semgrep \
        bandit \
        ruff \
        djlint \
        pip-audit \
        detect-secrets \
        checkov \
        wapiti3 \
        sslyze \
        arjun \
    && semgrep --version && bandit --version && ruff --version && djlint --version && pip-audit --version && checkov --version \
    && python -c "from importlib.metadata import version; print('sslyze', version('sslyze')); print('wapiti3', version('wapiti3')); print('arjun', version('arjun')); print('detect-secrets', version('detect-secrets'))"

RUN python - <<'PY'
from pathlib import Path
for path in Path('/usr/local/lib').glob('python*/site-packages/wapitiCore/language/language.py'):
    lines = [line for line in path.read_text().splitlines() if 'codeset=' not in line]
    path.write_text('\n'.join(lines) + '\n')
PY

RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

RUN apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
VOLUME ["/workspace/reports"]
ENTRYPOINT ["/bin/bash"]
