# ── сертификаты Минцифры (НУЦ) ──
# Корневой и промежуточный сертификаты «Russian Trusted CA» скачиваются при сборке,
# корневой сверяется по SHA-256 отпечатку, промежуточный — проверяется подписью корневого.
FROM python:3.14-slim AS certs

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG MINTSIFRY_CA_URL=https://gu-st.ru/content/lending
ARG ROOT_CA_SHA256=D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31

WORKDIR /certs
RUN curl -fsSL --retry 3 -o russian_trusted_root_ca.crt "$MINTSIFRY_CA_URL/russian_trusted_root_ca_pem.crt" \
    && curl -fsSL --retry 3 -o russian_trusted_sub_ca.crt "$MINTSIFRY_CA_URL/russian_trusted_sub_ca_pem.crt" \
    && openssl x509 -in russian_trusted_root_ca.crt -noout -fingerprint -sha256 \
        | grep -qix "sha256 fingerprint=$ROOT_CA_SHA256" \
    && openssl verify -CAfile russian_trusted_root_ca.crt russian_trusted_sub_ca.crt

# ── приложение ──
FROM python:3.14-slim

# добавляем сертификаты Минцифры в системное хранилище
# и указываем его httpx (по умолчанию он использует только certifi)
COPY --from=certs /certs/*.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rustore_monitor/ ./rustore_monitor/

VOLUME /data

CMD ["python", "-u", "-m", "rustore_monitor"]
