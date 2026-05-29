FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rustore_monitor/ ./rustore_monitor/

VOLUME /data

CMD ["python", "-u", "-m", "rustore_monitor"]
