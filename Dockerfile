FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && useradd --uid 65532 --create-home --shell /usr/sbin/nologin runner
COPY app.py /app/app.py
COPY vcw_runner.py /app/vcw_runner.py
USER 65532:65532
CMD ["python", "/app/app.py"]
