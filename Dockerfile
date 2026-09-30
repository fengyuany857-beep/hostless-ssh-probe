FROM python:3.12-alpine
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
CMD ["python", "/app/app.py"]
