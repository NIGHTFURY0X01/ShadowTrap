FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system shadowtrap && adduser --system --ingroup shadowtrap shadowtrap

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=shadowtrap:shadowtrap . ./
RUN mkdir -p /app/data && chown -R shadowtrap:shadowtrap /app/data

USER shadowtrap
EXPOSE 8000 8080 2222

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)" || exit 1

ENTRYPOINT ["python", "main.py"]
CMD ["api", "--host", "0.0.0.0"]
