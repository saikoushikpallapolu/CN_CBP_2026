FROM python:3.12-slim AS native-builder
RUN apt-get update && apt-get install -y --no-install-recommends g++ && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir setuptools
WORKDIR /native
COPY native .
RUN python setup.py build_ext --inplace

FROM python:3.12-slim AS runtime
WORKDIR /app
COPY requirements-production.txt .
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements-production.txt && useradd --create-home analyst
COPY api api
COPY classification classification
COPY data_processing data_processing
COPY ml/production_model.py ml/production_model.py
COPY frontend frontend
COPY scripts/acquire_production_data.py scripts/acquire_production_data.py
COPY --from=native-builder /native/traffic_native*.so /app/
RUN mkdir -p data/production ml/checkpoints && chown -R analyst:analyst /app
USER analyst
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--limit-concurrency", "16", "--timeout-keep-alive", "5"]

FROM runtime AS verification
USER root
RUN pip install --no-cache-dir pytest httpx
COPY tests tests
COPY scripts/prepare_cse.py scripts/prepare_cse.py
COPY pytest.ini .
USER analyst
RUN python -m pytest -q

FROM runtime AS production
