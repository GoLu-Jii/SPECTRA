FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN apt-get update \
    && apt-get install --no-install-recommends -y libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir -r /app/backend/requirements.txt \
    && useradd --system --uid 10001 --create-home --home-dir /home/spectra spectra

COPY backend /app/backend
COPY ml_engine /app/ml_engine
COPY data_and_demo /app/data_and_demo

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
