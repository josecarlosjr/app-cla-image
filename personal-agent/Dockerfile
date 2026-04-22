FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

RUN groupadd -r agent && useradd -r -g agent -u 1000 agent \
    && mkdir -p /data/notes && chown -R agent:agent /data

COPY --from=builder /install /usr/local

WORKDIR /app
COPY . .

USER agent

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "print('ok')"

CMD ["python", "bot.py"]
