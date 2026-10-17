FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV APP_ENV=production DATABASE_PATH=/data/servicepro.db
RUN useradd -m app && mkdir -p /data && chown app /data
USER app
EXPOSE 8000
# One worker + threads: SQLite is single-writer, and the login throttle is in-process.
CMD gunicorn wsgi:app --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 4
