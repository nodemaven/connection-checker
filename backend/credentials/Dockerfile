# @author Salama Malek
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8006
# Public-facing, so it binds all interfaces (put it behind your TLS reverse proxy).
CMD ["gunicorn", "-b", "0.0.0.0:8006", "-w", "2", "--timeout", "10", "app:app"]
