# @author Salama Malek
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8004
CMD ["gunicorn", "-b", "127.0.0.1:8004", "-w", "2", "--timeout", "10", "app:app"]
