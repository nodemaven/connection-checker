# @author Salama Malek
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY stun_observe.py .
CMD ["python", "-u", "stun_observe.py"]
