# @author Salama Malek
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 8000
# 2 workers is plenty for three static routes, and keeps the footprint small on
# a box that is already using most of its 4 GB.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "2", "--timeout", "30", "app:app"]
