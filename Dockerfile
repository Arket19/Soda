FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ core/
COPY modules/ modules/
COPY soda.py .

ENTRYPOINT ["python3", "soda.py"]