FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libldap-2.4-2 \
    libsasl2-2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]