FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .

RUN pip install --requirement requirements.txt

COPY main.py .
ENTRYPOINT ["python3", "main.py"]
