FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY upload_to_jira.py .

ENTRYPOINT ["python", "upload_to_jira.py"]