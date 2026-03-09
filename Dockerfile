FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV HOST=0.0.0.0
ENV PORT=5537
ENV SECRET_KEY=change-me-in-production

EXPOSE 5537

CMD ["gunicorn", "-w", "1", "-k", "eventlet", "-b", "0.0.0.0:5537", "app:app"]
