FROM python:3.12-slim
RUN pip install --no-cache-dir numpy
COPY rogue.py /app/rogue.py
WORKDIR /app
ENTRYPOINT ["python", "rogue.py"]
