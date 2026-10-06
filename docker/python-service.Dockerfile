# One Dockerfile for every Python service. Build with --build-arg SERVICE=<folder in services/>
FROM python:3.12-slim
ARG SERVICE
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY libs/common /libs/common
RUN pip install --no-cache-dir /libs/common
COPY services/${SERVICE}/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY services/${SERVICE}/ /app/
RUN useradd -r -u 10001 app
USER app
CMD ["python", "main.py"]
