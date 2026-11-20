ARG BASE=python:3.13-slim
FROM ${BASE}
COPY varyroot /opt/role/varyroot
ENV PYTHONPATH=/opt/role PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
WORKDIR /input
ENTRYPOINT []
CMD ["python", "-m", "varyroot"]
