# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OPSCENTER_DB_PATH=/data/opscenter.db
RUN useradd --create-home --uid 10001 opscenter \
    && mkdir /data \
    && chown opscenter /data
COPY --from=build /dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm /tmp/*.whl
USER opscenter
WORKDIR /home/opscenter
VOLUME ["/data"]
ENTRYPOINT ["opsctl"]
CMD ["init"]
