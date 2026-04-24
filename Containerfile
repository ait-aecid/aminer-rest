# NOTE: This Containerfile does not work on it's own and must be adapted so the aminer remote control socket is exposed and running.
# Also volumes need to be mounted for the aminer imports to work.
# This Containerfile is meant to be used in a docker compose configuration.

# sudo docker build -f Containerfile -t aminer-rest .
# sudo docker run -p 8000:8000 --rm aminer-rest

FROM ghcr.io/astral-sh/uv:latest AS uv

FROM ghcr.io/ait-aecid/logdata-anomaly-miner_rest

USER root

COPY --from=uv /uv /uvx /bin/

ADD . /home/aminer/aminer-rest
WORKDIR /home/aminer/aminer-rest

RUN uv pip install --python /usr/lib/logdata-anomaly-miner/.venv/bin/python --no-config -r requirements.txt
RUN chmod 0755 /home/aminer/aminer-rest/entrypoint.sh

ENV PATH="/usr/lib/logdata-anomaly-miner/.venv/bin/:${PATH}"

ADD README.md /docs/AMiner_REST_docs.md

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
