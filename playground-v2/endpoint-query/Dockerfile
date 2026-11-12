# The lab's endpoint-query service (#1391 r6 O8). Build context: playground-v2/ (it copies
# lab-surface.json and derives its enrolled hosts from hosts/inventory.yaml, the one host list).
FROM python:3.12-slim AS hosts
RUN pip install --no-cache-dir pyyaml==6.0.2
COPY hosts/inventory.yaml /src/inventory.yaml
RUN python -c "import yaml; print('\n'.join(h['name'] for h in yaml.safe_load(open('/src/inventory.yaml'))['hosts']))" > /hosts.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=hosts /hosts.txt /etc/endpoint-query/hosts.txt
COPY lab-surface.json /app/lab-surface.json
COPY endpoint-query/service.py /app/service.py
# Never `python app.py`: Shuffle's reaper kills any container whose command contains it.
ENTRYPOINT ["python", "/app/service.py"]
