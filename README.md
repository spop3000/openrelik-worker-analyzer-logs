# Openrelik worker for analyzing logs
OpenRelik Logs Analyzer worker is responsible for log analysis. Tasks that read (multiple) logs can be added to this worker.

## Features
- Bruteforce SSH authentication event detection (taskname: ssh_analyzer)
   - Analyze auth logs and detect bruteforce login attempts.

## Installation
Add the below configuration to the OpenRelik `docker-compose.yml` file.

```
  openrelik-worker-analyzer-logs:
      container_name: openrelik-worker-analyzer-logs
      image: ghcr.io/openrelik/openrelik-worker-analyzer-logs:latest
      restart: always
      environment:
        - REDIS_URL=redis://openrelik-redis:6379
      volumes:
        - ./data:/usr/share/openrelik/data
      command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-analyzer-logs"
```

## Test
```
pip install poetry
poetry install --with test --no-root
poetry run pytest --cov=. -v
```