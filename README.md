# Openrelik worker for analyzing logs

## Supported log events
- SSH authentication events

## Installation
Add the below configuration to the OpenRelik `docker-compose.yml` file.

```
  openrelik-worker-analyzer-logs:
      container_name: openrelik-worker-analyzer-logs
      image: openrelik-worker-analyzer-logs
      restart: always
      environment:
        - REDIS_URL=redis://openrelik-redis:6379
      volumes:
        - ./data:/usr/share/openrelik/data
      command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-analyzer-logs"
```
