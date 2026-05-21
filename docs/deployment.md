# SopsGate — Deployment

## Docker

### Build

```bash
docker build -t sopsgate .
```

### Run

```bash
docker run -d \
  --name sopsgate \
  -p 8080:8080 \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  -v /path/to/sopsgate.key:/app/sopsgate.key:ro \
  -v sopsgate-data:/data/secrets \
  sopsgate
```

### Docker Compose

```yaml
version: "3.8"
services:
  sopsgate:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./sopsgate.key:/app/sopsgate.key:ro
      - sopsgate-data:/data/secrets
    restart: unless-stopped

volumes:
  sopsgate-data:
```

## Kubernetes

Example deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sopsgate
spec:
  replicas: 1  # Must be 1 — git repo is local
  selector:
    matchLabels:
      app: sopsgate
  template:
    metadata:
      labels:
        app: sopsgate
    spec:
      containers:
        - name: sopsgate
          image: sopsgate:latest
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: config
              mountPath: /app/config.yaml
              subPath: config.yaml
            - name: age-key
              mountPath: /app/sopsgate.key
              subPath: sopsgate.key
            - name: data
              mountPath: /data/secrets
      volumes:
        - name: config
          configMap:
            name: sopsgate-config
        - name: age-key
          secret:
            secretName: sopsgate-age-key
        - name: data
          persistentVolumeClaim:
            claimName: sopsgate-data
```

## Important Notes

- **Single replica only** — SopsGate uses a local git repo. Running multiple replicas will cause data corruption.
- **Persistent storage** — The secrets repo must be on persistent storage to survive restarts.
- **Key security** — The age key file should be mounted read-only and stored securely (e.g., Kubernetes Secret).
