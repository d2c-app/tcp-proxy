.PHONY: build load deploy

# Build Docker image
build:
	docker build -t tcp-proxy:latest .

# Load image into kind cluster
load: build
	kind load docker-image tcp-proxy:latest --name d2c-cluster

# Deploy to Kubernetes
deploy: load
	kubectl rollout restart deployment tcp-proxy
