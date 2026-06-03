# ArxSentinel on Kubernetes

Two deployment options:

- **DaemonSet** (`daemonset.yaml`): one pod per node, reads host nginx logs via `hostPath`. Use when you have node-level log access.
- **Sidecar** (`sidecar.yaml`): runs alongside the app container in the same Pod, shares an `emptyDir` volume. Use with managed Kubernetes (EKS, GKE, AKS) where node log access is restricted.

Apply with `kubectl apply -f configmap.yaml -f daemonset.yaml` (or sidecar). Adjust the log path in `configmap.yaml` to match your nginx access log location. Metrics are scraped by Prometheus at port 9117.