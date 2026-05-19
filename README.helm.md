# ArxSentinel — Helm chart deployment guide

The ArxSentinel Helm chart deploys a DaemonSet that runs one pod per node,
reads the node's access log via `hostPath`, and writes threat events to a
configurable host directory for Fail2Ban integration.

## Prerequisites

- Helm 3.x
- Kubernetes 1.24+
- Docker image accessible from the cluster (`ghcr.io/mr-addams/arxsentinel`)

## Quick install

```bash
# Watch /var/log/nginx on every node, metrics only (no Fail2Ban)
helm install arxsentinel ./deploy/helm/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx
```

## Full install — bare-metal / k3s with Fail2Ban

```bash
# Create the threat log directory on every node:
# (run on each node, or use a DaemonSet init container)
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

helm install arxsentinel ./deploy/helm/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

## Values reference

| Key | Type | Default | Description |
|---|---|---|---|
| `image.repository` | string | `ghcr.io/mr-addams/arxsentinel` | Image repository |
| `image.tag` | string | `""` | Image tag; defaults to `Chart.AppVersion` |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy |
| `logVolume.hostPath` | string | `/var/log/nginx` | Host path containing the access log |
| `logFile` | string | `access.log` | Access log filename inside `logVolume.hostPath` |
| `threatLog.hostPath` | string | `""` | Host path for threat log; empty = no hostPath mount |
| `metrics.enabled` | bool | `true` | Enable Prometheus `/metrics` endpoint |
| `metrics.port` | int | `9117` | Metrics port |
| `service.type` | string | `ClusterIP` | Kubernetes Service type |
| `serviceMonitor.enabled` | bool | `false` | Create a Prometheus Operator `ServiceMonitor` |
| `serviceMonitor.namespace` | string | `monitoring` | Namespace of the Prometheus Operator |
| `serviceMonitor.interval` | string | `30s` | Scrape interval |
| `resources.limits.cpu` | string | `200m` | CPU limit |
| `resources.limits.memory` | string | `128Mi` | Memory limit |
| `resources.requests.cpu` | string | `20m` | CPU request |
| `resources.requests.memory` | string | `32Mi` | Memory request |
| `tolerations` | list | `[]` | Node tolerations |
| `nodeSelector` | object | `{}` | Node selector |
| `env` | object | see values.yaml | `ARXSENTINEL_*` env var overrides |
| `extraEnv` | list | `[]` | Additional env vars (arbitrary key/value pairs) |

## Fail2Ban integration (bare-metal / k3s)

Set `threatLog.hostPath` to a directory present on every node.
Fail2Ban on the host reads `threats.log` from that directory:

```bash
helm upgrade arxsentinel ./deploy/helm/arxsentinel \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Configure Fail2Ban on the host:

```ini
# /etc/fail2ban/jail.d/arxsentinel.conf
[arxsentinel]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/threats.log
maxretry = 1
bantime  = 3600
```

Filter and jail configs: [`deploy/fail2ban/`](deploy/fail2ban/).

## Prometheus Operator integration (ServiceMonitor)

```bash
helm upgrade arxsentinel ./deploy/helm/arxsentinel \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.namespace=monitoring \
  --set serviceMonitor.additionalLabels.release=prometheus
```

The `ServiceMonitor` targets port `metrics` (9117) on the ArxSentinel `ClusterIP` service.

## Watching control-plane nodes

By default, DaemonSet pods are not scheduled on control-plane nodes. Add a toleration:

```bash
helm upgrade arxsentinel ./deploy/helm/arxsentinel \
  --set "tolerations[0].key=node-role.kubernetes.io/control-plane" \
  --set "tolerations[0].operator=Exists" \
  --set "tolerations[0].effect=NoSchedule"
```

## Config overrides via env vars

The `env` values map directly to `ARXSENTINEL_*` environment variables.
They take priority over the ConfigMap-rendered `config.yaml`:

```yaml
# values-production.yaml
env:
  ARXSENTINEL_SCORING_BAN_THRESHOLD: "60"
  ARXSENTINEL_SCORING_OBSERVATION_WINDOW: "600s"
  ARXSENTINEL_METRICS_USERNAME: "prometheus"
  ARXSENTINEL_METRICS_PASSWORD_HASH: "$2y$10$..."
```

```bash
helm upgrade arxsentinel ./deploy/helm/arxsentinel -f values-production.yaml
```

## Cloud environments (managed Kubernetes)

In managed cloud clusters (EKS, GKE, AKS), nodes may lack Fail2Ban or host-level
iptables access. The `hostPath` threat log approach does not integrate with cloud
firewall APIs.

**Current recommendation:** leave `threatLog.hostPath` empty and monitor threat
events via the Prometheus metrics endpoint. Block IPs at the load balancer / WAF level
based on Prometheus alerts.

**Planned:** Output Plugins (future release) will enable sending threat events directly
to databases, message queues, webhooks, and cloud firewall APIs — removing the Fail2Ban
dependency for cloud deployments.

## Upgrade

```bash
helm upgrade arxsentinel ./deploy/helm/arxsentinel
```

Pods are restarted automatically when the ConfigMap checksum changes.

## Uninstall

```bash
helm uninstall arxsentinel
```

`hostPath` directories on nodes are not removed — clean them up manually if needed.
