# ArxSentinel у Kubernetes

> 🌐 [English](README.md) | [Русский](README.ru.md)

Два варіанти розгортання:

- **DaemonSet** (`daemonset.yaml`): по одному pod'у на кожен вузол, читає nginx-логи хоста через `hostPath`. Використовуйте, коли у вас є доступ до логів на рівні вузла.
- **Sidecar** (`sidecar.yaml`): запускається поряд із контейнером застосунку в тому ж Pod, поділяючи том `emptyDir`. Використовуйте з керованим Kubernetes (EKS, GKE, AKS), де доступ до логів вузлів обмежений.

Застосовується командою `kubectl apply -f configmap.yaml -f daemonset.yaml` (або sidecar). Поправте шлях до логів у `configmap.yaml` під розташування вашого access-логу nginx. Метрики скрейпляться Prometheus на порту 9117.
