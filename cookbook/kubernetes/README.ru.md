# ArxSentinel в Kubernetes

> 🌐 [English](README.md) | [Українська](README.uk.md)

Два варианта развёртывания:

- **DaemonSet** (`daemonset.yaml`): по одному pod'у на каждый узел, читает nginx-логи хоста через `hostPath`. Используйте, когда у вас есть доступ к логам на уровне узла.
- **Sidecar** (`sidecar.yaml`): запускается рядом с контейнером приложения в том же Pod, разделяя том `emptyDir`. Используйте с управляемым Kubernetes (EKS, GKE, AKS), где доступ к логам узлов ограничен.

Применяется командой `kubectl apply -f configmap.yaml -f daemonset.yaml` (или sidecar). Поправьте путь к логам в `configmap.yaml` под расположение вашего access-лога nginx. Метрики скрапятся Prometheus на порту 9117.
