# Phase 6: Kubernetes Deployment (minimal)

## Helm chart
```
helm upgrade --install ss ./deploy/charts/stress-strike
```

## CRDs
```
kubectl apply -f deploy/crds/stressstrike-crd.yaml
```

## HPA
```
kubectl apply -f deploy/hpa/worker-hpa.yaml
```

## Kustomize
```
kubectl apply -k deploy/operator
```
