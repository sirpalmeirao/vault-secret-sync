# Vault Secret Sync - Kubernetes Installation Guide

This guide will walk you through installing and deploying vault-secret-sync on Kubernetes to sync secrets from HashiCorp Vault to GCP Secret Manager.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Installation Steps](#installation-steps)
4. [Configuration](#configuration)
5. [Deployment](#deployment)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Components

- **Kubernetes Cluster**: v1.20+ with access to create CRDs and RBAC resources
- **HashiCorp Vault**: Running and accessible from your cluster
- **GCP Project**: With Secret Manager API enabled
- **kubectl**: Configured to access your cluster
- **Tools**: `helm` (optional), `git`, `docker`

### Required Permissions

#### Kubernetes Permissions
- Create CustomResourceDefinitions (CRDs)
- Create Namespaces
- Create ServiceAccounts, Roles, RoleBindings, ClusterRoles, ClusterRoleBindings
- Create Deployments, Services, ConfigMaps, Secrets

#### GCP Permissions
Your GCP service account needs:
```json
{
  "roles": [
    "roles/secretmanager.admin"
  ],
  "permissions": [
    "secretmanager.secrets.create",
    "secretmanager.secrets.delete",
    "secretmanager.secrets.get",
    "secretmanager.secrets.list",
    "secretmanager.secrets.update",
    "secretmanager.versions.access",
    "secretmanager.versions.add"
  ]
}
```

#### Vault Permissions
Your Vault role needs:
```hcl
path "secret/data/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           vault-secret-sync Operator                  │  │
│  │                                                        │  │
│  │  ┌────────────────┐         ┌──────────────────┐    │  │
│  │  │   Controller   │────────▶│  Event Handler   │    │  │
│  │  │   (CRD Watch)  │         │  (Vault Events)  │    │  │
│  │  └────────────────┘         └──────────────────┘    │  │
│  │          │                           │               │  │
│  │          │                           │               │  │
│  │          ▼                           ▼               │  │
│  │  ┌────────────────────────────────────────────┐    │  │
│  │  │         Sync Engine                         │    │  │
│  │  │  (Worker Pool, Queue, Transforms)          │    │  │
│  │  └────────────────────────────────────────────┘    │  │
│  │          │                                          │  │
│  └──────────┼──────────────────────────────────────────┘  │
│             │                                              │
└─────────────┼──────────────────────────────────────────────┘
              │
              │ Authentication (K8s SA / JWT)
              ▼
    ┌─────────────────────┐
    │   HashiCorp Vault   │
    │   (Secret Source)    │
    └─────────────────────┘
              │
              │ Read Secrets
              ▼
    ┌─────────────────────┐         ┌──────────────────────┐
    │ Sync Worker Pool    │────────▶│  GCP Secret Manager  │
    │ (Configurable Size) │  Write  │    (Destination)      │
    └─────────────────────┘         └──────────────────────┘
```

## Installation Steps

### Step 1: Clone the Repository

```bash
cd /tmp
git clone https://github.com/robertlestak/vault-secret-sync.git
cd vault-secret-sync
```

### Step 2: Create Namespace

```bash
kubectl create namespace vault-secret-sync
```

### Step 3: Install CRDs (Custom Resource Definitions)

```bash
kubectl apply -f deploy/charts/vault-secret-sync/crds/
```

Verify CRDs are installed:
```bash
kubectl get crd vaultsecretsync.lestak.sh
```

Expected output:
```
NAME                           CREATED AT
vaultsecretsync.lestak.sh      2025-11-18T10:00:00Z
```

### Step 4: Configure GCP Authentication

#### Option A: Using Workload Identity (Recommended for GKE)

1. Create GCP Service Account:
```bash
export PROJECT_ID="your-gcp-project"
export GSA_NAME="vault-secret-sync"

gcloud iam service-accounts create ${GSA_NAME} \
  --project=${PROJECT_ID} \
  --display-name="Vault Secret Sync"
```

2. Grant Secret Manager permissions:
```bash
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
  --member="serviceAccount:${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/secretmanager.admin"
```

3. Enable Workload Identity binding:
```bash
gcloud iam service-accounts add-iam-policy-binding \
  ${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:${PROJECT_ID}.svc.id.goog[vault-secret-sync/vault-secret-sync]"
```

4. Annotate Kubernetes ServiceAccount (will be created in Step 6):
```yaml
# This will be added to the ServiceAccount manifest
metadata:
  annotations:
    iam.gke.io/gcp-service-account: vault-secret-sync@your-project.iam.gserviceaccount.com
```

#### Option B: Using Service Account Key (Not recommended for production)

1. Create service account key:
```bash
gcloud iam service-accounts keys create ~/gcp-key.json \
  --iam-account=${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
```

2. Create Kubernetes secret:
```bash
kubectl create secret generic gcp-credentials \
  --from-file=key.json=~/gcp-key.json \
  -n vault-secret-sync

# Remove the key file
rm ~/gcp-key.json
```

### Step 5: Configure Vault Authentication

#### Option A: Using Kubernetes Auth (Recommended)

1. Enable Kubernetes auth in Vault:
```bash
vault auth enable kubernetes
```

2. Configure Kubernetes auth:
```bash
# Get Kubernetes CA cert
kubectl get cm kube-root-ca.crt -o jsonpath="{['data']['ca\.crt']}" > k8s-ca.crt

# Get Kubernetes API server
K8S_HOST="https://$(kubectl get svc kubernetes -o jsonpath='{.spec.clusterIP}')"

# Get service account token (Kubernetes 1.24+)
kubectl create token vault-secret-sync -n vault-secret-sync > sa-token.txt

vault write auth/kubernetes/config \
    token_reviewer_jwt=@sa-token.txt \
    kubernetes_host="${K8S_HOST}" \
    kubernetes_ca_cert=@k8s-ca.crt \
    disable_iss_validation=true

# Clean up
rm k8s-ca.crt sa-token.txt
```

3. Create Vault policy:
```bash
vault policy write vault-secret-sync - <<EOF
path "secret/data/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
EOF
```

4. Create Vault role:
```bash
vault write auth/kubernetes/role/vault-secret-sync \
    bound_service_account_names=vault-secret-sync \
    bound_service_account_namespaces=vault-secret-sync \
    policies=vault-secret-sync \
    ttl=1h
```

#### Option B: Using Vault Token (Not recommended for production)

1. Create a token in Vault:
```bash
vault token create -policy=vault-secret-sync -period=24h
```

2. Create Kubernetes secret with token:
```bash
kubectl create secret generic vault-token \
  --from-literal=token='<your-vault-token>' \
  -n vault-secret-sync
```

### Step 6: Create RBAC Resources

Create `rbac.yaml`:
```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-secret-sync
  namespace: vault-secret-sync
  # Uncomment for Workload Identity (GKE)
  # annotations:
  #   iam.gke.io/gcp-service-account: vault-secret-sync@YOUR-PROJECT.iam.gserviceaccount.com

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vault-secret-sync
rules:
- apiGroups: ["lestak.sh"]
  resources: ["vaultsecretsync"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["lestak.sh"]
  resources: ["vaultsecretsync/status"]
  verbs: ["get", "update", "patch"]
- apiGroups: ["lestak.sh"]
  resources: ["vaultsecretsync/finalizers"]
  verbs: ["update"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vault-secret-sync
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: vault-secret-sync
subjects:
- kind: ServiceAccount
  name: vault-secret-sync
  namespace: vault-secret-sync

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-secret-sync-leader-election
  namespace: vault-secret-sync
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-secret-sync-leader-election
  namespace: vault-secret-sync
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: vault-secret-sync-leader-election
subjects:
- kind: ServiceAccount
  name: vault-secret-sync
  namespace: vault-secret-sync
```

Apply RBAC:
```bash
kubectl apply -f rbac.yaml
```

### Step 7: Create ConfigMap

Create `config.yaml`:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-secret-sync-config
  namespace: vault-secret-sync
data:
  config.yaml: |
    # Logging configuration
    log:
      level: "info"        # debug, info, warn, error
      format: "json"       # json or text
      events: true         # Log sync events

    # Operator configuration
    operator:
      enabled: true
      workerPoolSize: 10   # Number of concurrent sync workers
      numSubscriptions: 5  # Number of queue subscriptions

    # Worker pool size for sync operations (default: 10)
    workerPoolSize: 10

    # Event handler configuration (optional)
    # events:
    #   enabled: true
    #   port: 8080
    #   security:
    #     enabled: true
    #     token: "your-secure-token-here"

    # Metrics server configuration
    metrics:
      port: 9090

    # Notification defaults (optional)
    # notifications:
    #   slack:
    #     url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    #     message: "Secret sync {{.Event}}: {{.VaultSecretSync.Name}}"
```

Apply ConfigMap:
```bash
kubectl apply -f config.yaml
```

### Step 8: Build and Push Container Image

```bash
# Build the image
docker build -t your-registry/vault-secret-sync:latest .

# Push to your registry
docker push your-registry/vault-secret-sync:latest
```

Or use the pre-built image (if available):
```bash
# Use the official image
IMAGE=ghcr.io/robertlestak/vault-secret-sync:latest
```

### Step 9: Create Deployment

Create `deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-secret-sync
  namespace: vault-secret-sync
  labels:
    app: vault-secret-sync
spec:
  replicas: 1  # Single replica recommended for leader election
  selector:
    matchLabels:
      app: vault-secret-sync
  template:
    metadata:
      labels:
        app: vault-secret-sync
    spec:
      serviceAccountName: vault-secret-sync

      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault

      containers:
      - name: vault-secret-sync
        image: your-registry/vault-secret-sync:latest
        imagePullPolicy: Always

        # Security context for container
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true

        # Command
        args:
        - "--config=/config/config.yaml"

        # Environment variables
        env:
        # Vault configuration
        - name: VAULT_ADDR
          value: "https://vault.example.com:8200"
        - name: VAULT_NAMESPACE
          value: "admin"  # Optional: for Vault Enterprise
        # Uncomment if using token auth
        # - name: VAULT_TOKEN
        #   valueFrom:
        #     secretKeyRef:
        #       name: vault-token
        #       key: token

        # GCP configuration (if using service account key)
        # - name: GOOGLE_APPLICATION_CREDENTIALS
        #   value: /var/secrets/google/key.json

        # Logging
        - name: LOG_LEVEL
          value: "info"
        - name: LOG_FORMAT
          value: "json"

        # Ports
        ports:
        - name: metrics
          containerPort: 9090
          protocol: TCP
        - name: http
          containerPort: 8080
          protocol: TCP

        # Resource limits
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"

        # Health checks
        livenessProbe:
          httpGet:
            path: /healthz
            port: 9090
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3

        readinessProbe:
          httpGet:
            path: /readyz
            port: 9090
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3

        # Volume mounts
        volumeMounts:
        - name: config
          mountPath: /config
          readOnly: true
        # Uncomment if using GCP service account key
        # - name: gcp-credentials
        #   mountPath: /var/secrets/google
        #   readOnly: true
        - name: tmp
          mountPath: /tmp

      # Volumes
      volumes:
      - name: config
        configMap:
          name: vault-secret-sync-config
      # Uncomment if using GCP service account key
      # - name: gcp-credentials
      #   secret:
      #     secretName: gcp-credentials
      - name: tmp
        emptyDir: {}

      # Node selector (optional)
      # nodeSelector:
      #   workload: system

      # Tolerations (optional)
      # tolerations:
      # - key: "workload"
      #   operator: "Equal"
      #   value: "system"
      #   effect: "NoSchedule"

---
apiVersion: v1
kind: Service
metadata:
  name: vault-secret-sync
  namespace: vault-secret-sync
  labels:
    app: vault-secret-sync
spec:
  selector:
    app: vault-secret-sync
  ports:
  - name: metrics
    port: 9090
    targetPort: 9090
    protocol: TCP
  - name: http
    port: 8080
    targetPort: 8080
    protocol: TCP
  type: ClusterIP
```

Apply deployment:
```bash
kubectl apply -f deployment.yaml
```

### Step 10: Verify Installation

Check pod status:
```bash
kubectl get pods -n vault-secret-sync
```

Expected output:
```
NAME                                  READY   STATUS    RESTARTS   AGE
vault-secret-sync-7b5d4c8f9d-abcde   1/1     Running   0          1m
```

Check logs:
```bash
kubectl logs -n vault-secret-sync -l app=vault-secret-sync -f
```

Successful startup logs should show:
```json
{"level":"info","msg":"Starting vault-secret-sync operator","time":"2025-11-18T10:00:00Z"}
{"level":"info","msg":"Vault client initialized","time":"2025-11-18T10:00:01Z"}
{"level":"info","msg":"GCP Secret Manager client initialized and permissions validated","time":"2025-11-18T10:00:02Z"}
{"level":"info","msg":"Watching for VaultSecretSync resources","time":"2025-11-18T10:00:03Z"}
```

## Configuration

### Create Your First Secret Sync

Create `my-first-sync.yaml`:
```yaml
apiVersion: lestak.sh/v1alpha1
kind: VaultSecretSync
metadata:
  name: database-credentials
  namespace: vault-secret-sync
spec:
  source:
    vault:
      address: "https://vault.example.com:8200"
      authMethod: "kubernetes"
      role: "vault-secret-sync"
      path: "secret/data/myapp/database"

  destinations:
    - gcp:
        project: "my-gcp-project"
        name: "myapp-database-credentials"
        replicationLocations:
          - "us-central1"
        labels:
          app: "myapp"
          environment: "production"
```

Apply the sync:
```bash
kubectl apply -f my-first-sync.yaml
```

## Verification

### 1. Check CRD Status

```bash
kubectl get vaultsecretsync -n vault-secret-sync
```

Expected output:
```
NAME                   STATUS   AGE
database-credentials   Synced   1m
```

### 2. Check Events

```bash
kubectl get events -n vault-secret-sync --sort-by='.lastTimestamp'
```

Look for events like:
```
LAST SEEN   TYPE     REASON       MESSAGE
1m          Normal   SyncSuccess  Secret synced successfully to GCP
```

### 3. Verify in GCP

```bash
gcloud secrets list --project=my-gcp-project --filter="name:myapp-database-credentials"
```

### 4. Check Metrics

Forward metrics port:
```bash
kubectl port-forward -n vault-secret-sync svc/vault-secret-sync 9090:9090
```

Access metrics:
```bash
curl http://localhost:9090/metrics
```

Look for metrics like:
```
# HELP vault_secret_sync_events_processed_total Total number of events processed
# TYPE vault_secret_sync_events_processed_total counter
vault_secret_sync_events_processed_total 10

# HELP vault_secret_sync_sync_duration_seconds Duration of sync operations
# TYPE vault_secret_sync_sync_duration_seconds histogram
vault_secret_sync_sync_duration_seconds_bucket{le="1"} 8
```

### 5. Test Secret Update

Update secret in Vault:
```bash
vault kv put secret/myapp/database \
  username="admin" \
  password="new-password"
```

Check if it syncs to GCP:
```bash
# Wait a few seconds, then check
gcloud secrets versions list myapp-database-credentials --project=my-gcp-project
```

You should see a new version created.

## Monitoring

### Prometheus Integration

Add ServiceMonitor for Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vault-secret-sync
  namespace: vault-secret-sync
  labels:
    app: vault-secret-sync
spec:
  selector:
    matchLabels:
      app: vault-secret-sync
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

### Grafana Dashboard

Import the provided Grafana dashboard (if available) or create custom panels for:
- Events processed per minute
- Sync success/failure rate
- Sync duration
- Error rate
- Queue depth

## Troubleshooting

### Pod Not Starting

**Check logs:**
```bash
kubectl logs -n vault-secret-sync -l app=vault-secret-sync
```

**Common issues:**
1. **GCP Authentication Failed**
   ```
   Error: failed to create GCP Secret Manager client
   ```
   Solution: Verify Workload Identity binding or service account key

2. **Vault Authentication Failed**
   ```
   Error: failed to authenticate with Vault
   ```
   Solution: Check Vault role and service account binding

3. **Permission Denied**
   ```
   Error: permission validation failed - unable to list secrets
   ```
   Solution: Verify GCP IAM permissions

### Sync Not Working

**Check CRD status:**
```bash
kubectl describe vaultsecretsync database-credentials -n vault-secret-sync
```

**Common issues:**
1. **Vault Path Not Found**
   ```
   Status: Error: secret not found
   ```
   Solution: Verify the secret exists in Vault at the specified path

2. **GCP Project Not Found**
   ```
   Status: Error: project not found
   ```
   Solution: Verify GCP project ID is correct

3. **Size Limit Exceeded**
   ```
   Status: Error: secret size exceeds GCP Secret Manager limit of 64KB
   ```
   Solution: Reduce secret size or split into multiple secrets

### High Memory Usage

**Check resource usage:**
```bash
kubectl top pod -n vault-secret-sync
```

**Solutions:**
1. Reduce worker pool size in config:
   ```yaml
   workerPoolSize: 5  # Reduce from 10
   ```

2. Increase memory limits in deployment:
   ```yaml
   resources:
     limits:
       memory: "1Gi"  # Increase from 512Mi
   ```

### Rate Limiting Issues

**Symptoms:**
```
HTTP 429: Rate limit exceeded
```

**Solution:**
Adjust rate limit in config:
```yaml
events:
  security:
    enabled: true
    rateLimit:
      requestsPerSecond: 20  # Increase from 10
      burst: 40              # Increase from 20
```

## Upgrade

### Rolling Update

```bash
# Update image in deployment
kubectl set image deployment/vault-secret-sync \
  vault-secret-sync=your-registry/vault-secret-sync:v2.0.0 \
  -n vault-secret-sync

# Watch rollout
kubectl rollout status deployment/vault-secret-sync -n vault-secret-sync
```

### Rollback

```bash
# Rollback to previous version
kubectl rollout undo deployment/vault-secret-sync -n vault-secret-sync

# Or to specific revision
kubectl rollout history deployment/vault-secret-sync -n vault-secret-sync
kubectl rollout undo deployment/vault-secret-sync --to-revision=2 -n vault-secret-sync
```

## Uninstall

```bash
# Delete all VaultSecretSync resources
kubectl delete vaultsecretsync --all -n vault-secret-sync

# Delete deployment
kubectl delete -f deployment.yaml

# Delete RBAC
kubectl delete -f rbac.yaml

# Delete ConfigMap
kubectl delete -f config.yaml

# Delete CRDs
kubectl delete -f deploy/charts/vault-secret-sync/crds/

# Delete namespace
kubectl delete namespace vault-secret-sync
```

## Best Practices

1. **Use Workload Identity** instead of service account keys
2. **Enable RBAC** and principle of least privilege
3. **Set resource limits** to prevent resource exhaustion
4. **Monitor metrics** for sync success rate and latency
5. **Use dry-run mode** first to test configurations
6. **Implement notifications** for sync failures
7. **Rotate credentials** regularly
8. **Test rollback procedures** before production
9. **Use multiple replicas** only if leader election is configured
10. **Keep secrets in Vault** as the source of truth

## Next Steps

- Configure notifications for sync events
- Set up monitoring and alerting
- Create multiple sync configurations for different applications
- Implement backup and disaster recovery procedures
- Review security audit logs regularly

## Support

For issues and questions:
- GitHub Issues: https://github.com/robertlestak/vault-secret-sync/issues
- Documentation: https://github.com/robertlestak/vault-secret-sync/tree/main/docs
