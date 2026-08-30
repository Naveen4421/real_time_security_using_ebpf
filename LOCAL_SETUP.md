# Local Setup & Technology Stack Guide

This document describes the technology stack used in this project and provides step-by-step instructions on how to start and run the application locally.

---

## 🛠️ Technology Stack Index

The project is structured into three primary layers: the Edge Security Agent, the Observability Stack, and the ML Pipeline.

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Frontend** | HTML5, CSS3, Vanilla JS | Glassmorphic real-time security telemetry dashboard. |
| **Backend** | Node.js, Express | REST API, simulation engine, webhook alerts receiver. |
| **ML Engine** | Python 3.12, PyTorch, Scikit-Learn | Vectorization, Isolation Forest anomaly mapping, PyTorch Autoencoder reconstruction loss. |
| **Containerization** | Docker, Docker Compose | Orchestrates all local simulator and ML agent services. |
| **Kubernetes** | Minikube, kubectl | Local K8s cluster node agent target (DaemonSet deployments). |
| **Log Management** | Grafana Loki, Promtail | Centralized log ingestion and shipping from container runtime sockets. |
| **Host Metrics** | Prometheus Node Exporter | Scrapes CPU, memory, filesystem, and network usage. |

---

## 📋 System Prerequisites

Before starting, ensure you have the following installed on your host:
*   **Docker & Docker Compose**
*   **Minikube**
*   **Python 3.12** (Optional, if running ML tests outside containers)

---

## 🚀 How to Start the Project (Step-by-Step)

### Step 1: Start Docker Compose Stack
This spins up the frontend console, Express backend, Loki log server, Promtail log collector, Node Exporter, and the real-time Python ML telemetry agent.

Run the following command from the root of the project directory:
```bash
docker compose up --build -d
```

To verify that all containers started successfully:
```bash
docker compose ps
```
All services should show a state of `Running` or `Up`.

---

### Step 2: Access the Console Dashboard
Open your web browser and navigate to:
*   **Frontend Console:** [http://localhost:8080](http://localhost:8080)
*   **Backend REST API:** [http://localhost:5000](http://localhost:5000)

---

### Step 3: Monitor Live ML Telemetry Logs
To view the real-time streaming sliding window calculations from the containerized ML security agent:
```bash
docker compose logs -f ml-agent
```

---

### Step 4: Start local Kubernetes cluster (Minikube)
If you want to run Kubernetes metadata tests or deploy DaemonSet probes on local nodes:
```bash
minikube start
```
Verify the cluster status:
```bash
kubectl get nodes
```

---

## 🧪 Validating the ML Pipeline Locally (Optional)

If you are developing or retraining ML models, you can run the test runners locally outside Docker:

1. **Install Local Python Dependencies:**
   ```bash
   pip install -r ml_pipeline/requirements.txt
   ```

2. **Run Phase 1 (Telemetry Collection & Windowing):**
   ```bash
   python3 ml_pipeline/test_phase1.py
   ```

3. **Run Phase 2 (Train Isolation Forest & PyTorch Autoencoder):**
   ```bash
   python3 ml_pipeline/test_phase2.py
   ```

4. **Run Phase 3 (Deploy & Evaluate Edge Inference):**
   ```bash
   python3 ml_pipeline/test_phase3.py
   ```
