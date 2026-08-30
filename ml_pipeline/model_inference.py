import os
import sys
import pickle
import time
import torch
import numpy as np
from datetime import datetime

# Import training/feature specs
from model_training import MODELS_DIR, FEATURE_KEYS, Autoencoder, engineer_features, ensemble_voting

# Global loaded models cache at edge
edge_models = {
    'iforest': None,
    'autoencoder': None,
    'baselines': {
        'iforest_mean': 0.0,
        'iforest_std': 1.0,
        'ae_mean': 0.0,
        'ae_std': 1.0
    }
}

def deploy_model_to_edge():
    """
    Step 3.1: Package and deploy trained models to the Edge Agent.
    Loads serialized models, packages them with metadata, and simulates a gRPC push.
    """
    iforest_path = os.path.join(MODELS_DIR, "iforest_model.pkl")
    autoencoder_path = os.path.join(MODELS_DIR, "autoencoder_model.pth")
    
    if not os.path.exists(iforest_path) or not os.path.exists(autoencoder_path):
        raise FileNotFoundError("Trained models not found. Please run Phase 2 first.")
        
    # 1. Package model components
    model_package = {
        'version': '1.0.0',
        'training_date': datetime.now().isoformat(),
        'iforest_path': iforest_path,
        'autoencoder_path': autoencoder_path,
        'baselines': {
            'iforest_mean': -0.43,
            'iforest_std': 0.07,
            'ae_mean': 47200.0,
            'ae_std': 218490.0
        }
    }
    
    # 2. Simulate gRPC loading onto Edge Agent Cache
    try:
        # Load Isolation Forest
        with open(iforest_path, "rb") as f:
            edge_models['iforest'] = pickle.load(f)
            
        # Load Autoencoder state dict
        ae = Autoencoder(input_dim=len(FEATURE_KEYS))
        ae.load_state_dict(torch.load(autoencoder_path))
        ae.eval()
        edge_models['autoencoder'] = ae
        
        # Load baselines
        edge_models['baselines'] = model_package['baselines']
        
        print(f"✅ Model deployed to Edge Agent: version={model_package['version']} ({len(FEATURE_KEYS)} features)")
        return True
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        return False

def edge_inference(container_id, event_window):
    """
    Step 3.2: Edge Inference (Real-time).
    Runs local inference combining both models and maps threat severity.
    """
    if edge_models['iforest'] is None or edge_models['autoencoder'] is None:
        # Load models if not already deployed
        deploy_model_to_edge()
        
    # 1. Prepare features from window
    features = engineer_features(event_window)
    
    # 2. Run Isolation Forest
    iforest_raw = edge_models['iforest'].score_samples(features)[0]
    # Map raw negative score to an anomaly intensity (outlier magnitude)
    iforest_score = max(0.0, -iforest_raw)
    
    # 3. Run Autoencoder
    ae = edge_models['autoencoder']
    test_tensor = torch.tensor(features, dtype=torch.float32)
    with torch.no_grad():
        reconstructed = ae(test_tensor)
        ae_score = torch.mean((test_tensor - reconstructed) ** 2).item()
        
    # 4. Ensemble
    scores = {
        'isolation_forest': iforest_score,
        'autoencoder': ae_score
    }
    final_score = ensemble_voting(scores, weights={'iforest': 0.5, 'autoencoder': 0.5})
    
    # 5. Classify severity based on combined baseline thresholds
    # We use Autoencoder reconstruction error scale for severity bounds
    ae_mean = edge_models['baselines']['ae_mean']
    ae_std = edge_models['baselines']['ae_std']
    
    threshold_critical = ae_mean + 3 * ae_std
    threshold_high = ae_mean + 1.5 * ae_std
    threshold_medium = ae_mean + 0.5 * ae_std
    
    if ae_score > threshold_critical or iforest_score > 0.8:
        severity = 'CRITICAL'
    elif ae_score > threshold_high or iforest_score > 0.65:
        severity = 'HIGH'
    elif ae_score > threshold_medium or iforest_score > 0.5:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'
        
    return {
        'container_id': container_id,
        'timestamp': time.time(),
        'score': round(final_score, 4),
        'severity': severity,
        'iforest_score': round(float(iforest_score), 4),
        'ae_score': round(float(ae_score), 4)
    }

def kernel_inference():
    """
    Step 3.3: Kernel-Level Inference (Optimized).
    Simulates compiling, pinning, and polling from a kernel-level eBPF program.
    """
    print("\n[Kernel Inference Simulation]")
    print("1. Translating model rules to BPF-compatible structures...")
    print("2. Attaching kprobe helper to 'sys_enter_execve'...")
    print("3. Polling kernel BPF perf buffer score map...")
    
    # Simulate a loop yielding kernel-level events
    time.sleep(0.5)
    print("   [BPF Map Event] PID 23819: Spawned bash shell with anomaly score=0.88")
    print("✅ Kernel inference handler polling active.")
    return True
