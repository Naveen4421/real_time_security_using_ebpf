import numpy as np
import pickle
import os
import torch
import torch.nn as nn
import torch.optim as optim
from datetime import datetime

# Setup models directory
MODELS_DIR = "models"
os.makedirs(MODELS_DIR, exist_ok=True)

# List of ordered feature keys to ensure consistent array shapes
FEATURE_KEYS = [
    "syscall_frequency",
    "unique_syscalls",
    "file_access_rate",
    "unique_files",
    "sensitive_file_access",
    "network_connections",
    "unique_ports",
    "outbound_traffic",
    "process_executions",
    "unique_processes",
    "process_hierarchy_depth",
    "cpu_usage",
    "memory_usage",
    "io_wait"
]

def engineer_features(raw_data):
    """
    Step 2.1: Feature Engineering.
    Extracts ordered feature list from raw window stats or data lists.
    Accepts a single stats dictionary or a list of dictionaries.
    """
    if isinstance(raw_data, list):
        features_list = []
        for item in raw_data:
            features_list.append([float(item.get(k, 0.0)) for k in FEATURE_KEYS])
        return np.array(features_list, dtype=np.float32)
    elif isinstance(raw_data, dict):
        return np.array([[float(raw_data.get(k, 0.0)) for k in FEATURE_KEYS]], dtype=np.float32)
    else:
        raise ValueError("Unsupported data type for feature engineering")

def train_isolation_forest(features):
    """
    Step 2.2: Train Isolation Forest anomaly detection model.
    """
    from sklearn.ensemble import IsolationForest
    
    # Instantiate and fit Isolation Forest
    model = IsolationForest(
        contamination=0.05,  # Expected 5% anomaly rate
        n_estimators=100,
        max_samples='auto',
        random_state=42
    )
    model.fit(features)
    
    # Calculate sample scores (higher score means less anomalous, lower score/negative means anomalous)
    scores = model.score_samples(features)
    
    baseline = {
        'mean': float(np.mean(scores)),
        'std': float(np.std(scores)),
        'percentiles': [float(p) for p in np.percentile(scores, [90, 95, 99])]
    }
    
    # Save model binary
    model_path = os.path.join(MODELS_DIR, "iforest_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
        
    print(f"✅ Isolation Forest trained and saved to {model_path}")
    return model, baseline

class Autoencoder(nn.Module):
    """
    Step 2.3: PyTorch Deep Learning Autoencoder.
    """
    def __init__(self, input_dim=14):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 4)  # Encoding dimension (bottleneck)
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim)
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def train_autoencoder(features):
    """
    Step 2.3: Train Deep Learning Autoencoder.
    Uses Reconstruction Error (MSE) as anomaly metric.
    """
    # Convert numpy array to torch tensor
    tensor_data = torch.tensor(features, dtype=torch.float32)
    
    # Initialize model, optimizer, loss
    model = Autoencoder(input_dim=len(FEATURE_KEYS))
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    criterion = nn.MSELoss()
    
    # Mini training loop
    epochs = 100
    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        outputs = model(tensor_data)
        loss = criterion(outputs, tensor_data)
        loss.backward()
        optimizer.step()
        
    # Compute reconstruction loss baseline metrics
    model.eval()
    with torch.no_grad():
        reconstructed = model(tensor_data)
        losses = torch.mean((tensor_data - reconstructed) ** 2, dim=1).numpy()
        
    baseline = {
        'mean': float(np.mean(losses)),
        'std': float(np.std(losses)),
        'percentiles': [float(p) for p in np.percentile(losses, [90, 95, 99])]
    }
    
    # Save model state dict
    model_path = os.path.join(MODELS_DIR, "autoencoder_model.pth")
    torch.save(model.state_dict(), model_path)
    
    print(f"✅ Deep learning Autoencoder trained and saved to {model_path}")
    return model, baseline

def ensemble_voting(scores, weights={'iforest': 0.5, 'autoencoder': 0.5}):
    """
    Step 2.4: Ensemble Voting.
    Combines Isolation Forest anomaly score and Autoencoder reconstruction loss.
    """
    # Combine scores with provided weights
    final_score = (
        scores['isolation_forest'] * weights['iforest'] +
        scores['autoencoder'] * weights['autoencoder']
    )
    
    return final_score
