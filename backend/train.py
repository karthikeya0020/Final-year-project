"""
Training Script for WAF Transformer Model

Generates synthetic training data for 4 classes (Normal, SQL Injection, DDoS, MITM)
and trains the Transformer classifier.
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import os
import sys

from model import get_model, CLASSES, FEATURE_DIM


def generate_synthetic_data(num_samples_per_class=2500, noise_level=0.15):
    """
    Generate synthetic feature vectors for each attack class.

    Each sample is a 16-dimensional feature vector.
    Features:
        0: body_length        1: url_length         2: param_count
        3: header_count       4: special_char_density  5: sql_keyword_count
        6: sql_pattern_score  7: suspicious_sql     8: request_rate
        9: requests_per_sec   10: method_encoding   11: missing_security_headers
        12: protocol_anomaly  13: user_agent_anomaly  14: cookie_anomaly
        15: payload_entropy
    """

    all_features = []
    all_labels = []
    rng = np.random.default_rng(42)

    for class_idx, class_name in enumerate(CLASSES):
        features = np.zeros((num_samples_per_class, FEATURE_DIM), dtype=np.float32)

        if class_name == "Normal":
            # Normal traffic: low special chars, no SQL, low rate, proper headers
            features[:, 0] = rng.uniform(0.0, 0.5, num_samples_per_class)     # body_len
            features[:, 1] = rng.uniform(0.1, 0.5, num_samples_per_class)     # url_len
            features[:, 2] = rng.uniform(0.0, 0.3, num_samples_per_class)     # params
            features[:, 3] = rng.uniform(0.3, 0.7, num_samples_per_class)     # headers
            features[:, 4] = rng.uniform(0.0, 0.3, num_samples_per_class)     # special chars
            features[:, 5] = rng.uniform(0.0, 0.1, num_samples_per_class)     # sql keywords
            features[:, 6] = rng.uniform(0.0, 0.0, num_samples_per_class)     # sql patterns
            features[:, 7] = rng.uniform(0.0, 0.0, num_samples_per_class)     # suspicious sql
            features[:, 8] = rng.uniform(0.0, 0.15, num_samples_per_class)    # request rate
            features[:, 9] = rng.uniform(0.0, 0.1, num_samples_per_class)     # rps
            features[:, 10] = rng.choice([0.2, 0.4], num_samples_per_class)   # GET/POST
            features[:, 11] = rng.uniform(0.0, 0.3, num_samples_per_class)    # missing headers
            features[:, 12] = 0.0                                              # https
            features[:, 13] = rng.uniform(0.0, 0.3, num_samples_per_class)    # normal UA
            features[:, 14] = rng.uniform(0.0, 0.5, num_samples_per_class)    # cookie
            features[:, 15] = rng.uniform(0.5, 1.5, num_samples_per_class)    # entropy

        elif class_name == "SQL_Injection":
            # SQL Injection: high special chars, SQL keywords, patterns present
            features[:, 0] = rng.uniform(0.1, 1.5, num_samples_per_class)     # body_len
            features[:, 1] = rng.uniform(0.3, 2.0, num_samples_per_class)     # longer URLs
            features[:, 2] = rng.uniform(0.1, 0.8, num_samples_per_class)     # params
            features[:, 3] = rng.uniform(0.2, 0.6, num_samples_per_class)     # headers
            features[:, 4] = rng.uniform(1.5, 5.0, num_samples_per_class)     # HIGH special chars
            features[:, 5] = rng.uniform(1.5, 5.0, num_samples_per_class)     # HIGH sql keywords
            features[:, 6] = rng.uniform(1.0, 5.0, num_samples_per_class)     # HIGH sql patterns
            features[:, 7] = rng.uniform(1.0, 5.0, num_samples_per_class)     # HIGH suspicious
            features[:, 8] = rng.uniform(0.0, 0.3, num_samples_per_class)     # normal rate
            features[:, 9] = rng.uniform(0.0, 0.2, num_samples_per_class)     # normal rps
            features[:, 10] = rng.choice([0.2, 0.4], num_samples_per_class)   # GET/POST
            features[:, 11] = rng.uniform(0.0, 0.4, num_samples_per_class)    # headers ok
            features[:, 12] = rng.choice([0.0, 1.0], num_samples_per_class, p=[0.8, 0.2])
            features[:, 13] = rng.uniform(0.0, 1.0, num_samples_per_class)    # various UA
            features[:, 14] = rng.uniform(0.0, 1.0, num_samples_per_class)    # cookie
            features[:, 15] = rng.uniform(1.5, 4.0, num_samples_per_class)    # high entropy

        elif class_name == "DDoS":
            # DDoS: very high request rate & rps, otherwise normal-looking
            features[:, 0] = rng.uniform(0.0, 0.3, num_samples_per_class)     # small body
            features[:, 1] = rng.uniform(0.1, 0.4, num_samples_per_class)     # short URL
            features[:, 2] = rng.uniform(0.0, 0.2, num_samples_per_class)     # few params
            features[:, 3] = rng.uniform(0.1, 0.4, num_samples_per_class)     # few headers
            features[:, 4] = rng.uniform(0.0, 0.3, num_samples_per_class)     # low special
            features[:, 5] = rng.uniform(0.0, 0.1, num_samples_per_class)     # no sql
            features[:, 6] = 0.0                                               # no sql
            features[:, 7] = 0.0                                               # no sql
            features[:, 8] = rng.uniform(2.0, 5.0, num_samples_per_class)     # VERY HIGH rate
            features[:, 9] = rng.uniform(2.0, 5.0, num_samples_per_class)     # VERY HIGH rps
            features[:, 10] = rng.choice([0.2, 0.4], num_samples_per_class)   # GET/POST
            features[:, 11] = rng.uniform(0.3, 1.0, num_samples_per_class)    # often missing
            features[:, 12] = rng.choice([0.0, 1.0], num_samples_per_class, p=[0.5, 0.5])
            features[:, 13] = rng.uniform(1.0, 3.0, num_samples_per_class)    # bot-like UA
            features[:, 14] = rng.uniform(0.5, 1.5, num_samples_per_class)    # no cookies
            features[:, 15] = rng.uniform(0.3, 1.0, num_samples_per_class)    # low entropy

        elif class_name == "MITM":
            # MITM: protocol anomalies, missing security headers, tampered cookies
            features[:, 0] = rng.uniform(0.0, 0.8, num_samples_per_class)     # body_len
            features[:, 1] = rng.uniform(0.1, 0.6, num_samples_per_class)     # url_len
            features[:, 2] = rng.uniform(0.0, 0.3, num_samples_per_class)     # params
            features[:, 3] = rng.uniform(0.1, 0.5, num_samples_per_class)     # fewer headers
            features[:, 4] = rng.uniform(0.0, 0.5, num_samples_per_class)     # some special
            features[:, 5] = rng.uniform(0.0, 0.2, num_samples_per_class)     # low sql
            features[:, 6] = rng.uniform(0.0, 0.1, num_samples_per_class)     # low sql
            features[:, 7] = 0.0                                               # no sql
            features[:, 8] = rng.uniform(0.0, 0.5, num_samples_per_class)     # moderate rate
            features[:, 9] = rng.uniform(0.0, 0.3, num_samples_per_class)     # moderate rps
            features[:, 10] = rng.choice([0.2, 0.4, 0.6], num_samples_per_class)
            features[:, 11] = rng.uniform(0.6, 1.0, num_samples_per_class)    # HIGH missing
            features[:, 12] = rng.choice([0.0, 1.0], num_samples_per_class, p=[0.2, 0.8])  # HTTP!
            features[:, 13] = rng.uniform(0.5, 2.0, num_samples_per_class)    # anomalous UA
            features[:, 14] = rng.uniform(1.0, 1.5, num_samples_per_class)    # NO cookies
            features[:, 15] = rng.uniform(0.8, 2.5, num_samples_per_class)    # moderate entropy

        # Add noise to make training more robust
        noise = rng.normal(0, noise_level, features.shape).astype(np.float32)
        features = np.clip(features + noise, 0, 5)

        labels = np.full(num_samples_per_class, class_idx, dtype=np.int64)

        all_features.append(features)
        all_labels.append(labels)

    X = np.concatenate(all_features, axis=0)
    y = np.concatenate(all_labels, axis=0)

    # Shuffle
    indices = rng.permutation(len(X))
    return X[indices], y[indices]


def train_model():
    """Train the WAF Transformer model on synthetic data."""

    print("=" * 60)
    print("  WAF Transformer Model Training")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\nDevice: {device}")

    # Generate synthetic data
    print("\n[1/4] Generating synthetic training data...")
    X_train, y_train = generate_synthetic_data(num_samples_per_class=2500)
    X_val, y_val = generate_synthetic_data(num_samples_per_class=500, noise_level=0.2)
    print(f"  Training samples: {len(X_train)}")
    print(f"  Validation samples: {len(X_val)}")
    for i, cls in enumerate(CLASSES):
        count = np.sum(y_train == i)
        print(f"    {cls}: {count} samples")

    # Create data loaders
    train_dataset = TensorDataset(
        torch.FloatTensor(X_train), torch.LongTensor(y_train)
    )
    val_dataset = TensorDataset(
        torch.FloatTensor(X_val), torch.LongTensor(y_val)
    )
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=128)

    # Create model
    print("\n[2/4] Initializing Transformer model...")
    model = get_model(device)
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Total parameters: {total_params:,}")
    print(f"  Trainable parameters: {trainable_params:,}")

    # Training setup
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=50)

    # Training loop
    print("\n[3/4] Training...")
    best_val_acc = 0
    epochs = 50

    for epoch in range(epochs):
        # Train
        model.train()
        train_loss = 0
        train_correct = 0
        train_total = 0

        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)

            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

            train_loss += loss.item() * batch_x.size(0)
            _, predicted = outputs.max(1)
            train_total += batch_y.size(0)
            train_correct += predicted.eq(batch_y).sum().item()

        scheduler.step()

        train_loss /= train_total
        train_acc = 100.0 * train_correct / train_total

        # Validate
        model.eval()
        val_correct = 0
        val_total = 0

        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                outputs = model(batch_x)
                _, predicted = outputs.max(1)
                val_total += batch_y.size(0)
                val_correct += predicted.eq(batch_y).sum().item()

        val_acc = 100.0 * val_correct / val_total

        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(
                f"  Epoch [{epoch+1:3d}/{epochs}]  "
                f"Loss: {train_loss:.4f}  "
                f"Train Acc: {train_acc:.1f}%  "
                f"Val Acc: {val_acc:.1f}%"
            )

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), "waf_model.pth")

    # Final evaluation
    print(f"\n[4/4] Training complete!")
    print(f"  Best Validation Accuracy: {best_val_acc:.1f}%")

    # Per-class accuracy
    model.load_state_dict(torch.load("waf_model.pth", map_location=device, weights_only=True))
    model.eval()

    class_correct = [0] * len(CLASSES)
    class_total = [0] * len(CLASSES)

    with torch.no_grad():
        for batch_x, batch_y in val_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            outputs = model(batch_x)
            _, predicted = outputs.max(1)
            for i in range(batch_y.size(0)):
                label = batch_y[i].item()
                class_total[label] += 1
                if predicted[i] == label:
                    class_correct[label] += 1

    print("\n  Per-class accuracy:")
    for i, cls in enumerate(CLASSES):
        if class_total[i] > 0:
            acc = 100.0 * class_correct[i] / class_total[i]
            print(f"    {cls:15s}: {acc:.1f}%  ({class_correct[i]}/{class_total[i]})")

    print(f"\n  Model saved to: waf_model.pth")
    print(f"  Model size: {os.path.getsize('waf_model.pth') / 1024:.1f} KB")
    print("=" * 60)

    return model


if __name__ == "__main__":
    train_model()
