# Transformer-Based WAF Pipeline

A **Transformer neural network**-powered Web Application Firewall (WAF) prototype that detects three types of cyber attacks in real-time:

- 🛡️ **SQL Injection** — Detects malicious SQL payloads in HTTP parameters
- ⚡ **DDoS Attack** — Identifies high-rate request flooding patterns
- 👁️ **Man-in-the-Middle (MITM)** — Detects protocol downgrade and header anomalies

## Architecture

```
HTTP Request → Feature Extractor (16-dim) → Transformer Encoder → Classification → Dashboard
```

**Model**: 2-layer Transformer Encoder with 4 attention heads, CLS token, and a 4-class softmax output.

## Quick Start

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Train the Model
```bash
python train.py
```
This generates synthetic training data and trains the Transformer model (~50 epochs). The trained weights are saved to `waf_model.pth`.

### 3. Run the Server
```bash
python app.py
```

### 4. Open the Dashboard
Open **http://localhost:5000** in your browser.

- Click **"Start Simulation"** to begin live traffic analysis
- Use the **Attack Tester** panel to test specific attack payloads
- Watch the **Live Traffic Monitor** and **Detection Logs** update in real-time

## Tech Stack

| Component | Technology |
|-----------|-----------|
| ML Model | PyTorch Transformer Encoder |
| Backend | Python Flask |
| Frontend | HTML/CSS/JS + Chart.js |
| Features | 16-dimensional HTTP request vector |

## Project Structure

```
Waf-project/
├── backend/
│   ├── app.py                  # Flask REST API
│   ├── model.py                # Transformer classifier
│   ├── feature_extractor.py    # HTTP → feature vector
│   ├── train.py                # Training script
│   ├── traffic_simulator.py    # Live traffic generator
│   └── requirements.txt        # Python dependencies
├── frontend/
│   ├── index.html              # Dashboard UI
│   ├── style.css               # Dark-mode styles
│   └── app.js                  # Dashboard logic
└── README.md
```

## University Project

This is a prototype developed for academic purposes demonstrating the application of Transformer architectures to network security (WAF) use cases.
