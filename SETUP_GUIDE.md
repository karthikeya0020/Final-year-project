# Installation & Setup Guide

Step-by-step guide to set up the **Transformer-Based WAF Pipeline** on a fresh PC.

---

## Prerequisites

| Software | Version | Download |
|----------|---------|----------|
| Python | 3.10 or higher | [python.org/downloads](https://www.python.org/downloads/) |
| pip | (comes with Python) | — |
| Git | (optional, for cloning) | [git-scm.com](https://git-scm.com/) |
| Web Browser | Chrome / Edge / Firefox | — |

> **Important:** During Python installation, check **"Add Python to PATH"**.

---

## Step 1 — Get the Project Files

**Option A: Copy the folder**
Copy the entire `Waf-project` folder to the new PC via USB, OneDrive, Google Drive, etc.

**Option B: Clone from Git (if uploaded)**
```bash
git clone <your-repo-url>
cd Waf-project
```

Your folder should look like this:
```
Waf-project/
├── backend/
│   ├── app.py
│   ├── model.py
│   ├── feature_extractor.py
│   ├── train.py
│   ├── traffic_simulator.py
│   ├── generate_report.py
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── README.md
└── SETUP_GUIDE.md  (this file)
```

---

## Step 2 — Verify Python Installation

Open **Terminal** (or **Command Prompt** / **PowerShell** on Windows) and run:

```bash
python --version
```

You should see something like `Python 3.12.x`. If not, install Python first.

Also verify pip:
```bash
pip --version
```

---

## Step 3 — Install Dependencies

Navigate to the backend folder and install required packages:

```bash
cd Waf-project/backend
pip install -r requirements.txt
```

This installs:
- **Flask** — Web server framework
- **flask-cors** — Cross-origin support
- **PyTorch** — Deep learning framework (for the Transformer model)
- **NumPy** — Numerical computation

> **Note:** PyTorch download is ~200 MB. On slow internet, this may take a few minutes.

> **If you get an error on `torch`**, try installing it separately:
> ```bash
> pip install torch --index-url https://download.pytorch.org/whl/cpu
> ```

---

## Step 4 — Train the Model

Run the training script to generate the model weights:

```bash
cd Waf-project/backend
python train.py
```

**Expected output:**
```
============================================================
  WAF Transformer Model Training
============================================================

Device: cpu

[1/4] Generating synthetic training data...
  Training samples: 10000
  Validation samples: 2000

[2/4] Initializing Transformer model...
  Total parameters: 69,668

[3/4] Training...
  Epoch [  1/50]  Loss: 0.9834  Train Acc: 67.2%  Val Acc: 95.6%
  ...
  Epoch [ 50/50]  Loss: 0.0002  Train Acc: 100.0%  Val Acc: 100.0%

[4/4] Training complete!
  Best Validation Accuracy: 100.0%
  Model saved to: waf_model.pth
============================================================
```

This creates `waf_model.pth` (~286 KB) in the backend folder.

> **Alternatively:** If you already have `waf_model.pth` from another PC, just copy it into `backend/` and skip this step.

---

## Step 5 — Start the Server

```bash
cd Waf-project/backend
python app.py
```

**Expected output:**
```
============================================================
  Transformer-Based WAF Pipeline
============================================================
[WAF] Loading trained model from waf_model.pth
[WAF] Model loaded successfully

[WAF] Starting server on http://localhost:5000
[WAF] Dashboard: http://localhost:5000
============================================================
 * Running on http://127.0.0.1:5000
```

> **Keep this terminal open!** The server needs to keep running.

---

## Step 6 — Open the Dashboard

Open your web browser and go to:

```
http://localhost:5000
```

You should see the **WAF Shield** dashboard with:
- Stats bar (total requests, blocked, allowed)
- Live Traffic Monitor chart
- Threat Breakdown chart
- Attack Tester panel
- Detection Logs table

---

## Step 7 — Test It!

1. Click **"Start Simulation"** to begin live traffic monitoring
2. Watch the charts and logs update in real-time
3. Use the **Attack Tester** panel:
   - Click **"SQL Injection"** → Should show BLOCKED (99%+ confidence)
   - Click **"DDoS Attack"** → Should show BLOCKED (100% confidence)
   - Click **"MITM Attack"** → Should show BLOCKED (99%+ confidence)
   - Click **"Normal"** → Should show ALLOWED
4. Type a custom payload like `' OR 1=1 --` and click **"Analyze"**

---

## Optional — Generate PDF Report

```bash
cd Waf-project/backend
pip install fpdf2
python generate_report.py
```

This creates `WAF_Project_Report.pdf` in the project root folder.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `python` not recognized | Install Python and check "Add to PATH" during installer |
| `pip install` fails | Try `python -m pip install -r requirements.txt` |
| PyTorch install error | Use: `pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| Port 5000 in use | Kill the other process, or edit `app.py` line: `app.run(port=5001)` |
| Dashboard shows errors | Make sure `python app.py` is still running in the terminal |
| Model accuracy is low | Delete `waf_model.pth` and re-run `python train.py` |

---

## Quick Reference (All Commands)

```bash
# 1. Install dependencies
cd Waf-project/backend
pip install -r requirements.txt

# 2. Train the model (one-time)
python train.py

# 3. Start the server
python app.py

# 4. Open in browser
# http://localhost:5000

# 5. Generate PDF report (optional)
pip install fpdf2
python generate_report.py
```

---

## File Summary

| File | What it does |
|------|-------------|
| `model.py` | Transformer neural network architecture |
| `feature_extractor.py` | Converts HTTP requests to 16-dim feature vectors |
| `train.py` | Generates training data and trains the model |
| `traffic_simulator.py` | Simulates live traffic with attack patterns |
| `app.py` | Flask web server (API + serves dashboard) |
| `generate_report.py` | Generates the PDF project report |
| `waf_model.pth` | Trained model weights (generated by train.py) |
| `index.html` | Dashboard webpage |
| `style.css` | Dashboard styling (dark mode) |
| `app.js` | Dashboard interactivity and charts |
