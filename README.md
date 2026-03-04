# AI-Based Web Application Firewall (WAF)

## Abstract

This project presents an AI-based Web Application Firewall (WAF) designed to detect and prevent malicious web attacks using machine learning techniques. Unlike traditional rule-based WAF systems, this implementation leverages a Transformer-based deep learning model to classify incoming web requests as benign or malicious. The system improves adaptability and detection accuracy against modern and evolving cyber threats such as SQL Injection (SQLi) and Cross-Site Scripting (XSS).

---

## Introduction

Web applications are increasingly targeted by sophisticated cyber-attacks. Traditional Web Application Firewalls rely primarily on predefined rules and signatures, which can fail to detect zero-day or obfuscated attacks.

This project proposes a machine learning-driven WAF that:

* Extracts relevant features from incoming HTTP requests
* Uses a trained deep learning model for classification
* Identifies malicious traffic patterns
* Generates security reports
* Simulates traffic for testing and validation

The system demonstrates how artificial intelligence can enhance modern cybersecurity solutions.

---

## Objectives

* To design a Web Application Firewall using machine learning.
* To implement a Transformer-based model for attack classification.
* To detect common web-based attacks such as SQL Injection and XSS.
* To generate automated reports for security analysis.
* To provide a simple frontend interface for interaction.

---

## System Architecture

The project consists of two main components:

### Backend

* Built using Python and Flask
* Handles request processing and classification
* Includes feature extraction and model inference
* Generates security reports

### Frontend

* Developed using HTML, CSS, and JavaScript
* Provides a user interface for testing requests
* Displays detection results

---

## Technology Stack

### Backend

* Python
* PyTorch
* NumPy
* Pandas

### Frontend

* HTML
* CSS
* JavaScript

### Version Control

* Git
* GitHub

---

## Project Structure

```
Final-year-project/
│
├── backend/
│   ├── app.py
│   ├── model.py
│   ├── train.py
│   ├── feature_extractor.py
│   ├── domain_scanner.py
│   ├── traffic_simulator.py
│   ├── generate_report.py
│   └── requirements.txt
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── WAF_Project_Report.pdf
└── README.md
```

---

## Installation and Setup

### Step 1: Clone the Repository

```
git clone https://github.com/karthikeya0020/Final-year-project.git
cd Final-year-project
```

### Step 2: Install Dependencies

```
pip install -r backend/requirements.txt
```

### Step 3: Run the Backend Server

```
cd backend
python app.py
```

The server will run locally at:

```
http://127.0.0.1:5000/
```

### Step 4: Open the Frontend

Open the file `frontend/index.html` in a web browser to access the interface.

---

## Model Training

To retrain the model:

```
cd backend
python train.py
```

The trained model file will be saved as:

```
waf_model.pth
```

---

## Working Principle

1. A user submits a web request through the interface.
2. The backend extracts relevant features from the request.
3. The Transformer-based model processes the features.
4. The request is classified as benign or malicious.
5. A report is generated for analysis.

---

## Future Enhancements

* Deployment on cloud infrastructure
* Real-time monitoring of live traffic
* Integration with production web servers
* Expansion of training dataset
* Containerization using Docker

---

## Conclusion

This project demonstrates the practical application of machine learning in cybersecurity. By integrating a Transformer-based classification model with a Web Application Firewall framework, the system provides improved detection capabilities compared to traditional rule-based approaches. The project highlights the potential of artificial intelligence in strengthening web application security.

---

## Author

Karthikeya
Final Year Engineering Project
Department of Computer Science / Cybersecurity
