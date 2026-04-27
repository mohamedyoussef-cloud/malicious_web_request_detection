# Malicious Web Request Detection

A simple Streamlit application that detects whether a URL or web request looks benign or malicious.

## Features

- URL/request classification
- Risk score
- Simple explanation of suspicious patterns
- Character-level TF-IDF features
- URL structure features
- Lightweight Linear SVM model

## Dataset Format

Place your dataset here:

```text
data/dataset.csv
```

Required columns:

```csv
url,label
https://example.com,0
http://test.com/?id=1 union select password,1
```

Where:

- `0` = benign
- `1` = malicious

## Train the Model

```bash
python train_model.py
```

## Run the App

```bash
streamlit run app.py
```

## Deploy on Streamlit Cloud

1. Upload the project to GitHub.
2. Make sure `requirements.txt` is in the root folder.
3. Make sure `models/malicious_url_model.joblib` exists after training.
4. Select `app.py` as the main Streamlit file.

## Important Note

This project is an educational ML-based detector. It should not replace a production Web Application Firewall.
