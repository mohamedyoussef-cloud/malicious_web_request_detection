import os
import joblib
import pandas as pd

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from detector import extract_features

DATA_PATH = "data/dataset.csv"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "malicious_url_model.joblib")


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = []
        for url in X:
            features = extract_features(str(url))
            rows.append(list(features.values()))
        return rows


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError("Put your training CSV at data/dataset.csv with columns: url,label")

    df = pd.read_csv(DATA_PATH)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("dataset.csv must contain columns: url,label")

    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str)
    df["label"] = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        df["url"],
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"]
    )

    text_features = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        max_features=5000,
        lowercase=True
    )

    numeric_features = Pipeline([
        ("extractor", URLFeatureExtractor()),
        ("scaler", StandardScaler())
    ])

    features = FeatureUnion([
        ("char_tfidf", text_features),
        ("numeric", numeric_features)
    ])

    base_svm = LinearSVC(
        C=0.75,
        class_weight="balanced",
        random_state=42
    )

    classifier = CalibratedClassifierCV(base_svm, cv=3)

    pipeline = Pipeline([
        ("features", features),
        ("classifier", classifier)
    ])

    pipeline.fit(X_train, y_train)
    preds = pipeline.predict(X_test)

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))
    print("\nClassification Report:")
    print(classification_report(y_test, preds, digits=4))

    model_bundle = {
        "pipeline": pipeline,
        "threshold": 0.5,
        "model_name": "Linear SVM with Character TF-IDF and URL Structure Features"
    }

    joblib.dump(model_bundle, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
