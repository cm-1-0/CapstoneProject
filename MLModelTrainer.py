import pandas as pd
import re
import pickle
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.metrics import classification_report


class ExtraFeatures(BaseEstimator, TransformerMixin):
    def fit(self, x, y=None):
        return self

    def transform(self, texts):
        features = []
        for text in texts:
            text = text.lower()
            num_links = len(re.findall(r'https?://', text))
            urgent_keywords = ["urgent", "immediately", "act now", "response required"]
            has_urgent = int(any(word in text for word in urgent_keywords))
            has_suspicious_phrase = int("verify your account" in text or "click the link" in text)
            features.append([num_links, has_urgent, has_suspicious_phrase])
        return np.array(features)

def clean_text(text):
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', '', text)  # Remove URLs
    text = re.sub(r'[^a-zA-Z0-9 ]', '', text)   # Remove punctuation
    return text


data = pd.read_csv('/Users/cm/Phishing_Detection_System/CEAS_08.csv')
data.dropna(subset=['body', 'label'], inplace=True)
data['body'] = data['body'].apply(clean_text)

X = data['body']
y = data['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)


combined_features = FeatureUnion([
    ("tfidf", TfidfVectorizer(max_features=3000, stop_words='english')),
    ("extra", ExtraFeatures())
])


model = Pipeline([
    ("features", combined_features),
    ("classifier", LogisticRegression(max_iter=1000))
])


model.fit(X_train, y_train)
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

with open('phishing_ml_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model trained and saved to phishing_ml_model.pkl")
