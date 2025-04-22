import pandas as pd
import re
import pickle
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report

# Clean text function
def clean_text(text):
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', '', text)  # Remove URLs
    text = re.sub(r'[^a-zA-Z0-9 ]', '', text)    # Remove punctuation
    return text

# Load dataset (using CEAS_08.csv with 'body' and 'label' columns)
data = pd.read_csv('/Users/cm/Phishing_Detection_System/CEAS_08.csv')
data.dropna(subset=['body', 'label'], inplace=True)
data['body'] = data['body'].apply(clean_text)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    data['body'], data['label'], test_size=0.2, random_state=42
)

# Build model pipeline
model = make_pipeline(TfidfVectorizer(), MultinomialNB())
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
with open('phishing_ml_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model trained and saved to phishing_ml_model.pkl")