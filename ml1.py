import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestRegressor
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_squared_error
import joblib
import re

# Load the training dataset
data = pd.read_csv("cve1.csv")
data.fillna({'summary': ''}, inplace=True)
X = data['summary']
y = data['cvss']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
pipeline = Pipeline(steps=[
    ('vectorizer', TfidfVectorizer(max_features=1000)),  # Tfidf for text input
    ('model', RandomForestRegressor(random_state=42))
])
param_grid = {
    'model__n_estimators': [50, 100],
    'model__max_depth': [10, 20],
    'model__min_samples_split': [2, 5]
}
grid_search = GridSearchCV(pipeline, param_grid, cv=3, scoring='neg_mean_squared_error', verbose=1)
grid_search.fit(X_train, y_train)
best_pipeline = grid_search.best_estimator_
y_pred = best_pipeline.predict(X_test)
mse = mean_squared_error(y_test, y_pred)
print(f"Mean Squared Error on Test Data: {mse}")
joblib.dump(best_pipeline, "incident_text_cvss_model.pkl")
cyber_incident_keywords = [
    'aq', 'ransomware', 'malware', 'DDoS', 'data breach', 'SQL injection',
    'cross-site scripting', 'privilege escalation', 'zero-day', 'brute force',
    'botnet', 'APT', 'trojan', 'virus', 'worm'
]


# Function to validate and predict CVSS
def validate_and_predict_cvss(incident_description):
    # Check if the input contains cyber incident keywords
    if not any(keyword.lower() in incident_description.lower() for keyword in cyber_incident_keywords):
        return "The entered content does not appear to describe a cyber incident. Please provide a valid incident description."

    # Load the trained model
    model = joblib.load("incident_text_cvss_model.pkl")

    # Predict CVSS
    predicted_cvss = model.predict([incident_description])[0]
    return f"Predicted CVSS score for the incident: {predicted_cvss}"


# Example usage
# incident_description = input("Enter the incident description: ")
# result = validate_and_predict_cvss(incident_description)
# print(result)