import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_squared_error
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
import joblib

# Load the training dataset
data = pd.read_csv("cve1.csv")

# Ensure no missing values in important columns
data.fillna({'cwe_name': 'Unknown', 'summary': ''}, inplace=True)

# Define features and target variable
X = data[['cwe_name', 'summary']]
y = data['cvss']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Preprocessing: OneHotEncode 'cwe_name' and Tfidf for 'summary'
preprocessor = ColumnTransformer(
    transformers=[
        ('cwe', OneHotEncoder(handle_unknown='ignore'), ['cwe_name']),
        ('summary', TfidfVectorizer(max_features=1000), 'summary')
    ]
)

# Create the Random Forest pipeline
pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('model', RandomForestRegressor(random_state=42))
])

# Hyperparameter tuning for Random Forest
param_grid = {
    'model__n_estimators': [50, 100],
    'model__max_depth': [10, 20],
    'model__min_samples_split': [2, 5]
}

grid_search = GridSearchCV(pipeline, param_grid, cv=3, scoring='neg_mean_squared_error', verbose=1)
grid_search.fit(X_train, y_train)

# Best pipeline after hyperparameter tuning
best_pipeline = grid_search.best_estimator_

# Evaluate the model
y_pred = best_pipeline.predict(X_test)
mse = mean_squared_error(y_test, y_pred)
print(f"Mean Squared Error on Test Data: {mse}")

# Save the trained model for reuse
joblib.dump(best_pipeline, "random_forest_cvss_model.pkl")

# Load new data for prediction
new_data = pd.read_csv("new_data.csv")

# Handle missing columns in new_data
if 'cwe_name' not in new_data.columns:
    raise ValueError("The 'cwe_name' column is missing from new_data.csv.")
if 'summary' not in new_data.columns:
    print("The 'summary' column is missing. Adding placeholder values.")
    new_data['summary'] = ''  # Add placeholder for missing summary column

# Predict CVSS severity and update the cvss column
new_data['cvss'] = best_pipeline.predict(new_data[['cwe_name', 'summary']])

# Save the updated dataset to a new CSV file
new_data.to_csv("updated_new_data.csv", index=False)

print("Updated CVSS values written to 'updated_new_data.csv'.")
