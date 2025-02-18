from flask import Flask, request, jsonify, render_template
import pandas as pd
import os
import joblib
from sel import scrape_nciipc, scrape_cyware  # Import scraping functions from sel.py
from ml1 import validate_and_predict_cvss

app = Flask(__name__)

# Paths
SCRAPED_DATA_PATH = "new_data.csv"  # Scraped data file
PREDICTED_DATA_PATH = "predicted_data.csv"  # Prediction output file
MODEL_PATH = "random_forest_cvss_model.pkl"  # Pre-trained model file

# Load the machine learning model
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
model = joblib.load(MODEL_PATH)

# Home route - renders the index.html page
@app.route("/")
def home():
    return render_template("index.html")

# Route to scrape data
@app.route("/scrape", methods=["POST"])
def scrape_data():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        if "nciipc.gov.in" in url:
            scrape_nciipc()
        elif "cyware.com" in url:
            scrape_cyware()
        else:
            return jsonify({"error": "Unsupported URL"}), 400

        return jsonify({"message": "Scraping completed successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to predict CVSS severity
@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Ensure the scraped data exists
        if not os.path.exists(SCRAPED_DATA_PATH):
            return jsonify({"error": "No scraped data available for prediction"}), 400

        # Load the scraped data
        input_data = pd.read_csv(SCRAPED_DATA_PATH)

        # Ensure required columns exist
        if "cwe_name" not in input_data.columns:
            return jsonify({"error": "'cwe_name' column missing in scraped data"}), 400
        if "summary" not in input_data.columns:
            input_data["summary"] = ""  # Add placeholder if missing

        # Predict CVSS severity
        input_data["cvss"] = model.predict(input_data[["cwe_name", "summary"]])

        # Save the results to a new CSV file
        input_data.to_csv(PREDICTED_DATA_PATH, index=False)

        return jsonify({"message": "Predictions completed successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to view scraped data
@app.route("/view-scraped", methods=["GET"])
def view_scraped_data():
    try:
        if not os.path.exists(SCRAPED_DATA_PATH):
            return jsonify([])  # Return empty list if no data

        data = pd.read_csv(SCRAPED_DATA_PATH)
        return jsonify(data.to_dict(orient="records"))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Route to view predicted data
@app.route("/view-predicted", methods=["GET"])
def view_predicted_data():
    try:
        if not os.path.exists(PREDICTED_DATA_PATH):
            return jsonify([])  # Return empty list if no data

        data = pd.read_csv(PREDICTED_DATA_PATH)
        return jsonify(data.to_dict(orient="records"))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/predict-input", methods=["POST"])
def predict_input():
    try:
        # Extract the input description from the request
        data = request.json
        incident_description = data.get("description")

        if not incident_description:
            return jsonify({"error": "Incident description is required"}), 400

        # Run the prediction function from ml1.py
        result = validate_and_predict_cvss(incident_description)
        print(result)

        return jsonify({"message": "Prediction successful", "result": result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to render results page
@app.route("/results")
def results():
    return render_template("results.html")

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
