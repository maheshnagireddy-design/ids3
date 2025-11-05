"""
Intrusion Detection System with Manual Entry Detection
Main Flask Application - UPDATED for dynamic features
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import pandas as pd
import numpy as np
from manual_detection import ManualDetection
from model import IDSModel
import json
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'

# Initialize the IDS components
ids_model = IDSModel()
manual_detector = ManualDetection()

# Store detection history
detection_history = []

@app.route('/')
def index():
    """Home page with options for detection methods"""
    feature_count = len(manual_detector.get_feature_names())
    return render_template('index.html', feature_count=feature_count)

@app.route('/manual-entry')
def manual_entry():
    """Manual entry form page with dynamic features"""
    feature_names = manual_detector.get_feature_names()
    feature_descriptions = manual_detector.get_feature_descriptions()
    return render_template('manual_entry.html', 
                         features=feature_names,
                         descriptions=feature_descriptions)

@app.route('/predict-manual', methods=['POST'])
def predict_manual():
    """Handle manual entry prediction"""
    try:
        # Get form data
        data = request.form.to_dict()

        # Convert to appropriate format
        features = {}
        for key, value in data.items():
            try:
                features[key] = float(value)
            except ValueError:
                features[key] = value

        # Make prediction
        prediction_result = manual_detector.predict(features)

        # Store in history
        history_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'method': 'manual',
            'features': features,
            'result': prediction_result
        }
        detection_history.append(history_entry)

        return render_template('results.html', 
                             result=prediction_result,
                             features=features,
                             method='manual')

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/predict-batch', methods=['POST'])
def predict_batch():
    """Handle batch file upload prediction"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        # Read CSV file
        df = pd.read_csv(file)

        # Make predictions
        predictions = ids_model.predict_batch(df)

        # Store results
        results = {
            'total': len(predictions),
            'normal': int(sum(predictions == 0)),
            'attack': int(sum(predictions == 1)),
            'predictions': predictions.tolist()
        }

        return render_template('results.html', 
                             result=results,
                             method='batch')

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/history')
def history():
    """View detection history"""
    return jsonify(detection_history)

@app.route('/api/features')
def api_features():
    """Get active features from the system"""
    return jsonify({
        'active_features': manual_detector.get_feature_names(),
        'num_features': len(manual_detector.get_feature_names()),
        'descriptions': manual_detector.get_feature_descriptions()
    })

@app.route('/api/predict', methods=['POST'])
def api_predict():
    """API endpoint for predictions"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Make prediction
        prediction_result = manual_detector.predict(data)

        return jsonify(prediction_result)

    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    print("=" * 60)
    print("Starting Intrusion Detection System...")
    print("=" * 60)
    print(f"Active features: {len(manual_detector.get_feature_names())}")
    print(f"Features: {', '.join(manual_detector.get_feature_names())}")
    print("=" * 60)
    print("Access the application at: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
