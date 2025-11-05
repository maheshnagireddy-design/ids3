# Intrusion Detection System with Manual Entry Detection
## ✨ UPDATED: Dynamic Feature Configuration

This enhanced IDS now shows **ONLY the features used in your active detection model** in the manual entry form.

## 🎯 Key Feature: Dynamic Feature Loading

The system automatically adapts to show only the features that are actually used in your trained model, making the manual entry interface clean and relevant to your specific implementation.

---

## 📋 Quick Start

### 1. Installation
```bash
unzip intrusion_detection_system.zip
cd intrusion_detection_system
pip install -r requirements.txt
```

### 2. Configure Active Features

**Option A: Extract from Existing Model**
```bash
python extract_features.py models/your_model.pkl
```

**Option B: Extract from Training Dataset**
```bash
python extract_features.py data/your_data.csv label
```

**Option C: Manual Configuration**

Edit `config.json` and set your active features:
```json
{
  "active_features": [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count"
  ],
  "feature_descriptions": {
    "duration": "Connection duration in seconds",
    "protocol_type": "Protocol type (tcp, udp, icmp)",
    ...
  }
}
```

### 3. Train/Load Model
```bash
# If you have a dataset
python train_model.py --data data/your_data.csv --target label

# Or use demo model
python train_model.py
```

### 4. Start Application
```bash
python app.py
```

Access at: `http://localhost:5000`

---

## 🔄 How It Works

### Feature Detection Flow

1. **System Start**: Manual detection module initializes
2. **Config Loading**: Reads `config.json` for active features
3. **Model Loading**: Loads trained model and validates feature count
4. **Form Generation**: Creates manual entry form with ONLY active features
5. **Prediction**: Uses only configured features for detection

### File Structure
```
intrusion_detection_system/
├── config.json              # ⭐ Feature configuration
├── extract_features.py      # ⭐ NEW: Feature extraction utility
├── manual_detection.py      # ⭐ UPDATED: Dynamic feature loading
├── app.py                   # Main Flask application
├── model.py                 # ML model operations
├── train_model.py          # Model training
├── templates/
│   ├── index.html
│   ├── manual_entry.html   # ⭐ UPDATED: Dynamic form
│   └── results.html
└── ... (other files)
```

---

## 📝 Configuration File (config.json)

### Structure
```json
{
  "active_features": [
    // List of feature names used in your model
    // ONLY these features will appear in manual entry form
  ],
  "feature_descriptions": {
    // Human-readable descriptions for each feature
    // Used as help text in the form
  },
  "num_features": 14,  // Automatically set
  "model": {
    "algorithm": "random_forest",
    "n_estimators": 100,
    "max_depth": 20
  },
  "detection": {
    "threshold": 0.5,
    "risk_levels": {
      "low": 0.3,
      "medium": 0.7
    }
  }
}
```

### Example: Minimal Feature Set
```json
{
  "active_features": [
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "serror_rate"
  ]
}
```

### Example: Full Feature Set
```json
{
  "active_features": [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "count", "srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate", 
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate"
  ]
}
```

---

## 🛠️ Feature Extraction Utility

### Usage

**Extract from Model File:**
```bash
python extract_features.py models/ids_model.pkl
```

**Extract from Dataset:**
```bash
python extract_features.py data/training_data.csv label
```

**With Custom Target Column:**
```bash
python extract_features.py data/network_traffic.csv attack_type
```

### What It Does

1. ✅ Reads your model or dataset
2. ✅ Extracts feature names
3. ✅ Updates `config.json` automatically
4. ✅ Validates feature count
5. ✅ Preserves other config settings

---

## 🎨 Manual Entry Interface

### Adaptive Form

The manual entry form automatically adapts based on your configuration:

- **Few Features (< 10)**: Single-column layout for quick entry
- **Many Features (10-20)**: Two-column grid layout
- **Lots of Features (> 20)**: Three-column organized by categories

### Smart Input Types

The system automatically selects the right input type:

- **Categorical**: Dropdown menus (protocol_type, service, flag)
- **Binary**: Yes/No selectors (logged_in, land, root_shell)
- **Rate**: Number inputs with 0-1 range (serror_rate, rerror_rate)
- **Numeric**: Standard number inputs (duration, bytes, counts)

### Sample Data Buttons

Two pre-filled sample options:
- **Normal Traffic Sample**: Typical benign HTTP traffic
- **Attack Sample**: Suspicious scanning behavior

---

## 📊 Using Your Own Model

### Step 1: Prepare Your Dataset

Your CSV should have:
- Network traffic features (columns)
- Target label (e.g., 'label', 'attack', 'class')

Example:
```csv
duration,src_bytes,dst_bytes,count,serror_rate,label
0,181,5450,1,0,normal
0,0,0,150,1,attack
```

### Step 2: Extract Features
```bash
python extract_features.py data/your_data.csv label
```

### Step 3: Train Model
```bash
python train_model.py --data data/your_data.csv --target label
```

### Step 4: Verify Configuration
```bash
cat config.json
# Check that active_features matches your dataset columns
```

### Step 5: Start Application
```bash
python app.py
```

The manual entry form will now show **only your features**!

---

## 🔍 API Usage with Active Features

### Get Active Features
```python
import requests

response = requests.get('http://localhost:5000/api/features')
features = response.json()['active_features']
print(f"Active features: {features}")
```

### Manual Prediction
```python
import requests

# Use only the active features
data = {
    "duration": 0,
    "src_bytes": 181,
    "dst_bytes": 5450,
    "count": 1,
    "serror_rate": 0
    # Only include features from config.json
}

response = requests.post(
    'http://localhost:5000/api/predict',
    json=data
)

result = response.json()
print(f"Prediction: {result['prediction_label']}")
print(f"Features used: {result['features_used']}")
```

---

## ⚙️ Advanced Configuration

### Custom Feature Descriptions

Add helpful descriptions in `config.json`:
```json
{
  "feature_descriptions": {
    "duration": "Length of connection in seconds (0-58329)",
    "src_bytes": "Data sent from source in bytes (0-1379963888)",
    "custom_feature": "Your custom feature description"
  }
}
```

These appear as help text in the form.

### Feature Validation Rules

Edit `manual_detection.py` to add custom validation:
```python
def validate_feature(self, feature_name, value):
    if feature_name == 'duration' and value < 0:
        raise ValueError("Duration cannot be negative")
    if 'rate' in feature_name and not (0 <= value <= 1):
        raise ValueError(f"{feature_name} must be between 0 and 1")
    return value
```

---

## 🎯 Benefits of Dynamic Features

### ✅ Cleaner Interface
- Only shows relevant features
- Reduces user confusion
- Faster data entry

### ✅ Flexible Deployment
- Works with any feature set
- Adapts to different datasets
- No code changes needed

### ✅ Maintainable
- Single config file controls everything
- Easy to update features
- Automatic form generation

### ✅ Compatible
- Works with existing models
- Supports feature selection
- Handles dimensionality reduction

---

## 🔧 Troubleshooting

### Issue: Form shows wrong features

**Solution:**
```bash
python extract_features.py models/ids_model.pkl
```

### Issue: Feature count mismatch

**Check:**
```python
# In Python
import pickle
with open('models/ids_model.pkl', 'rb') as f:
    model = pickle.load(f)
    print(f"Model expects: {model['model'].n_features_in_} features")

import json
with open('config.json', 'r') as f:
    config = json.load(f)
    print(f"Config has: {len(config['active_features'])} features")
```

### Issue: Missing feature descriptions

**Add them manually in config.json:**
```json
{
  "feature_descriptions": {
    "your_feature": "Description of your feature"
  }
}
```

---

## 📚 Common Feature Sets

### Minimal Set (5 features)
```json
["duration", "src_bytes", "dst_bytes", "count", "flag"]
```

### Basic Set (14 features) - DEFAULT
```json
[
  "duration", "protocol_type", "service", "flag",
  "src_bytes", "dst_bytes", "count", "srv_count",
  "serror_rate", "srv_serror_rate", 
  "rerror_rate", "srv_rerror_rate",
  "same_srv_rate", "diff_srv_rate"
]
```

### Extended Set (22 features)
```json
[
  "duration", "protocol_type", "service", "flag",
  "src_bytes", "dst_bytes", "land", "wrong_fragment",
  "urgent", "hot", "num_failed_logins", "logged_in",
  "count", "srv_count", "serror_rate", "srv_serror_rate",
  "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
  "dst_host_count", "dst_host_srv_count"
]
```

### Full KDD Cup 99 (41 features)
Use `extract_features.py` with KDD dataset

---

## 🚀 Production Deployment

### Before Deployment:

1. ✅ Extract features from your production model
2. ✅ Verify config.json has correct features
3. ✅ Test manual entry with sample data
4. ✅ Validate API endpoints
5. ✅ Set debug=false in config.json

### Security Checklist:

- Change Flask secret key in app.py
- Use HTTPS in production
- Implement rate limiting
- Add authentication for API
- Regular model updates

---

## 📞 Support

For issues:
1. Check feature count matches between model and config
2. Verify config.json syntax (valid JSON)
3. Run extract_features.py to auto-configure
4. Check application logs for errors

---

**Version**: 2.1 (Dynamic Features Update)
**Last Updated**: November 2025
**Key Feature**: Automatic adaptation to your model's active features

🎉 Now your manual entry form shows ONLY the features your model actually uses!
