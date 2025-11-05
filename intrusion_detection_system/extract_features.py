"""
Feature Extraction Utility
Extracts active features from an existing IDS model file
"""

import pickle
import json
import sys
import os

def extract_features_from_model(model_path='models/ids_model.pkl', output_path='config.json'):
    """
    Extract feature information from a trained model
    and update the configuration file
    """

    if not os.path.exists(model_path):
        print(f"❌ Model file not found: {model_path}")
        print("Please provide the path to your trained model.")
        return False

    try:
        # Load the model
        print(f"📂 Loading model from: {model_path}")
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        feature_names = []

        # Try to extract feature names
        if 'feature_names' in model_data:
            feature_names = model_data['feature_names']
            print(f"✅ Found feature_names in model: {len(feature_names)} features")
        elif 'model' in model_data and hasattr(model_data['model'], 'n_features_in_'):
            n_features = model_data['model'].n_features_in_
            print(f"ℹ️ Model expects {n_features} features (names not found)")
            feature_names = [f'feature_{i}' for i in range(n_features)]
        else:
            print("⚠️ Could not determine feature count from model")
            return False

        # Load existing config or create new
        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                config = json.load(f)
            print(f"📝 Updating existing config: {output_path}")
        else:
            config = {
                "model": {"algorithm": "random_forest"},
                "detection": {"threshold": 0.5},
                "application": {"host": "0.0.0.0", "port": 5000}
            }
            print(f"📝 Creating new config: {output_path}")

        # Update active features
        config['active_features'] = feature_names
        config['num_features'] = len(feature_names)

        # Add default descriptions if not present
        if 'feature_descriptions' not in config:
            config['feature_descriptions'] = {}

        # Save updated config
        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuration updated successfully!")
        print(f"📊 Active features: {len(feature_names)}")
        print(f"📋 Features: {', '.join(feature_names[:10])}{'...' if len(feature_names) > 10 else ''}")

        return True

    except Exception as e:
        print(f"❌ Error extracting features: {e}")
        return False

def extract_from_dataset(data_path, target_column='label', output_path='config.json'):
    """
    Extract feature names from a training dataset CSV
    """
    import pandas as pd

    if not os.path.exists(data_path):
        print(f"❌ Data file not found: {data_path}")
        return False

    try:
        print(f"📂 Loading dataset from: {data_path}")
        df = pd.read_csv(data_path)

        # Get all columns except target
        all_columns = df.columns.tolist()
        if target_column in all_columns:
            all_columns.remove(target_column)

        feature_names = all_columns

        print(f"✅ Found {len(feature_names)} features in dataset")

        # Update config
        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                config = json.load(f)
        else:
            config = {
                "model": {"algorithm": "random_forest"},
                "detection": {"threshold": 0.5},
                "application": {"host": "0.0.0.0", "port": 5000}
            }

        config['active_features'] = feature_names
        config['num_features'] = len(feature_names)

        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✅ Configuration updated from dataset!")
        print(f"📋 Features: {', '.join(feature_names[:10])}{'...' if len(feature_names) > 10 else ''}")

        return True

    except Exception as e:
        print(f"❌ Error extracting from dataset: {e}")
        return False

if __name__ == "__main__":
    print("="*60)
    print("IDS Feature Extraction Utility")
    print("="*60)
    print()

    if len(sys.argv) > 1:
        source = sys.argv[1]

        if source.endswith('.pkl'):
            # Extract from model
            extract_features_from_model(source)
        elif source.endswith('.csv'):
            # Extract from dataset
            target = sys.argv[2] if len(sys.argv) > 2 else 'label'
            extract_from_dataset(source, target)
        else:
            print("❌ Unknown file type. Please provide .pkl (model) or .csv (dataset)")
    else:
        print("Usage:")
        print("  python extract_features.py <model.pkl>")
        print("  python extract_features.py <data.csv> [target_column]")
        print()
        print("Examples:")
        print("  python extract_features.py models/ids_model.pkl")
        print("  python extract_features.py data/training_data.csv label")
        print()
        print("This will extract the active features and update config.json")
