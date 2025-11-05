"""
Model Training Script - UPDATED to save feature names
"""

import pandas as pd
import numpy as np
from model import IDSModel
import argparse
import sys
import json
import os

def save_features_to_config(feature_names, config_path='config.json'):
    """Save feature names to config file"""
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
    else:
        config = {}

    config['active_features'] = feature_names
    config['num_features'] = len(feature_names)

    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)

    print(f"✅ Saved {len(feature_names)} features to {config_path}")

def load_data(data_path):
    """Load training data"""
    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"Data loaded: {df.shape[0]} samples, {df.shape[1]} features")
    return df

def prepare_data(df, target_column='label'):
    """Prepare features and labels"""
    if target_column not in df.columns:
        print(f"Error: Target column '{target_column}' not found!")
        sys.exit(1)

    X = df.drop(columns=[target_column])
    y = df[target_column]

    if y.dtype == 'object':
        y = (y != 'normal').astype(int)

    return X, y

def main():
    parser = argparse.ArgumentParser(description='Train IDS Model')
    parser.add_argument('--data', type=str, help='Path to training data CSV')
    parser.add_argument('--target', type=str, default='label', help='Target column name')
    parser.add_argument('--algorithm', type=str, default='random_forest')
    parser.add_argument('--output', type=str, default='models/ids_model.pkl')

    args = parser.parse_args()

    if args.data:
        df = load_data(args.data)
        X, y = prepare_data(df, args.target)
    else:
        # Create sample data
        print("No data provided. Creating sample data...")
        np.random.seed(42)
        n_samples = 1000

        # Use features from config if available
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                config = json.load(f)
                if 'active_features' in config:
                    feature_names = config['active_features']
                else:
                    feature_names = ['duration', 'protocol_type', 'service', 'flag',
                                   'src_bytes', 'dst_bytes', 'count', 'srv_count',
                                   'serror_rate', 'srv_serror_rate', 'rerror_rate', 
                                   'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate']
        else:
            feature_names = ['duration', 'src_bytes', 'dst_bytes', 'count', 
                           'serror_rate', 'same_srv_rate']

        X = pd.DataFrame(
            np.random.randn(n_samples, len(feature_names)),
            columns=feature_names
        )
        y = np.random.randint(0, 2, n_samples)

        # Save sample data
        os.makedirs('data', exist_ok=True)
        df = X.copy()
        df['label'] = y
        df.to_csv('data/sample_data.csv', index=False)
        print(f"Sample data created: data/sample_data.csv")

    # Save feature names to config
    feature_names = X.columns.tolist()
    save_features_to_config(feature_names)

    # Train model
    ids_model = IDSModel(model_path=args.output)
    metrics = ids_model.train(X, y, algorithm=args.algorithm)
    ids_model.save_model()

    print(f"\n✅ Training completed! Model saved to: {args.output}")
    print(f"📊 Features: {len(feature_names)}")

if __name__ == "__main__":
    main()
