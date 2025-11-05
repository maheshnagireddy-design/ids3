"""
Core IDS Model Module
Handles machine learning model operations
"""

import numpy as np
import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

class IDSModel:
    """Intrusion Detection System Model"""

    def __init__(self, model_path='models/ids_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = []

        if os.path.exists(model_path):
            self.load_model()

    def load_model(self):
        """Load trained model from disk"""
        try:
            with open(self.model_path, 'rb') as f:
                saved_data = pickle.load(f)
                self.model = saved_data['model']
                self.scaler = saved_data['scaler']
                if 'label_encoders' in saved_data:
                    self.label_encoders = saved_data['label_encoders']
                if 'feature_names' in saved_data:
                    self.feature_names = saved_data['feature_names']
            print("Model loaded successfully!")
        except Exception as e:
            print(f"Error loading model: {e}")

    def save_model(self):
        """Save trained model to disk"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        saved_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names
        }

        with open(self.model_path, 'wb') as f:
            pickle.dump(saved_data, f)

        print(f"Model saved to {self.model_path}")

    def preprocess_data(self, df, fit=False):
        """Preprocess the data"""
        df = df.copy()
        categorical_cols = df.select_dtypes(include=['object']).columns

        for col in categorical_cols:
            if col in df.columns:
                if fit:
                    self.label_encoders[col] = LabelEncoder()
                    df[col] = self.label_encoders[col].fit_transform(df[col].astype(str))
                else:
                    if col in self.label_encoders:
                        le = self.label_encoders[col]
                        df[col] = df[col].apply(
                            lambda x: le.transform([str(x)])[0] if str(x) in le.classes_ else -1
                        )
                    else:
                        df[col] = 0

        return df

    def train(self, X, y, algorithm='random_forest'):
        """Train the IDS model"""
        print("Training IDS model...")

        # Store feature names
        self.feature_names = X.columns.tolist() if hasattr(X, 'columns') else []

        X_processed = self.preprocess_data(X, fit=True)
        X_train, X_test, y_train, y_test = train_test_split(
            X_processed, y, test_size=0.2, random_state=42
        )

        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        if algorithm == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100, max_depth=20, random_state=42, n_jobs=-1
            )
        elif algorithm == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
            )

        self.model.fit(X_train_scaled, y_train)
        y_pred = self.model.predict(X_test_scaled)

        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1_score': f1_score(y_test, y_pred, average='weighted')
        }

        print(f"\nAccuracy: {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall: {metrics['recall']:.4f}")
        print(f"F1 Score: {metrics['f1_score']:.4f}")

        return metrics

    def predict(self, X):
        """Make predictions"""
        if self.model is None:
            raise Exception("Model not trained or loaded!")

        X_processed = self.preprocess_data(X, fit=False)
        X_scaled = self.scaler.transform(X_processed)
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)

        return predictions, probabilities

    def predict_batch(self, df):
        """Predict on batch of samples"""
        predictions, _ = self.predict(df)
        return predictions
