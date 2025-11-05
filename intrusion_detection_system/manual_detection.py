"""
Manual Detection Module for IDS
Handles manual entry of network features and performs intrusion detection
UPDATED: Uses only features from active detection model
"""

import numpy as np
import pandas as pd
import pickle
import os
import json
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

class ManualDetection:
    """
    Manual detection system for intrusion detection
    Dynamically adapts to the features used in the trained model
    """

    def __init__(self, model_path='models/ids_model.pkl', config_path='config.json'):
        """Initialize the manual detection system"""
        self.model_path = model_path
        self.config_path = config_path
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.feature_descriptions = {}

        # Load configuration
        self._load_config()

        # Load model if exists, otherwise use default
        self._load_or_create_model()

    def _load_config(self):
        """Load feature configuration from config file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    if 'active_features' in config:
                        self.feature_names = config['active_features']
                        print(f"Loaded {len(self.feature_names)} active features from config")
                    if 'feature_descriptions' in config:
                        self.feature_descriptions = config['feature_descriptions']
            except Exception as e:
                print(f"Error loading config: {e}")
                self._set_default_features()
        else:
            self._set_default_features()

    def _set_default_features(self):
        """Set default features if no config exists"""
        # Common features used in most IDS implementations
        self.feature_names = [
            'duration',
            'protocol_type',
            'service',
            'flag',
            'src_bytes',
            'dst_bytes',
            'count',
            'srv_count',
            'serror_rate',
            'srv_serror_rate',
            'rerror_rate',
            'srv_rerror_rate',
            'same_srv_rate',
            'diff_srv_rate'
        ]
        self.feature_descriptions = self._get_default_descriptions()

    def _get_default_descriptions(self):
        """Get descriptions for common features"""
        return {
            'duration': 'Connection duration in seconds',
            'protocol_type': 'Protocol type (tcp, udp, icmp)',
            'service': 'Network service (http, ftp, smtp, etc.)',
            'flag': 'Connection flag (SF, S0, REJ, etc.)',
            'src_bytes': 'Number of data bytes from source to destination',
            'dst_bytes': 'Number of data bytes from destination to source',
            'land': 'Is connection from/to same host/port (1=yes, 0=no)',
            'wrong_fragment': 'Number of wrong fragments',
            'urgent': 'Number of urgent packets',
            'hot': 'Number of hot indicators',
            'num_failed_logins': 'Number of failed login attempts',
            'logged_in': 'Successfully logged in (1=yes, 0=no)',
            'num_compromised': 'Number of compromised conditions',
            'root_shell': 'Root shell obtained (1=yes, 0=no)',
            'su_attempted': 'Su root command attempted (1=yes, 0=no)',
            'num_root': 'Number of root accesses',
            'num_file_creations': 'Number of file creation operations',
            'num_shells': 'Number of shell prompts',
            'num_access_files': 'Number of operations on access control files',
            'count': 'Number of connections to same host',
            'srv_count': 'Number of connections to same service',
            'serror_rate': 'Percentage of connections with SYN errors',
            'srv_serror_rate': 'Percentage of connections with SYN errors (same service)',
            'rerror_rate': 'Percentage of connections with REJ errors',
            'srv_rerror_rate': 'Percentage of connections with REJ errors (same service)',
            'same_srv_rate': 'Percentage of connections to same service',
            'diff_srv_rate': 'Percentage of connections to different services',
            'srv_diff_host_rate': 'Percentage of connections to different hosts',
            'dst_host_count': 'Count of connections with same destination host',
            'dst_host_srv_count': 'Count of connections with same destination host and service',
            'dst_host_same_srv_rate': 'Percentage of same service connections',
            'dst_host_diff_srv_rate': 'Percentage of different service connections',
            'dst_host_same_src_port_rate': 'Percentage of same source port connections',
        }

    def _load_or_create_model(self):
        """Load existing model or create a default one"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    saved_data = pickle.load(f)
                    self.model = saved_data['model']
                    self.scaler = saved_data['scaler']

                    # Extract feature names from model if available
                    if 'feature_names' in saved_data:
                        self.feature_names = saved_data['feature_names']
                        print(f"Loaded {len(self.feature_names)} features from model")
                    elif hasattr(self.model, 'n_features_in_'):
                        print(f"Model expects {self.model.n_features_in_} features")
                        if len(self.feature_names) != self.model.n_features_in_:
                            print(f"Warning: Config features ({len(self.feature_names)}) != model features ({self.model.n_features_in_})")

                print("Model loaded successfully!")
            except Exception as e:
                print(f"Error loading model: {e}")
                self._create_default_model()
        else:
            self._create_default_model()

    def _create_default_model(self):
        """Create a default model for demonstration"""
        print("Creating default model...")
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()

        # Create dummy training data
        np.random.seed(42)
        n_features = len(self.feature_names)
        X_dummy = np.random.randn(1000, n_features)
        y_dummy = np.random.randint(0, 2, 1000)

        # Fit scaler and model
        X_scaled = self.scaler.fit_transform(X_dummy)
        self.model.fit(X_scaled, y_dummy)

        print(f"Default model created with {n_features} features!")

    def preprocess_input(self, features):
        """Preprocess manual input features"""
        feature_vector = []

        for feature_name in self.feature_names:
            if feature_name in features:
                value = features[feature_name]

                # Handle categorical features
                if feature_name in ['protocol_type', 'service', 'flag']:
                    if isinstance(value, str):
                        value = hash(value) % 100

                try:
                    feature_vector.append(float(value))
                except (ValueError, TypeError):
                    feature_vector.append(0.0)
            else:
                feature_vector.append(0.0)

        return np.array(feature_vector).reshape(1, -1)

    def predict(self, features):
        """Make prediction on manually entered features"""
        try:
            # Preprocess input
            X = self.preprocess_input(features)

            # Scale features
            X_scaled = self.scaler.transform(X)

            # Make prediction
            prediction = self.model.predict(X_scaled)[0]
            probability = self.model.predict_proba(X_scaled)[0]

            # Get feature importance
            feature_importance = self.get_feature_importance()

            # Prepare result
            result = {
                'prediction': int(prediction),
                'prediction_label': 'ATTACK' if prediction == 1 else 'NORMAL',
                'confidence': float(max(probability)) * 100,
                'probabilities': {
                    'normal': float(probability[0]) * 100,
                    'attack': float(probability[1]) * 100
                },
                'risk_level': self._calculate_risk_level(probability),
                'top_features': feature_importance[:5],
                'features_used': len(self.feature_names)
            }

            return result

        except Exception as e:
            raise Exception(f"Prediction error: {str(e)}")

    def _calculate_risk_level(self, probability):
        """Calculate risk level based on probability"""
        attack_prob = probability[1]

        if attack_prob < 0.3:
            return 'LOW'
        elif attack_prob < 0.7:
            return 'MEDIUM'
        else:
            return 'HIGH'

    def get_feature_importance(self):
        """Get feature importance from the model"""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            feature_imp = [(name, float(imp)) for name, imp in 
                          zip(self.feature_names, importances)]
            feature_imp.sort(key=lambda x: x[1], reverse=True)
            return feature_imp
        return []

    def get_feature_names(self):
        """Return list of active feature names"""
        return self.feature_names

    def get_feature_descriptions(self):
        """Return feature descriptions"""
        descriptions = {}
        for feature in self.feature_names:
            descriptions[feature] = self.feature_descriptions.get(
                feature, 
                f'{feature} (Network traffic feature)'
            )
        return descriptions

    def get_feature_type(self, feature_name):
        """Get the input type for a feature"""
        categorical_features = {
            'protocol_type': ['tcp', 'udp', 'icmp'],
            'service': ['http', 'smtp', 'ftp', 'ssh', 'telnet', 'dns', 'ftp_data', 
                       'pop_3', 'finger', 'other'],
            'flag': ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'S2', 'RSTOS0', 'S3']
        }

        binary_features = ['land', 'logged_in', 'is_host_login', 'is_guest_login',
                          'root_shell', 'su_attempted']

        if feature_name in categorical_features:
            return 'categorical', categorical_features[feature_name]
        elif feature_name in binary_features:
            return 'binary', None
        elif 'rate' in feature_name:
            return 'rate', None  # 0-1 range
        else:
            return 'numeric', None

    def save_config(self):
        """Save current configuration"""
        config = {
            'active_features': self.feature_names,
            'feature_descriptions': self.feature_descriptions,
            'num_features': len(self.feature_names)
        }

        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"Configuration saved with {len(self.feature_names)} features")

# Test the module
if __name__ == "__main__":
    detector = ManualDetection()
    print("Manual Detection System initialized!")
    print(f"Active features: {len(detector.get_feature_names())}")
    print(f"Features: {', '.join(detector.get_feature_names())}")
