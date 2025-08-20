import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import RobustScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, precision_recall_curve, average_precision_score
)
import joblib
from datetime import datetime, timedelta
import random

# ================= Synthetic Data Generator =================
def generate_login_csv(file_path="login.csv", n_samples=2000):
    np.random.seed(42)
    random.seed(42)

    user_ids = [f"user_{i}" for i in range(1, 21)]
    locations = ["US", "CN", "FR", "IN", "BR", "unknown"]
    operating_systems = ["Windows", "Linux", "MacOS", "Android", "iOS", "unknown"]

    rows = []
    base_time = datetime.now()

    for _ in range(n_samples):
        user = random.choice(user_ids)
        timestamp = base_time - timedelta(minutes=random.randint(0, 60*24*30))
        ip_address = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
        location = random.choice(locations)
        osys = random.choice(operating_systems)
        ip_reputation = np.random.uniform(0, 100)
        device_change = np.random.choice([0, 1], p=[0.9, 0.1])
        latitude = np.random.uniform(-90, 90)
        longitude = np.random.uniform(-180, 180)
        time_since_last_login = np.random.exponential(scale=5)
        login_frequency_per_user = np.random.randint(1, 20)
        login_frequency_in_window = np.random.randint(1, 10)
        avg_login_interval = np.random.uniform(1, 48)
        is_typical_hour = np.random.rand()
        historical_ip_usage_count = np.random.randint(0, 50)
        unique_locations_per_ip = np.random.randint(1, 5)
        distance_from_last_login = np.random.uniform(0, 5000)

        suspicious = int(
            (ip_reputation < 20 and distance_from_last_login > 1000)
            or device_change == 1
            or (is_typical_hour < 0.1 and login_frequency_per_user > 15)
        )

        rows.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "ip_address": ip_address,
            "user_id": user,
            "location": location,
            "operating_system": osys,
            "ip_reputation": ip_reputation,
            "device_fingerprint_change": device_change,
            "latitude": latitude,
            "longitude": longitude,
            "time_since_last_login": time_since_last_login,
            "login_frequency_per_user": login_frequency_per_user,
            "login_frequency_in_window": login_frequency_in_window,
            "avg_login_interval": avg_login_interval,
            "is_typical_hour": is_typical_hour,
            "historical_ip_usage_count": historical_ip_usage_count,
            "unique_locations_per_ip": unique_locations_per_ip,
            "distance_from_last_login": distance_from_last_login,
            "suspicious": suspicious
        })

    df = pd.DataFrame(rows)
    df.to_csv(file_path, index=False)
    print(f"✅ Generated synthetic login data: {file_path} ({n_samples} rows)")

# ================= Preprocessing =================
def preprocess_data(data):
    data = data.copy()
    data['timestamp'] = pd.to_datetime(data['timestamp'], errors='coerce')
    data['hour'] = data['timestamp'].dt.hour
    data['minute'] = data['timestamp'].dt.minute
    data['user_id'] = data['user_id'].astype(str)

    for col in ['location', 'operating_system', 'user_id']:
        data[col] = data[col].fillna('unknown')

    if 'ip_subnet' not in data.columns:
        data['ip_subnet'] = data['ip_address'].apply(lambda x: '.'.join(x.split('.')[:3]) if isinstance(x, str) else 'unknown')

    if 'ip_int' not in data.columns:
        data['ip_int'] = data['ip_address'].apply(lambda ip: int(''.join([f'{int(octet):08b}' for octet in ip.split('.')]), 2) if isinstance(ip, str) and '.' in ip else 0)

    if 'ip_rarity' not in data.columns:
        data['ip_rarity'] = 1 / (data['historical_ip_usage_count'] + 1e-6)

    data['subnet_count'] = data.groupby(['user_id', 'ip_subnet'])['timestamp'].transform('count')
    data['subnet_count'] = data['subnet_count'].fillna(0)
    return data

# ================= Feature/Model Setup =================
def get_feature_pipeline():
    numeric_features = [
        'hour', 'minute', 'time_since_last_login', 'login_frequency_per_user',
        'login_frequency_in_window', 'avg_login_interval', 'is_typical_hour',
        'ip_int', 'historical_ip_usage_count', 'ip_rarity', 'unique_locations_per_ip',
        'latitude', 'longitude', 'distance_from_last_login', 'ip_reputation',
        'device_fingerprint_change', 'subnet_count'
    ]
    categorical_features = ['user_id', 'location', 'operating_system', 'ip_subnet']

    preprocessor = ColumnTransformer([
        ('num', RobustScaler(), numeric_features),
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_features)
    ])

    model = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ))
    ])
    return model, numeric_features + categorical_features

# ================= Train Model =================
def train_model():
    if not os.path.exists('login.csv'):
        generate_login_csv('login.csv', n_samples=2000)

    df = pd.read_csv('login.csv')
    df = preprocess_data(df)

    model, features = get_feature_pipeline()
    X = df[features]
    y = df['suspicious']

    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n==== Final Evaluation ====")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")

    # 📊 Visualizations
    plot_model_performance(y_test, y_prob, y_pred, model, X)

    # Save model for API use
    joblib.dump(model, 'anomaly_model.pkl')
    print("✅ Model saved as anomaly_model.pkl (ready for API use)")

    return model, df

# ================= Plots =================
def plot_model_performance(y_test, y_prob, y_pred, model, X):
    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.figure()
    plt.plot(fpr, tpr, label=f'AUC = {roc_auc_score(y_test, y_prob):.2f}')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend()
    plt.show()

    # Precision-Recall curve
    precision, recall, _ = precision_recall_curve(y_test, y_prob)
    ap_score = average_precision_score(y_test, y_prob)
    plt.figure()
    plt.plot(recall, precision, label=f'AP = {ap_score:.2f}')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend()
    plt.show()

    # Confusion matrix (pure matplotlib)
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots()
    cax = ax.matshow(cm, cmap=plt.cm.Blues)
    plt.title('Confusion Matrix')
    fig.colorbar(cax)
    for (i, j), val in np.ndenumerate(cm):
        ax.text(j, i, f"{val}", ha='center', va='center', color='red', fontsize=12)
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Suspicious"])
    ax.set_yticklabels(["Normal", "Suspicious"])
    plt.show()

    # Feature importance
    ohe = model.named_steps['preprocessor'].named_transformers_['cat']
    cat_features = ohe.get_feature_names_out(['user_id', 'location', 'operating_system', 'ip_subnet'])
    num_features = X.columns[:len(X.columns) - 4]  # numeric features
    all_features = list(num_features) + list(cat_features)
    importances = model.named_steps['classifier'].feature_importances_
    indices = np.argsort(importances)[-20:]
    plt.figure(figsize=(10, 6))
    plt.barh(np.array(all_features)[indices], importances[indices])
    plt.title("Top 20 Feature Importances")
    plt.tight_layout()
    plt.show()

# ================= Manual Scoring =================
def manual_score(model, historical_data):
    print("\n=== Manual Login Scoring ===")
    def safe_input(prompt, cast_type, default=None):
        try:
            return cast_type(input(prompt))
        except:
            return default

    login_data = {
        'timestamp': input("Timestamp (YYYY-MM-DD HH:MM:SS): "),
        'ip_address': input("IP Address: "),
        'user_id': input("User ID: "),
        'location': input("Location (e.g. US, CN): "),
        'operating_system': input("Operating System (e.g. Windows, Linux): "),
        'ip_reputation': safe_input("IP Reputation (0-100): ", float, 50.0),
        'device_fingerprint_change': safe_input("Device Fingerprint Change (0 or 1): ", int, 0),
        'latitude': safe_input("Latitude: ", float, 0.0),
        'longitude': safe_input("Longitude: ", float, 0.0),
        'time_since_last_login': safe_input("Time since last login (hours): ", float, 1.0),
        'login_frequency_per_user': safe_input("Login frequency per user: ", int, 1),
        'login_frequency_in_window': safe_input("Login frequency in time window: ", int, 1),
        'avg_login_interval': safe_input("Average login interval (hours): ", float, 24.0),
        'is_typical_hour': safe_input("Typical hour score (0-1): ", float, 0.5),
        'historical_ip_usage_count': safe_input("Historical IP usage count: ", int, 0),
        'unique_locations_per_ip': safe_input("Unique locations per IP: ", int, 1),
        'distance_from_last_login': safe_input("Distance from last login (km): ", float, 0.0)
    }

    df_input = pd.DataFrame([login_data])
    df_input = preprocess_data(df_input)
    _, features = get_feature_pipeline()
    X_input = df_input[features]
    prob = model.predict_proba(X_input)[0][1]

    # Use optimal threshold for decision
    threshold = 0.3
    prediction = int(prob > threshold)

    print(f"\nAnomaly Score: {prob:.4f}")
    print("Prediction:", "🚨 Suspicious" if prediction else "✅ Normal")
    if prediction:
        reasons = []
        if login_data['ip_reputation'] < 20: reasons.append("Low IP reputation")
        if login_data['device_fingerprint_change'] == 1: reasons.append("Device fingerprint change")
        if login_data['distance_from_last_login'] > 2000: reasons.append("Large geolocation jump")
        if login_data['is_typical_hour'] < 0.1: reasons.append("Unusual login hour")
        print("Reason(s):", ", ".join(reasons) if reasons else "High anomaly score from combined factors")

# ================= Main =================
def main():
    model, data = train_model()
    cont = input("\nDo you want to manually score a login? (yes/no): ").strip().lower()
    if cont == 'yes':
        manual_score(model, data)

if __name__ == '__main__':
    main()
