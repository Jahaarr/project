import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib
import random
from datetime import datetime, timedelta

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, roc_curve, precision_recall_curve
)
from sklearn.preprocessing import RobustScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier, plot_importance

# ================= Synthetic Data Generation =================
def generate_synthetic_data(n_samples=10000):
    data = []
    users = [f"user{i}" for i in range(1, 51)]
    locations = ["US", "UK", "CA", "RU", "CN", "DE", "FR", "BR", "IN", "JP"]
    operating_systems = ["Windows", "Linux", "MacOS", "Android", "iOS"]

    for _ in range(n_samples):
        suspicious = random.choice([0, 1])  # balanced classes

        # Normal login
        if suspicious == 0:
            user = random.choice(users)
            location = random.choice(["US", "UK", "CA", "DE", "FR"])
            os = random.choice(operating_systems[:3])
            ip_reputation = random.randint(70, 100)
            device_change = 0
            latitude, longitude = (37.7749, -122.4194) if location == "US" else (
                48.8566, 2.3522
            )
            time_since_last = random.uniform(1, 6)
            login_freq_user = random.randint(5, 20)
            login_freq_window = random.randint(2, 10)
            avg_interval = random.uniform(1, 5)
            typical_hour = random.uniform(0.7, 1.0)
            hist_ip_count = random.randint(20, 100)
            unique_loc_ip = 1
            distance_last = random.uniform(0, 50)

        # Suspicious login
        else:
            user = random.choice(users)
            location = random.choice(["RU", "CN", "BR", "IN"])
            os = random.choice(operating_systems)
            ip_reputation = random.randint(0, 40)
            device_change = random.choice([0, 1])
            latitude, longitude = (55.7558, 37.6173) if location == "RU" else (39.9042, 116.4074)
            time_since_last = random.uniform(0, 1)
            login_freq_user = random.randint(1, 3)
            login_freq_window = random.randint(0, 2)
            avg_interval = random.uniform(20, 72)
            typical_hour = random.uniform(0.0, 0.3)
            hist_ip_count = random.randint(0, 5)
            unique_loc_ip = random.randint(2, 6)
            distance_last = random.uniform(500, 10000)

        timestamp = datetime(2025, 8, 12, random.randint(0, 23), random.randint(0, 59))
        ip_address = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

        data.append([
            timestamp, ip_address, user, location, os, ip_reputation,
            device_change, latitude, longitude, time_since_last,
            login_freq_user, login_freq_window, avg_interval, typical_hour,
            hist_ip_count, unique_loc_ip, distance_last, suspicious
        ])

    columns = [
        "timestamp", "ip_address", "user_id", "location", "operating_system", "ip_reputation",
        "device_fingerprint_change", "latitude", "longitude", "time_since_last_login",
        "login_frequency_per_user", "login_frequency_in_window", "avg_login_interval",
        "is_typical_hour", "historical_ip_usage_count", "unique_locations_per_ip",
        "distance_from_last_login", "suspicious"
    ]
    df = pd.DataFrame(data, columns=columns)
    df.to_csv("login.csv", index=False)
    print("✅ Synthetic login.csv generated")
    return df

# ================= Preprocessing =================
def preprocess_data(data):
    data = data.copy()
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")
    data["hour"] = data["timestamp"].dt.hour
    data["minute"] = data["timestamp"].dt.minute
    data["ip_subnet"] = data["ip_address"].apply(lambda x: ".".join(x.split(".")[:3]) if isinstance(x, str) else "unknown")
    data["ip_int"] = data["ip_address"].apply(
        lambda ip: int("".join([f"{int(octet):08b}" for octet in ip.split(".")]), 2)
        if isinstance(ip, str) and "." in ip else 0
    )
    data["ip_rarity"] = 1 / (data["historical_ip_usage_count"] + 1e-6)
    return data

# ================= Feature/Model Setup =================
def get_feature_pipeline():
    numeric_features = [
        "hour", "minute", "time_since_last_login", "login_frequency_per_user",
        "login_frequency_in_window", "avg_login_interval", "is_typical_hour",
        "ip_int", "historical_ip_usage_count", "ip_rarity", "unique_locations_per_ip",
        "latitude", "longitude", "distance_from_last_login", "ip_reputation",
        "device_fingerprint_change"
    ]
    categorical_features = ["user_id", "location", "operating_system", "ip_subnet"]

    preprocessor = ColumnTransformer([
        ("num", RobustScaler(), numeric_features),
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical_features)
    ])

    model = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=42,
            use_label_encoder=False
        ))
    ])
    return model, numeric_features + categorical_features

# ================= Train Model =================
def train_model():
    df = generate_synthetic_data(10000)
    df = preprocess_data(df)

    model, features = get_feature_pipeline()
    X = df[features]
    y = df["suspicious"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n==== Final Evaluation ====")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")

    # Confusion matrix plot
    cm = confusion_matrix(y_test, y_pred)
    plt.imshow(cm, cmap="Blues")
    plt.title("Confusion Matrix")
    plt.colorbar()
    plt.xlabel("Predicted")
    plt.ylabel("True")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, cm[i, j], ha="center", va="center", color="red")
    plt.show()

    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc_score(y_test, y_prob):.2f}")
    plt.plot([0, 1], [0, 1], "k--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend()
    plt.show()

    # Precision-Recall curve
    precision, recall, _ = precision_recall_curve(y_test, y_prob)
    plt.plot(recall, precision)
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve")
    plt.show()

    # Feature importance
    booster = model.named_steps["classifier"].get_booster()
    plot_importance(booster, importance_type="weight")
    plt.show()

    joblib.dump(model, "anomaly_model.pkl")
    print("✅ Model saved as anomaly_model.pkl")
    return model, df

# ================= Manual Scoring =================
def manual_score(model, historical_data):
    while True:
        print("\n=== Enter Login Information ===")
        login_data = {
            "timestamp": input("Login date and time (YYYY-MM-DD HH:MM:SS): "),
            "ip_address": input("IP Address: "),
            "user_id": input("User ID: "),
            "location": input("Location (e.g. US, CN): "),
            "operating_system": input("Operating System (e.g. Windows, Linux): "),
            "ip_reputation": float(input("IP Reputation (0-100): ")),
            "device_fingerprint_change": int(input("Device Fingerprint Change (0 or 1): ")),
            "latitude": float(input("Latitude: ")),
            "longitude": float(input("Longitude: ")),
            "time_since_last_login": float(input("Time since last login (hours): ")),
            "login_frequency_per_user": int(input("Login frequency per user: ")),
            "login_frequency_in_window": int(input("Login frequency in time window: ")),
            "avg_login_interval": float(input("Average login interval (hours): ")),
            "is_typical_hour": float(input("Typical hour score (0-1): ")),
            "historical_ip_usage_count": int(input("Historical IP usage count: ")),
            "unique_locations_per_ip": int(input("Unique locations per IP: ")),
            "distance_from_last_login": float(input("Distance from last login (km): "))
        }

        df_input = pd.DataFrame([login_data])
        df_input = preprocess_data(df_input)
        _, features = get_feature_pipeline()
        X_input = df_input[features]
        prob = model.predict_proba(X_input)[0][1]
        prediction = int(prob > 0.5)

        print(f"\n📊 Anomaly Score: {prob:.4f}")
        print("Prediction:", "🚨 Suspicious" if prediction else "✅ Normal")

        cont = input("\nDo you want to score another login? (yes/no): ").strip().lower()
        if cont != "yes":
            break

# ================= Main =================
def main():
    model, data = train_model()
    cont = input("\nDo you want to manually score a login? (yes/no): ").strip().lower()
    if cont == "yes":
        manual_score(model, data)

if __name__ == "__main__":
    main()
