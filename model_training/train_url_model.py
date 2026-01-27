"""
Advanced URL Phishing Detection Model Trainer
Trains ensemble models on comprehensive phishing dataset
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix, roc_auc_score
import xgboost as xgb
import lightgbm as lgb
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

print("="*80)
print("URL PHISHING DETECTION MODEL TRAINER")
print("="*80)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

# Load dataset
print("[*] Loading dataset...")
df = pd.read_csv('datasets/URL_PHISHING_DATASET_PERFECT.csv', low_memory=False)
print(f"[+] Loaded {len(df):,} URLs")
print(f"   - Phishing: {(df['label']=='phishing').sum():,}")
print(f"   - Legitimate: {(df['label']=='legitimate').sum():,}\n")

# Select numeric features
print("[*] Preparing features...")
feature_cols = [
    'url_length', 'domain_length', 'path_length', 'has_https', 'has_http',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_question_marks', 'num_equal_signs', 'num_at_symbols', 'num_ampersands',
    'num_digits', 'num_percent', 'num_subdomains', 'has_ip_address', 'has_port',
    'has_suspicious_words', 'has_shortener', 'digit_ratio',
    'domain_entropy', 'domain_has_digits', 'domain_has_hyphens', 'fragment_length',
    'has_login_path', 'has_redirect_param', 'https_in_domain', 'is_brand_similar',
    'is_http', 'is_https', 'is_ip_address', 'is_shortener', 'letter_ratio',
    'max_consecutive_digits', 'max_consecutive_dots', 'max_consecutive_hyphens',
    'min_brand_distance', 'num_exclamation', 'num_hashtags', 'num_letters',
    'num_query_params', 'num_suspicious_words', 'path_depth', 'query_length',
    'tld_length', 'tld_suspicious', 'url_entropy', 'special_char_ratio'
]

X = df[feature_cols].fillna(0)
y = (df['label'] == 'phishing').astype(int)

print(f"[+] Features: {X.shape[1]}")
print(f"[+] Samples: {X.shape[0]:,}\n")

# Split data
print("[*] Splitting dataset (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"   - Training: {len(X_train):,}")
print(f"   - Testing: {len(X_test):,}\n")

# Train models
print("[*] Training models...\n")

# 1. XGBoost
print("[1] Training XGBoost...")
xgb_model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
    eval_metric='logloss'
)
xgb_model.fit(X_train, y_train)
xgb_pred = xgb_model.predict(X_test)
xgb_acc = accuracy_score(y_test, xgb_pred)
print(f"    [+] Accuracy: {xgb_acc:.4f}")

# 2. LightGBM
print("[2] Training LightGBM...")
lgb_model = lgb.LGBMClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
    verbose=-1
)
lgb_model.fit(X_train, y_train)
lgb_pred = lgb_model.predict(X_test)
lgb_acc = accuracy_score(y_test, lgb_pred)
print(f"    [+] Accuracy: {lgb_acc:.4f}")

# 3. Random Forest
print("[3] Training Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)
rf_acc = accuracy_score(y_test, rf_pred)
print(f"    [+] Accuracy: {rf_acc:.4f}")

# 4. Gradient Boosting
print("[4] Training Gradient Boosting...")
gb_model = GradientBoostingClassifier(
    n_estimators=200,
    max_depth=7,
    learning_rate=0.1,
    subsample=0.8,
    random_state=42
)
gb_model.fit(X_train, y_train)
gb_pred = gb_model.predict(X_test)
gb_acc = accuracy_score(y_test, gb_pred)
print(f"    [+] Accuracy: {gb_acc:.4f}\n")

# Ensemble
print("[*] Creating Ensemble Model...")
ensemble = VotingClassifier(
    estimators=[
        ('xgb', xgb_model),
        ('lgb', lgb_model),
        ('rf', rf_model),
        ('gb', gb_model)
    ],
    voting='soft',
    n_jobs=-1
)
ensemble.fit(X_train, y_train)
ensemble_pred = ensemble.predict(X_test)
ensemble_proba = ensemble.predict_proba(X_test)[:, 1]

# Evaluation
print("\n" + "="*80)
print("FINAL RESULTS")
print("="*80)

acc = accuracy_score(y_test, ensemble_pred)
prec = precision_score(y_test, ensemble_pred)
rec = recall_score(y_test, ensemble_pred)
f1 = f1_score(y_test, ensemble_pred)
auc = roc_auc_score(y_test, ensemble_proba)

print(f"\n[*] Ensemble Performance:")
print(f"   - Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
print(f"   - Precision: {prec:.4f} ({prec*100:.2f}%)")
print(f"   - Recall:    {rec:.4f} ({rec*100:.2f}%)")
print(f"   - F1-Score:  {f1:.4f}")
print(f"   - ROC-AUC:   {auc:.4f}")

cm = confusion_matrix(y_test, ensemble_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn)
print(f"\n[*] Confusion Matrix:")
print(f"   - True Negatives:  {tn:,}")
print(f"   - False Positives: {fp:,} (FPR: {fpr*100:.2f}%)")
print(f"   - False Negatives: {fn:,}")
print(f"   - True Positives:  {tp:,}")

print(f"\n[*] Classification Report:")
print(classification_report(y_test, ensemble_pred, target_names=['Legitimate', 'Phishing']))

# Save models
print("\n[*] Saving models...")
joblib.dump(ensemble, 'models/url_phishing_ensemble.joblib', compress=3)
joblib.dump(xgb_model, 'models/url_phishing_xgboost.joblib', compress=3)
joblib.dump(feature_cols, 'models/url_feature_columns.joblib', compress=3)

# Also save a simple predictor function
import pickle
predictor_data = {
    'model': ensemble,
    'features': feature_cols,
    'scaler': None
}
with open('models/url_predictor.pkl', 'wb') as f:
    pickle.dump(predictor_data, f, protocol=4)

print("    [+] Saved: models/url_phishing_ensemble.joblib")
print("    [+] Saved: models/url_phishing_xgboost.joblib")
print("    [+] Saved: models/url_feature_columns.joblib")
print("    [+] Saved: models/url_predictor.pkl")

# Feature importance
print("\n[*] Top 15 Important Features:")
feature_importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': xgb_model.feature_importances_
}).sort_values('importance', ascending=False).head(15)

for idx, row in feature_importance.iterrows():
    print(f"   {row['feature']:30s} {row['importance']:.4f}")

print("\n" + "="*80)
print(f"[+] Training completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)
