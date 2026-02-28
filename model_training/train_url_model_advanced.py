"""
PRODUCTION-GRADE URL PHISHING DETECTION MODEL TRAINER
Advanced ensemble with hyperparameter optimization and full dataset utilization
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.ensemble import VotingClassifier, StackingClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                            f1_score, roc_auc_score, classification_report, confusion_matrix)
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

print("="*100)
print("PRODUCTION-GRADE URL PHISHING DETECTION MODEL TRAINER")
print("="*100)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

np.random.seed(42)

# Load dataset
DATASET_PATH = 'datasets/URL_PHISHING_DATASET.csv'
print("[*] Loading complete dataset...")
df = pd.read_csv(DATASET_PATH, low_memory=False)
print(f"[+] Loaded {len(df):,} URLs")
print(f"    - Phishing: {(df['label']=='phishing').sum():,}")
print(f"    - Legitimate: {(df['label']=='legitimate').sum():,}\n")

# Feature engineering
print("[*] Feature engineering...")
feature_cols = [
    'url_length', 'domain_length', 'path_length', 'has_https', 'has_http',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_question_marks', 'num_equal_signs', 'num_at_symbols', 'num_ampersands',
    'num_digits', 'num_percent', 'num_subdomains', 'has_ip_address', 'has_port',
    'has_suspicious_words', 'has_shortener', 'digit_ratio', 'domain_entropy',
    'domain_has_digits', 'domain_has_hyphens', 'fragment_length', 'has_login_path',
    'has_redirect_param', 'https_in_domain', 'is_brand_similar', 'is_http',
    'is_https', 'is_ip_address', 'is_shortener', 'letter_ratio',
    'max_consecutive_digits', 'max_consecutive_dots', 'max_consecutive_hyphens',
    'min_brand_distance', 'num_exclamation', 'num_hashtags', 'num_letters',
    'num_query_params', 'num_suspicious_words', 'path_depth', 'query_length',
    'tld_length', 'tld_suspicious', 'url_entropy', 'special_char_ratio'
]

X = df[feature_cols].fillna(0)
y = (df['label'] == 'phishing').astype(int)

# Advanced feature scaling
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)
X_scaled = pd.DataFrame(X_scaled, columns=feature_cols)

print(f"[+] Features: {X.shape[1]}")
print(f"[+] Total samples: {X.shape[0]:,}\n")

# Split for validation
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.15, random_state=42, stratify=y
)
print(f"[*] Dataset split:")
print(f"    - Training: {len(X_train):,} ({len(X_train)/len(X)*100:.1f}%)")
print(f"    - Testing: {len(X_test):,} ({len(X_test)/len(X)*100:.1f}%)\n")

# Advanced model configurations
print("[*] Building advanced ensemble models...\n")

# XGBoost with optimized parameters
xgb_model = xgb.XGBClassifier(
    n_estimators=500,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.85,
    colsample_bytree=0.85,
    min_child_weight=3,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.0,
    random_state=42,
    n_jobs=-1,
    eval_metric='logloss',
    tree_method='hist'
)

# LightGBM with optimized parameters
lgb_model = lgb.LGBMClassifier(
    n_estimators=500,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.85,
    colsample_bytree=0.85,
    min_child_samples=20,
    reg_alpha=0.1,
    reg_lambda=1.0,
    random_state=42,
    n_jobs=-1,
    verbose=-1
)

# CatBoost for additional diversity
cat_model = CatBoostClassifier(
    iterations=500,
    depth=10,
    learning_rate=0.05,
    l2_leaf_reg=3,
    random_seed=42,
    verbose=False,
    thread_count=-1
)

# Train individual models
print("[1] Training XGBoost...")
xgb_model.fit(X_train, y_train)
xgb_pred = xgb_model.predict(X_test)
xgb_acc = accuracy_score(y_test, xgb_pred)
print(f"    [+] XGBoost Accuracy: {xgb_acc:.6f} ({xgb_acc*100:.4f}%)")

print("[2] Training LightGBM...")
lgb_model.fit(X_train, y_train)
lgb_pred = lgb_model.predict(X_test)
lgb_acc = accuracy_score(y_test, lgb_pred)
print(f"    [+] LightGBM Accuracy: {lgb_acc:.6f} ({lgb_acc*100:.4f}%)")

print("[3] Training CatBoost...")
cat_model.fit(X_train, y_train)
cat_pred = cat_model.predict(X_test)
cat_acc = accuracy_score(y_test, cat_pred)
print(f"    [+] CatBoost Accuracy: {cat_acc:.6f} ({cat_acc*100:.4f}%)\n")

# Stacking ensemble for maximum accuracy
print("[*] Creating Stacking Ensemble...")
stacking_model = StackingClassifier(
    estimators=[
        ('xgb', xgb_model),
        ('lgb', lgb_model),
        ('cat', cat_model)
    ],
    final_estimator=xgb.XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        random_state=42
    ),
    cv=5,
    n_jobs=-1
)
stacking_model.fit(X_train, y_train)

# Voting ensemble as backup
voting_model = VotingClassifier(
    estimators=[
        ('xgb', xgb_model),
        ('lgb', lgb_model),
        ('cat', cat_model)
    ],
    voting='soft',
    weights=[1.2, 1.0, 1.1],
    n_jobs=-1
)
voting_model.fit(X_train, y_train)

# Evaluate both ensembles
stack_pred = stacking_model.predict(X_test)
stack_proba = stacking_model.predict_proba(X_test)[:, 1]
vote_pred = voting_model.predict(X_test)
vote_proba = voting_model.predict_proba(X_test)[:, 1]

stack_acc = accuracy_score(y_test, stack_pred)
vote_acc = accuracy_score(y_test, vote_pred)

print(f"    [+] Stacking Ensemble Accuracy: {stack_acc:.6f} ({stack_acc*100:.4f}%)")
print(f"    [+] Voting Ensemble Accuracy: {vote_acc:.6f} ({vote_acc*100:.4f}%)\n")

# Select best ensemble
best_model = stacking_model if stack_acc >= vote_acc else voting_model
best_pred = stack_pred if stack_acc >= vote_acc else vote_pred
best_proba = stack_proba if stack_acc >= vote_acc else vote_proba
best_name = "Stacking" if stack_acc >= vote_acc else "Voting"

print("="*100)
print(f"FINAL RESULTS - {best_name} Ensemble")
print("="*100)

acc = accuracy_score(y_test, best_pred)
prec = precision_score(y_test, best_pred)
rec = recall_score(y_test, best_pred)
f1 = f1_score(y_test, best_pred)
auc = roc_auc_score(y_test, best_proba)

print(f"\n[*] Performance Metrics:")
print(f"    - Accuracy:  {acc:.6f} ({acc*100:.4f}%)")
print(f"    - Precision: {prec:.6f} ({prec*100:.4f}%)")
print(f"    - Recall:    {rec:.6f} ({rec*100:.4f}%)")
print(f"    - F1-Score:  {f1:.6f}")
print(f"    - ROC-AUC:   {auc:.6f}")

cm = confusion_matrix(y_test, best_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

print(f"\n[*] Confusion Matrix:")
print(f"    - True Negatives:  {tn:,}")
print(f"    - False Positives: {fp:,} (FPR: {fpr*100:.4f}%)")
print(f"    - False Negatives: {fn:,} (FNR: {fnr*100:.4f}%)")
print(f"    - True Positives:  {tp:,}")

print(f"\n[*] Classification Report:")
print(classification_report(y_test, best_pred, target_names=['Legitimate', 'Phishing'], digits=6))

# Retrain on FULL dataset for production
print("\n[*] Retraining on COMPLETE dataset for production deployment...")

xgb_full = xgb.XGBClassifier(
    n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.85,
    colsample_bytree=0.85, min_child_weight=3, gamma=0.1, reg_alpha=0.1,
    reg_lambda=1.0, random_state=42, n_jobs=-1, eval_metric='logloss', tree_method='hist'
)
lgb_full = lgb.LGBMClassifier(
    n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.85,
    colsample_bytree=0.85, min_child_samples=20, reg_alpha=0.1, reg_lambda=1.0,
    random_state=42, n_jobs=-1, verbose=-1
)
cat_full = CatBoostClassifier(
    iterations=500, depth=10, learning_rate=0.05, l2_leaf_reg=3,
    random_seed=42, verbose=False, thread_count=-1
)

xgb_full.fit(X_scaled, y)
lgb_full.fit(X_scaled, y)
cat_full.fit(X_scaled, y)

if best_name == "Stacking":
    final_model = StackingClassifier(
        estimators=[('xgb', xgb_full), ('lgb', lgb_full), ('cat', cat_full)],
        final_estimator=xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42),
        cv=5, n_jobs=-1
    )
else:
    final_model = VotingClassifier(
        estimators=[('xgb', xgb_full), ('lgb', lgb_full), ('cat', cat_full)],
        voting='soft', weights=[1.2, 1.0, 1.1], n_jobs=-1
    )

final_model.fit(X_scaled, y)

# Save production models
print("\n[*] Saving production models...")
joblib.dump(final_model, 'models/url_phishing_ensemble.joblib', compress=3)
joblib.dump(xgb_full, 'models/url_phishing_xgboost.joblib', compress=3)
joblib.dump(scaler, 'models/url_feature_scaler.joblib', compress=3)
joblib.dump(feature_cols, 'models/url_feature_columns.joblib', compress=3)

print("    [+] models/url_phishing_ensemble.joblib")
print("    [+] models/url_phishing_xgboost.joblib")
print("    [+] models/url_feature_scaler.joblib")
print("    [+] models/url_feature_columns.joblib")

# Feature importance
print(f"\n[*] Top 20 Most Important Features:")
importance_df = pd.DataFrame({
    'feature': feature_cols,
    'importance': xgb_full.feature_importances_
}).sort_values('importance', ascending=False).head(20)

for idx, row in importance_df.iterrows():
    print(f"    {row['feature']:35s} {row['importance']:.6f}")

print("\n" + "="*100)
print(f"[+] TRAINING COMPLETED SUCCESSFULLY")
print(f"[+] Final Accuracy: {acc*100:.4f}%")
print(f"[+] Model trained on {len(X):,} samples")
print(f"[+] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*100)
