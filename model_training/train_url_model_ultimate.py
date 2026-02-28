"""
ULTRA-ADVANCED PHISHING DETECTION MODEL TRAINER
State-of-the-art ensemble with deep learning and AutoML optimization
Inspired by: Google Safe Browsing, Microsoft Defender SmartScreen, Opera Security
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier
from sklearn.ensemble import VotingClassifier, RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

print("="*120)
print("ULTRA-ADVANCED PHISHING DETECTION MODEL TRAINER")
print("State-of-the-Art Ensemble: XGBoost + LightGBM + CatBoost + Neural Network + Random Forest")
print("="*120)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

np.random.seed(42)

DATASET_PATH = 'datasets/URL_PHISHING_DATASET.csv'
print("[*] Loading complete dataset...")
df = pd.read_csv(DATASET_PATH, low_memory=False)
print(f"[+] Loaded {len(df):,} URLs")
print(f"    - Phishing: {(df['label']=='phishing').sum():,} ({(df['label']=='phishing').sum()/len(df)*100:.2f}%)")
print(f"    - Legitimate: {(df['label']=='legitimate').sum():,} ({(df['label']=='legitimate').sum()/len(df)*100:.2f}%)\n")

print("[*] Advanced feature engineering...")
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

# Advanced scaling
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)
X_scaled = pd.DataFrame(X_scaled, columns=feature_cols)

print(f"[+] Features: {X.shape[1]}")
print(f"[+] Total samples: {X.shape[0]:,}\n")

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.15, random_state=42, stratify=y
)
print(f"[*] Dataset split:")
print(f"    - Training: {len(X_train):,} ({len(X_train)/len(X)*100:.1f}%)")
print(f"    - Testing: {len(X_test):,} ({len(X_test)/len(X)*100:.1f}%)\n")

print("[*] Building ultra-advanced ensemble (7 models)...\n")

# Model 1: XGBoost (Optimized)
print("[1/7] Training XGBoost (Extreme Gradient Boosting)...")
xgb_model = xgb.XGBClassifier(
    n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8,
    colsample_bytree=0.8, min_child_weight=1, gamma=0.2, reg_alpha=0.1,
    reg_lambda=1.5, random_state=42, n_jobs=-1, eval_metric='logloss',
    tree_method='hist', scale_pos_weight=1
)
xgb_model.fit(X_train, y_train)
xgb_pred = xgb_model.predict(X_test)
xgb_acc = accuracy_score(y_test, xgb_pred)
print(f"      Accuracy: {xgb_acc:.6f} ({xgb_acc*100:.4f}%)")

# Model 2: LightGBM (Microsoft)
print("[2/7] Training LightGBM (Microsoft Gradient Boosting)...")
lgb_model = lgb.LGBMClassifier(
    n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8,
    colsample_bytree=0.8, min_child_samples=10, reg_alpha=0.1, reg_lambda=1.5,
    random_state=42, n_jobs=-1, verbose=-1, num_leaves=50
)
lgb_model.fit(X_train, y_train)
lgb_pred = lgb_model.predict(X_test)
lgb_acc = accuracy_score(y_test, lgb_pred)
print(f"      Accuracy: {lgb_acc:.6f} ({lgb_acc*100:.4f}%)")

# Model 3: CatBoost (Yandex)
print("[3/7] Training CatBoost (Yandex Gradient Boosting)...")
cat_model = CatBoostClassifier(
    iterations=1000, depth=12, learning_rate=0.03, l2_leaf_reg=3,
    random_seed=42, verbose=False, thread_count=-1, border_count=254
)
cat_model.fit(X_train, y_train)
cat_pred = cat_model.predict(X_test)
cat_acc = accuracy_score(y_test, cat_pred)
print(f"      Accuracy: {cat_acc:.6f} ({cat_acc*100:.4f}%)")

# Model 4: Random Forest (Ensemble Trees)
print("[4/7] Training Random Forest (Ensemble Decision Trees)...")
rf_model = RandomForestClassifier(
    n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2,
    max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced'
)
rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)
rf_acc = accuracy_score(y_test, rf_pred)
print(f"      Accuracy: {rf_acc:.6f} ({rf_acc*100:.4f}%)")

# Model 5: Extra Trees (Extremely Randomized Trees)
print("[5/7] Training Extra Trees (Extremely Randomized Trees)...")
et_model = ExtraTreesClassifier(
    n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2,
    max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced'
)
et_model.fit(X_train, y_train)
et_pred = et_model.predict(X_test)
et_acc = accuracy_score(y_test, et_pred)
print(f"      Accuracy: {et_acc:.6f} ({et_acc*100:.4f}%)")

# Model 6: Gradient Boosting
print("[6/7] Training Gradient Boosting (Scikit-learn)...")
gb_model = GradientBoostingClassifier(
    n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.8,
    min_samples_split=5, min_samples_leaf=2, random_state=42
)
gb_model.fit(X_train, y_train)
gb_pred = gb_model.predict(X_test)
gb_acc = accuracy_score(y_test, gb_pred)
print(f"      Accuracy: {gb_acc:.6f} ({gb_acc*100:.4f}%)")

# Model 7: Deep Neural Network
print("[7/7] Training Deep Neural Network (Multi-Layer Perceptron)...")
nn_model = MLPClassifier(
    hidden_layer_sizes=(256, 128, 64, 32), activation='relu', solver='adam',
    alpha=0.001, batch_size=256, learning_rate='adaptive', learning_rate_init=0.001,
    max_iter=500, random_state=42, early_stopping=True, validation_fraction=0.1
)
nn_model.fit(X_train, y_train)
nn_pred = nn_model.predict(X_test)
nn_acc = accuracy_score(y_test, nn_pred)
print(f"      Accuracy: {nn_acc:.6f} ({nn_acc*100:.4f}%)\n")

# Ultra-Advanced Voting Ensemble
print("[*] Creating Ultra-Advanced Voting Ensemble (7 models)...")
voting_model = VotingClassifier(
    estimators=[
        ('xgb', xgb_model),
        ('lgb', lgb_model),
        ('cat', cat_model),
        ('rf', rf_model),
        ('et', et_model),
        ('gb', gb_model),
        ('nn', nn_model)
    ],
    voting='soft',
    weights=[1.5, 1.4, 1.3, 1.0, 1.0, 1.1, 0.9],
    n_jobs=-1
)
voting_model.fit(X_train, y_train)

best_pred = voting_model.predict(X_test)
best_proba = voting_model.predict_proba(X_test)[:, 1]

print("\n" + "="*120)
print("FINAL RESULTS - Ultra-Advanced 7-Model Ensemble")
print("="*120)

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
tpr = tp / (tp + fn) if (tp + fn) > 0 else 0

print(f"\n[*] Confusion Matrix:")
print(f"    - True Negatives:  {tn:,}")
print(f"    - False Positives: {fp:,} (FPR: {fpr*100:.4f}%)")
print(f"    - False Negatives: {fn:,} (FNR: {fnr*100:.4f}%)")
print(f"    - True Positives:  {tp:,} (TPR: {tpr*100:.4f}%)")

print(f"\n[*] Classification Report:")
print(classification_report(y_test, best_pred, target_names=['Legitimate', 'Phishing'], digits=6))

# Retrain on FULL dataset
print("\n[*] Retraining on COMPLETE dataset for production...")

xgb_full = xgb.XGBClassifier(n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8, colsample_bytree=0.8, min_child_weight=1, gamma=0.2, reg_alpha=0.1, reg_lambda=1.5, random_state=42, n_jobs=-1, eval_metric='logloss', tree_method='hist')
lgb_full = lgb.LGBMClassifier(n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8, colsample_bytree=0.8, min_child_samples=10, reg_alpha=0.1, reg_lambda=1.5, random_state=42, n_jobs=-1, verbose=-1, num_leaves=50)
cat_full = CatBoostClassifier(iterations=1000, depth=12, learning_rate=0.03, l2_leaf_reg=3, random_seed=42, verbose=False, thread_count=-1)
rf_full = RandomForestClassifier(n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2, max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced')
et_full = ExtraTreesClassifier(n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2, max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced')
gb_full = GradientBoostingClassifier(n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.8, min_samples_split=5, min_samples_leaf=2, random_state=42)
nn_full = MLPClassifier(hidden_layer_sizes=(256, 128, 64, 32), activation='relu', solver='adam', alpha=0.001, batch_size=256, learning_rate='adaptive', max_iter=500, random_state=42, early_stopping=True, validation_fraction=0.1)

xgb_full.fit(X_scaled, y)
lgb_full.fit(X_scaled, y)
cat_full.fit(X_scaled, y)
rf_full.fit(X_scaled, y)
et_full.fit(X_scaled, y)
gb_full.fit(X_scaled, y)
nn_full.fit(X_scaled, y)

final_model = VotingClassifier(
    estimators=[('xgb', xgb_full), ('lgb', lgb_full), ('cat', cat_full), ('rf', rf_full), ('et', et_full), ('gb', gb_full), ('nn', nn_full)],
    voting='soft', weights=[1.5, 1.4, 1.3, 1.0, 1.0, 1.1, 0.9], n_jobs=-1
)
final_model.fit(X_scaled, y)

print("\n[*] Saving production models...")
joblib.dump(final_model, 'models/url_phishing_ensemble.joblib', compress=3)
joblib.dump(xgb_full, 'models/url_phishing_xgboost.joblib', compress=3)
joblib.dump(scaler, 'models/url_feature_scaler.joblib', compress=3)
joblib.dump(feature_cols, 'models/url_feature_columns.joblib', compress=3)

print("    [+] models/url_phishing_ensemble.joblib (7-model ensemble)")
print("    [+] models/url_phishing_xgboost.joblib")
print("    [+] models/url_feature_scaler.joblib")
print("    [+] models/url_feature_columns.joblib")

print(f"\n[*] Top 20 Most Important Features:")
importance_df = pd.DataFrame({
    'feature': feature_cols,
    'importance': xgb_full.feature_importances_
}).sort_values('importance', ascending=False).head(20)

for idx, row in importance_df.iterrows():
    print(f"    {row['feature']:35s} {row['importance']:.6f}")

print("\n" + "="*120)
print(f"[+] TRAINING COMPLETED SUCCESSFULLY")
print(f"[+] Final Accuracy: {acc*100:.4f}%")
print(f"[+] Model trained on {len(X):,} samples with 7 advanced algorithms")
print(f"[+] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*120)
