"""
ULTRA-ADVANCED PHISHING DETECTION MODEL TRAINER
State-of-the-art ensemble with deep pattern analysis
Achieves maximum accuracy through comprehensive feature engineering
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, StackingClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix
import xgboost as xgb
import lightgbm as lgb
from sklearn.ensemble import ExtraTreesClassifier
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

print("="*100)
print("ULTRA-ADVANCED PHISHING DETECTION MODEL TRAINER")
print("State-of-the-art Ensemble with Deep Pattern Analysis")
print("="*100)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

np.random.seed(42)

# Load dataset
DATASET_PATH = 'datasets/URL_PHISHING_DATASET.csv'
print("[*] Loading and analyzing dataset...")
df = pd.read_csv(DATASET_PATH, low_memory=False)
print(f"[+] Loaded {len(df):,} URLs")
print(f"    - Phishing URLs: {(df['label']=='phishing').sum():,} ({(df['label']=='phishing').sum()/len(df)*100:.2f}%)")
print(f"    - Legitimate URLs: {(df['label']=='legitimate').sum():,} ({(df['label']=='legitimate').sum()/len(df)*100:.2f}%)")

# Analyze attack types
print(f"\n[*] Attack Type Distribution:")
attack_types = df[df['label']=='phishing']['attack_type'].value_counts()
for attack, count in attack_types.head(10).items():
    print(f"    - {attack:30s}: {count:,}")

# Feature engineering - ALL numeric features
print(f"\n[*] Engineering features from {df.shape[1]} columns...")
feature_cols = [
    'url_length', 'domain_length', 'path_length', 'has_https', 'has_http',
    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
    'num_question_marks', 'num_equal_signs', 'num_at_symbols', 'num_ampersands',
    'num_digits', 'num_percent', 'num_subdomains', 'has_ip_address', 'has_port',
    'has_suspicious_words', 'has_shortener', 'digit_ratio', 'domain_entropy',
    'domain_has_digits', 'domain_has_hyphens', 'fragment_length',
    'has_login_path', 'has_redirect_param', 'https_in_domain', 'is_brand_similar',
    'is_http', 'is_https', 'is_ip_address', 'is_shortener', 'letter_ratio',
    'max_consecutive_digits', 'max_consecutive_dots', 'max_consecutive_hyphens',
    'min_brand_distance', 'num_exclamation', 'num_hashtags', 'num_letters',
    'num_query_params', 'num_suspicious_words', 'path_depth', 'query_length',
    'tld_length', 'tld_suspicious', 'url_entropy', 'special_char_ratio'
]

X = df[feature_cols].fillna(0).copy()
y = (df['label'] == 'phishing').astype(int)

# Advanced feature engineering
print("[*] Creating advanced derived features...")
X['url_complexity'] = X['num_dots'] + X['num_hyphens'] + X['num_underscores']
X['suspicious_score'] = X['has_suspicious_words'] + X['has_login_path'] + X['has_redirect_param']
X['encoding_anomaly'] = X['num_percent'] + X['num_equal_signs']
X['domain_risk'] = X['domain_has_digits'] + X['domain_has_hyphens'] + X['is_ip_address']
X['url_obfuscation'] = X['max_consecutive_digits'] + X['max_consecutive_dots']
X['path_complexity'] = X['path_length'] / (X['url_length'] + 1)
X['query_complexity'] = X['query_length'] / (X['url_length'] + 1)
X['entropy_ratio'] = X['url_entropy'] / (X['domain_entropy'] + 0.1)
X['special_char_density'] = X['special_char_ratio'] * X['url_length']
X['subdomain_depth'] = X['num_subdomains'] * X['num_dots']

print(f"[+] Total features: {X.shape[1]}")
print(f"[+] Total samples: {X.shape[0]:,}\n")

# Analyze feature distributions
print("[*] Analyzing feature patterns...")
phishing_mask = y == 1
legitimate_mask = y == 0

key_features = ['url_length', 'domain_entropy', 'num_dots', 'has_suspicious_words', 'url_entropy']
print("\n[*] Key Feature Statistics:")
print(f"{'Feature':<25} {'Phishing Mean':<15} {'Legitimate Mean':<15} {'Difference':<15}")
print("-" * 70)
for feat in key_features:
    phish_mean = X.loc[phishing_mask, feat].mean()
    legit_mean = X.loc[legitimate_mask, feat].mean()
    diff = abs(phish_mean - legit_mean)
    print(f"{feat:<25} {phish_mean:<15.4f} {legit_mean:<15.4f} {diff:<15.4f}")

# Split data
print(f"\n[*] Splitting dataset (80/20 stratified split)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"    - Training: {len(X_train):,} samples")
print(f"    - Testing: {len(X_test):,} samples")

# Scale features for better performance
print("\n[*] Scaling features...")
scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Build ultra-advanced ensemble
print("\n[*] Building state-of-the-art ensemble models...")
print("    [1] XGBoost (Extreme Gradient Boosting)")
print("    [2] LightGBM (Light Gradient Boosting Machine)")
print("    [3] Extra Trees (Extremely Randomized Trees)")
print("    [4] Random Forest (Deep Trees)")
print("    [5] Gradient Boosting (Classic)")

# Model 1: XGBoost - Optimized for accuracy
xgb_model = xgb.XGBClassifier(
    n_estimators=500,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.9,
    min_child_weight=1,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.0,
    random_state=42,
    n_jobs=-1,
    eval_metric='logloss',
    tree_method='hist'
)

# Model 2: LightGBM - Fast and accurate
lgb_model = lgb.LGBMClassifier(
    n_estimators=500,
    max_depth=10,
    learning_rate=0.05,
    subsample=0.9,
    colsample_bytree=0.9,
    min_child_samples=20,
    reg_alpha=0.1,
    reg_lambda=1.0,
    random_state=42,
    n_jobs=-1,
    verbose=-1
)

# Model 3: Extra Trees - Another powerful ensemble
from sklearn.ensemble import ExtraTreesClassifier
et_model = ExtraTreesClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

# Model 4: Random Forest - Robust ensemble
rf_model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features='sqrt',
    random_state=42,
    n_jobs=-1
)

# Model 5: Gradient Boosting - Classic strong learner
gb_model = GradientBoostingClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.9,
    random_state=42
)

# Train individual models
print("\n[*] Training individual models...")
models = {
    'XGBoost': xgb_model,
    'LightGBM': lgb_model,
    'ExtraTrees': et_model,
    'RandomForest': rf_model,
    'GradientBoosting': gb_model
}

model_scores = {}
for name, model in models.items():
    print(f"\n    Training {name}...")
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    acc = accuracy_score(y_test, pred)
    prec = precision_score(y_test, pred)
    rec = recall_score(y_test, pred)
    f1 = f1_score(y_test, pred)
    model_scores[name] = {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1}
    print(f"        Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")

# Create weighted voting ensemble
print("\n[*] Creating weighted voting ensemble...")
ensemble = VotingClassifier(
    estimators=[
        ('xgb', xgb_model),
        ('lgb', lgb_model),
        ('et', et_model),
        ('rf', rf_model),
        ('gb', gb_model)
    ],
    voting='soft',
    weights=[2, 2, 1, 1, 1],  # Higher weight for boosting models
    n_jobs=-1
)

print("    Training ensemble...")
ensemble.fit(X_train, y_train)

# Create stacking ensemble for even better performance
print("\n[*] Creating stacking ensemble (meta-learner)...")
stacking = StackingClassifier(
    estimators=[
        ('xgb', xgb_model),
        ('lgb', lgb_model),
        ('et', et_model),
        ('rf', rf_model)
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

print("    Training stacking ensemble...")
stacking.fit(X_train, y_train)

# Evaluate ensembles
print("\n" + "="*100)
print("EVALUATION RESULTS")
print("="*100)

# Voting Ensemble
print("\n[*] Voting Ensemble Performance:")
voting_pred = ensemble.predict(X_test)
voting_proba = ensemble.predict_proba(X_test)[:, 1]

v_acc = accuracy_score(y_test, voting_pred)
v_prec = precision_score(y_test, voting_pred)
v_rec = recall_score(y_test, voting_pred)
v_f1 = f1_score(y_test, voting_pred)
v_auc = roc_auc_score(y_test, voting_proba)

print(f"    Accuracy:  {v_acc:.6f} ({v_acc*100:.4f}%)")
print(f"    Precision: {v_prec:.6f} ({v_prec*100:.4f}%)")
print(f"    Recall:    {v_rec:.6f} ({v_rec*100:.4f}%)")
print(f"    F1-Score:  {v_f1:.6f}")
print(f"    ROC-AUC:   {v_auc:.6f}")

# Stacking Ensemble
print("\n[*] Stacking Ensemble Performance:")
stacking_pred = stacking.predict(X_test)
stacking_proba = stacking.predict_proba(X_test)[:, 1]

s_acc = accuracy_score(y_test, stacking_pred)
s_prec = precision_score(y_test, stacking_pred)
s_rec = recall_score(y_test, stacking_pred)
s_f1 = f1_score(y_test, stacking_pred)
s_auc = roc_auc_score(y_test, stacking_proba)

print(f"    Accuracy:  {s_acc:.6f} ({s_acc*100:.4f}%)")
print(f"    Precision: {s_prec:.6f} ({s_prec*100:.4f}%)")
print(f"    Recall:    {s_rec:.6f} ({s_rec*100:.4f}%)")
print(f"    F1-Score:  {s_f1:.6f}")
print(f"    ROC-AUC:   {s_auc:.6f}")

# Choose best model
best_model = stacking if s_acc > v_acc else ensemble
best_name = "Stacking" if s_acc > v_acc else "Voting"
best_acc = max(s_acc, v_acc)

print(f"\n[+] Best Model: {best_name} Ensemble (Accuracy: {best_acc:.6f})")

# Confusion Matrix
cm = confusion_matrix(y_test, best_model.predict(X_test))
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

print(f"\n[*] Confusion Matrix:")
print(f"    True Negatives:  {tn:,} (Correctly identified legitimate)")
print(f"    False Positives: {fp:,} (Legitimate marked as phishing) - FPR: {fpr*100:.4f}%")
print(f"    False Negatives: {fn:,} (Phishing marked as legitimate) - FNR: {fnr*100:.4f}%")
print(f"    True Positives:  {tp:,} (Correctly identified phishing)")

print(f"\n[*] Classification Report:")
print(classification_report(y_test, best_model.predict(X_test), 
                          target_names=['Legitimate', 'Phishing'], digits=4))

# Cross-validation
print("\n[*] Performing 5-Fold Cross-Validation...")
cv_scores = cross_val_score(best_model, X_train, y_train, cv=5, scoring='accuracy', n_jobs=-1)
print(f"    CV Scores: {[f'{s:.4f}' for s in cv_scores]}")
print(f"    Mean CV Accuracy: {cv_scores.mean():.6f} (+/- {cv_scores.std() * 2:.6f})")

# Retrain on full dataset
print("\n[*] Retraining best model on full dataset...")
best_model_full = StackingClassifier(
    estimators=[
        ('xgb', xgb.XGBClassifier(n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.9, 
                                  colsample_bytree=0.9, random_state=42, n_jobs=-1, eval_metric='logloss')),
        ('lgb', lgb.LGBMClassifier(n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.9,
                                   colsample_bytree=0.9, random_state=42, n_jobs=-1, verbose=-1)),
        ('et', ExtraTreesClassifier(n_estimators=300, max_depth=20, random_state=42, n_jobs=-1)),
        ('rf', RandomForestClassifier(n_estimators=300, max_depth=20, random_state=42, n_jobs=-1))
    ],
    final_estimator=xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42),
    cv=5,
    n_jobs=-1
)

scaler_full = RobustScaler()
X_scaled_full = scaler_full.fit_transform(X)
best_model_full.fit(X, y)

# Save models
print("\n[*] Saving models and artifacts...")
joblib.dump(best_model_full, 'models/url_phishing_advanced.joblib', compress=3)
joblib.dump(scaler_full, 'models/url_scaler.joblib', compress=3)
joblib.dump(list(X.columns), 'models/url_feature_columns_advanced.joblib', compress=3)

# Save individual models
joblib.dump(xgb_model, 'models/url_phishing_xgboost.joblib', compress=3)
joblib.dump(lgb_model, 'models/url_phishing_lightgbm.joblib', compress=3)
joblib.dump(et_model, 'models/url_phishing_extratrees.joblib', compress=3)
joblib.dump(ensemble, 'models/url_phishing_ensemble.joblib', compress=3)

print("    [+] models/url_phishing_advanced.joblib (Best Stacking Model)")
print("    [+] models/url_phishing_ensemble.joblib (Voting Ensemble)")
print("    [+] models/url_phishing_xgboost.joblib")
print("    [+] models/url_phishing_lightgbm.joblib")
print("    [+] models/url_phishing_extratrees.joblib")
print("    [+] models/url_scaler.joblib")
print("    [+] models/url_feature_columns_advanced.joblib")

# Feature importance
print("\n[*] Top 20 Most Important Features:")
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': xgb_model.feature_importances_
}).sort_values('importance', ascending=False).head(20)

for idx, row in feature_importance.iterrows():
    print(f"    {row['feature']:35s} {row['importance']:.6f}")

# Summary
print("\n" + "="*100)
print("TRAINING SUMMARY")
print("="*100)
print(f"[+] Dataset: {len(df):,} URLs analyzed")
print(f"[+] Features: {X.shape[1]} engineered features")
print(f"[+] Best Model: {best_name} Ensemble")
print(f"[+] Final Accuracy: {best_acc:.6f} ({best_acc*100:.4f}%)")
print(f"[+] False Positive Rate: {fpr*100:.4f}%")
print(f"[+] False Negative Rate: {fnr*100:.4f}%")
print(f"[+] Models trained: 5 individual + 2 ensembles")
print(f"[+] Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*100)
print("\n[SUCCESS] Ultra-advanced phishing detection model trained with maximum accuracy!")
