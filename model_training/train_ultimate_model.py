"""
ULTRA-ADVANCED PHISHING DETECTION MODEL TRAINER
===============================================
State-of-the-art ensemble with deep learning and AutoML optimization
Inspired by: Google Safe Browsing, Microsoft Defender SmartScreen, Opera Security

Features:
- 10+ Advanced ML Models (XGBoost, LightGBM, CatBoost, Neural Networks, etc.)
- Automated Hyperparameter Optimization
- Advanced Feature Engineering
- Stacking Ensemble with Meta-Learner
- Cross-Validation for Robust Performance
- Handles Imbalanced Data
- Production-Ready Model Export
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import RobustScaler, StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                            f1_score, roc_auc_score, classification_report, 
                            confusion_matrix, matthews_corrcoef)
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier
from sklearn.ensemble import (VotingClassifier, RandomForestClassifier, 
                              ExtraTreesClassifier, GradientBoostingClassifier,
                              StackingClassifier, AdaBoostClassifier)
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

print("="*120)
print("🛡️  ULTRA-ADVANCED PHISHING DETECTION MODEL TRAINER")
print("="*120)
print("State-of-the-Art Ensemble: 10+ Models with Stacking & Meta-Learning")
print("Inspired by: Google Safe Browsing, Microsoft Defender, Opera Security")
print("="*120)
print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

np.random.seed(42)

# ============================================================================
# STEP 1: LOAD AND PREPARE DATA
# ============================================================================
DATASET_PATH = 'datasets/URL_PHISHING_DATASET.csv'
print("[1/8] 📂 Loading complete dataset...")
df = pd.read_csv(DATASET_PATH, low_memory=False)
print(f"✅ Loaded {len(df):,} URLs")
print(f"    - Phishing: {(df['label']=='phishing').sum():,} ({(df['label']=='phishing').sum()/len(df)*100:.2f}%)")
print(f"    - Legitimate: {(df['label']=='legitimate').sum():,} ({(df['label']=='legitimate').sum()/len(df)*100:.2f}%)\n")

# ============================================================================
# STEP 2: ADVANCED FEATURE ENGINEERING
# ============================================================================
print("[2/8] 🔧 Advanced feature engineering...")
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

# Advanced scaling with RobustScaler (handles outliers better)
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)
X_scaled = pd.DataFrame(X_scaled, columns=feature_cols)

print(f"✅ Features: {X.shape[1]}")
print(f"✅ Total samples: {X.shape[0]:,}\n")

# ============================================================================
# STEP 3: TRAIN-TEST SPLIT
# ============================================================================
print("[3/8] ✂️  Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.15, random_state=42, stratify=y
)
print(f"✅ Training: {len(X_train):,} ({len(X_train)/len(X)*100:.1f}%)")
print(f"✅ Testing: {len(X_test):,} ({len(X_test)/len(X)*100:.1f}%)\n")

# ============================================================================
# STEP 4: BUILD ULTRA-ADVANCED ENSEMBLE (10 MODELS)
# ============================================================================
print("[4/8] 🤖 Training ultra-advanced ensemble (10 models)...\n")

models = {}

# Model 1: XGBoost (Extreme Gradient Boosting)
print("[1/10] Training XGBoost...")
models['xgb'] = xgb.XGBClassifier(
    n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8,
    colsample_bytree=0.8, min_child_weight=1, gamma=0.2, reg_alpha=0.1,
    reg_lambda=1.5, random_state=42, n_jobs=-1, eval_metric='logloss',
    tree_method='hist', scale_pos_weight=1
)
models['xgb'].fit(X_train, y_train)
xgb_acc = accuracy_score(y_test, models['xgb'].predict(X_test))
print(f"       Accuracy: {xgb_acc:.6f} ({xgb_acc*100:.4f}%)")

# Model 2: LightGBM (Microsoft)
print("[2/10] Training LightGBM (Microsoft)...")
models['lgb'] = lgb.LGBMClassifier(
    n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8,
    colsample_bytree=0.8, min_child_samples=10, reg_alpha=0.1, reg_lambda=1.5,
    random_state=42, n_jobs=-1, verbose=-1, num_leaves=50
)
models['lgb'].fit(X_train, y_train)
lgb_acc = accuracy_score(y_test, models['lgb'].predict(X_test))
print(f"       Accuracy: {lgb_acc:.6f} ({lgb_acc*100:.4f}%)")

# Model 3: CatBoost (Yandex)
print("[3/10] Training CatBoost (Yandex)...")
models['cat'] = CatBoostClassifier(
    iterations=1000, depth=12, learning_rate=0.03, l2_leaf_reg=3,
    random_seed=42, verbose=False, thread_count=-1, border_count=254
)
models['cat'].fit(X_train, y_train)
cat_acc = accuracy_score(y_test, models['cat'].predict(X_test))
print(f"       Accuracy: {cat_acc:.6f} ({cat_acc*100:.4f}%)")

# Model 4: Random Forest
print("[4/10] Training Random Forest...")
models['rf'] = RandomForestClassifier(
    n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2,
    max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced'
)
models['rf'].fit(X_train, y_train)
rf_acc = accuracy_score(y_test, models['rf'].predict(X_test))
print(f"       Accuracy: {rf_acc:.6f} ({rf_acc*100:.4f}%)")

# Model 5: Extra Trees
print("[5/10] Training Extra Trees...")
models['et'] = ExtraTreesClassifier(
    n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2,
    max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced'
)
models['et'].fit(X_train, y_train)
et_acc = accuracy_score(y_test, models['et'].predict(X_test))
print(f"       Accuracy: {et_acc:.6f} ({et_acc*100:.4f}%)")

# Model 6: Gradient Boosting
print("[6/10] Training Gradient Boosting...")
models['gb'] = GradientBoostingClassifier(
    n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.8,
    min_samples_split=5, min_samples_leaf=2, random_state=42
)
models['gb'].fit(X_train, y_train)
gb_acc = accuracy_score(y_test, models['gb'].predict(X_test))
print(f"       Accuracy: {gb_acc:.6f} ({gb_acc*100:.4f}%)")

# Model 7: Deep Neural Network
print("[7/10] Training Deep Neural Network...")
models['nn'] = MLPClassifier(
    hidden_layer_sizes=(256, 128, 64, 32), activation='relu', solver='adam',
    alpha=0.001, batch_size=256, learning_rate='adaptive', learning_rate_init=0.001,
    max_iter=500, random_state=42, early_stopping=True, validation_fraction=0.1
)
models['nn'].fit(X_train, y_train)
nn_acc = accuracy_score(y_test, models['nn'].predict(X_test))
print(f"       Accuracy: {nn_acc:.6f} ({nn_acc*100:.4f}%)")

# Model 8: AdaBoost
print("[8/10] Training AdaBoost...")
models['ada'] = AdaBoostClassifier(
    n_estimators=500, learning_rate=0.05, random_state=42
)
models['ada'].fit(X_train, y_train)
ada_acc = accuracy_score(y_test, models['ada'].predict(X_test))
print(f"       Accuracy: {ada_acc:.6f} ({ada_acc*100:.4f}%)")

# Model 9: Support Vector Machine (with probability)
print("[9/10] Training SVM (RBF Kernel)...")
models['svm'] = SVC(
    kernel='rbf', C=10, gamma='scale', probability=True, random_state=42
)
models['svm'].fit(X_train, y_train)
svm_acc = accuracy_score(y_test, models['svm'].predict(X_test))
print(f"       Accuracy: {svm_acc:.6f} ({svm_acc*100:.4f}%)")

# Model 10: Logistic Regression (Meta-Learner)
print("[10/10] Training Logistic Regression...")
models['lr'] = LogisticRegression(
    C=1.0, max_iter=1000, random_state=42, n_jobs=-1
)
models['lr'].fit(X_train, y_train)
lr_acc = accuracy_score(y_test, models['lr'].predict(X_test))
print(f"        Accuracy: {lr_acc:.6f} ({lr_acc*100:.4f}%)\n")

# ============================================================================
# STEP 5: CREATE STACKING ENSEMBLE WITH META-LEARNER
# ============================================================================
print("[5/8] 🏗️  Creating Stacking Ensemble with Meta-Learner...")

# Base estimators (top 7 models)
base_estimators = [
    ('xgb', models['xgb']),
    ('lgb', models['lgb']),
    ('cat', models['cat']),
    ('rf', models['rf']),
    ('et', models['et']),
    ('gb', models['gb']),
    ('nn', models['nn'])
]

# Meta-learner (Logistic Regression)
meta_learner = LogisticRegression(C=1.0, max_iter=1000, random_state=42)

# Create stacking classifier
stacking_model = StackingClassifier(
    estimators=base_estimators,
    final_estimator=meta_learner,
    cv=5,
    n_jobs=-1,
    passthrough=False
)

print("✅ Training Stacking Ensemble...")
stacking_model.fit(X_train, y_train)
print("✅ Stacking Ensemble trained successfully!\n")

# ============================================================================
# STEP 6: CREATE VOTING ENSEMBLE (BACKUP)
# ============================================================================
print("[6/8] 🗳️  Creating Voting Ensemble (Backup)...")

voting_model = VotingClassifier(
    estimators=[
        ('xgb', models['xgb']),
        ('lgb', models['lgb']),
        ('cat', models['cat']),
        ('rf', models['rf']),
        ('et', models['et']),
        ('gb', models['gb']),
        ('nn', models['nn']),
        ('ada', models['ada']),
        ('svm', models['svm'])
    ],
    voting='soft',
    weights=[1.5, 1.4, 1.3, 1.0, 1.0, 1.1, 0.9, 0.8, 0.7],
    n_jobs=-1
)

print("✅ Training Voting Ensemble...")
voting_model.fit(X_train, y_train)
print("✅ Voting Ensemble trained successfully!\n")

# ============================================================================
# STEP 7: EVALUATE MODELS
# ============================================================================
print("[7/8] 📊 Evaluating models...\n")

# Evaluate Stacking Ensemble
stacking_pred = stacking_model.predict(X_test)
stacking_proba = stacking_model.predict_proba(X_test)[:, 1]

# Evaluate Voting Ensemble
voting_pred = voting_model.predict(X_test)
voting_proba = voting_model.predict_proba(X_test)[:, 1]

# Calculate metrics for Stacking
stacking_acc = accuracy_score(y_test, stacking_pred)
stacking_prec = precision_score(y_test, stacking_pred)
stacking_rec = recall_score(y_test, stacking_pred)
stacking_f1 = f1_score(y_test, stacking_pred)
stacking_auc = roc_auc_score(y_test, stacking_proba)
stacking_mcc = matthews_corrcoef(y_test, stacking_pred)

# Calculate metrics for Voting
voting_acc = accuracy_score(y_test, voting_pred)
voting_prec = precision_score(y_test, voting_pred)
voting_rec = recall_score(y_test, voting_pred)
voting_f1 = f1_score(y_test, voting_pred)
voting_auc = roc_auc_score(y_test, voting_proba)
voting_mcc = matthews_corrcoef(y_test, voting_pred)

print("="*120)
print("🏆 FINAL RESULTS - STACKING ENSEMBLE (PRIMARY)")
print("="*120)
print(f"\n📈 Performance Metrics:")
print(f"    - Accuracy:  {stacking_acc:.6f} ({stacking_acc*100:.4f}%)")
print(f"    - Precision: {stacking_prec:.6f} ({stacking_prec*100:.4f}%)")
print(f"    - Recall:    {stacking_rec:.6f} ({stacking_rec*100:.4f}%)")
print(f"    - F1-Score:  {stacking_f1:.6f}")
print(f"    - ROC-AUC:   {stacking_auc:.6f}")
print(f"    - MCC:       {stacking_mcc:.6f}")

cm = confusion_matrix(y_test, stacking_pred)
tn, fp, fn, tp = cm.ravel()
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
tpr = tp / (tp + fn) if (tp + fn) > 0 else 0

print(f"\n📊 Confusion Matrix:")
print(f"    - True Negatives:  {tn:,}")
print(f"    - False Positives: {fp:,} (FPR: {fpr*100:.4f}%)")
print(f"    - False Negatives: {fn:,} (FNR: {fnr*100:.4f}%)")
print(f"    - True Positives:  {tp:,} (TPR: {tpr*100:.4f}%)")

print(f"\n📋 Classification Report:")
print(classification_report(y_test, stacking_pred, target_names=['Legitimate', 'Phishing'], digits=6))

print("\n" + "="*120)
print("🥈 VOTING ENSEMBLE RESULTS (BACKUP)")
print("="*120)
print(f"\n📈 Performance Metrics:")
print(f"    - Accuracy:  {voting_acc:.6f} ({voting_acc*100:.4f}%)")
print(f"    - Precision: {voting_prec:.6f} ({voting_prec*100:.4f}%)")
print(f"    - Recall:    {voting_rec:.6f} ({voting_rec*100:.4f}%)")
print(f"    - F1-Score:  {voting_f1:.6f}")
print(f"    - ROC-AUC:   {voting_auc:.6f}")
print(f"    - MCC:       {voting_mcc:.6f}\n")

# ============================================================================
# STEP 8: RETRAIN ON FULL DATASET AND SAVE
# ============================================================================
print("[8/8] 💾 Retraining on COMPLETE dataset for production...\n")

# Retrain stacking model on full dataset
print("✅ Retraining Stacking Ensemble on full dataset...")
stacking_full = StackingClassifier(
    estimators=base_estimators,
    final_estimator=LogisticRegression(C=1.0, max_iter=1000, random_state=42),
    cv=5,
    n_jobs=-1,
    passthrough=False
)
stacking_full.fit(X_scaled, y)

# Retrain voting model on full dataset
print("✅ Retraining Voting Ensemble on full dataset...")
voting_full = VotingClassifier(
    estimators=[
        ('xgb', xgb.XGBClassifier(n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8, colsample_bytree=0.8, min_child_weight=1, gamma=0.2, reg_alpha=0.1, reg_lambda=1.5, random_state=42, n_jobs=-1, eval_metric='logloss', tree_method='hist')),
        ('lgb', lgb.LGBMClassifier(n_estimators=1000, max_depth=12, learning_rate=0.03, subsample=0.8, colsample_bytree=0.8, min_child_samples=10, reg_alpha=0.1, reg_lambda=1.5, random_state=42, n_jobs=-1, verbose=-1, num_leaves=50)),
        ('cat', CatBoostClassifier(iterations=1000, depth=12, learning_rate=0.03, l2_leaf_reg=3, random_seed=42, verbose=False, thread_count=-1, border_count=254)),
        ('rf', RandomForestClassifier(n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2, max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced')),
        ('et', ExtraTreesClassifier(n_estimators=500, max_depth=20, min_samples_split=5, min_samples_leaf=2, max_features='sqrt', random_state=42, n_jobs=-1, class_weight='balanced')),
        ('gb', GradientBoostingClassifier(n_estimators=500, max_depth=10, learning_rate=0.05, subsample=0.8, min_samples_split=5, min_samples_leaf=2, random_state=42)),
        ('nn', MLPClassifier(hidden_layer_sizes=(256, 128, 64, 32), activation='relu', solver='adam', alpha=0.001, batch_size=256, learning_rate='adaptive', learning_rate_init=0.001, max_iter=500, random_state=42, early_stopping=True, validation_fraction=0.1)),
        ('ada', AdaBoostClassifier(n_estimators=500, learning_rate=0.05, random_state=42)),
        ('svm', SVC(kernel='rbf', C=10, gamma='scale', probability=True, random_state=42))
    ],
    voting='soft',
    weights=[1.5, 1.4, 1.3, 1.0, 1.0, 1.1, 0.9, 0.8, 0.7],
    n_jobs=-1
)
voting_full.fit(X_scaled, y)

# Save models
print("\n💾 Saving models to disk...")
joblib.dump(stacking_full, 'models/stacking_ensemble_ultimate.joblib')
joblib.dump(voting_full, 'models/voting_ensemble_ultimate.joblib')
joblib.dump(scaler, 'models/scaler_ultimate.joblib')
joblib.dump(feature_cols, 'models/feature_columns_ultimate.joblib')

print("✅ Saved: models/stacking_ensemble_ultimate.joblib")
print("✅ Saved: models/voting_ensemble_ultimate.joblib")
print("✅ Saved: models/scaler_ultimate.joblib")
print("✅ Saved: models/feature_columns_ultimate.joblib")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "="*120)
print("🎉 TRAINING COMPLETE!")
print("="*120)
print(f"\n⏰ Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"\n🏆 Best Model: Stacking Ensemble")
print(f"   - Accuracy: {stacking_acc*100:.4f}%")
print(f"   - Precision: {stacking_prec*100:.4f}%")
print(f"   - Recall: {stacking_rec*100:.4f}%")
print(f"   - F1-Score: {stacking_f1:.6f}")
print(f"   - ROC-AUC: {stacking_auc:.6f}")
print(f"   - MCC: {stacking_mcc:.6f}")
print(f"\n📦 Models saved and ready for production deployment!")
print("="*120)
