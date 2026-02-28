import xgboost as xgb
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from backend.url_service.feature_extractor import URLFeatureExtractor
import os

def train_xgboost_url():
    """Train XGBoost URL classifier with 87 features"""
    print("Training XGBoost URL Classifier...")
    
    dataset_path = 'datasets/url/combined_urls.csv'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}")
        return
    
    df = pd.read_csv(dataset_path)
    extractor = URLFeatureExtractor()
    
    # Extract features
    print("Extracting features...")
    features_list = []
    labels = []
    
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            print(f"Processed {idx}/{len(df)} URLs")
        try:
            features = extractor.extract_features(row['url'])
            features_list.append(features)
            labels.append(row['label'])
        except:
            continue
    
    features_df = pd.DataFrame(features_list)
    X_train, X_val, y_train, y_val = train_test_split(features_df, labels, test_size=0.2, random_state=42)
    
    # Train XGBoost
    model = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=2,
        eval_metric='auc',
        use_label_encoder=False
    )
    
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=True)
    
    # Save model
    os.makedirs('models/url', exist_ok=True)
    joblib.dump(model, 'models/url/xgboost_url.joblib')
    print("Training complete!")

if __name__ == '__main__':
    train_xgboost_url()
