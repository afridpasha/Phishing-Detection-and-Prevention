import os

import joblib
import lightgbm as lgb
import numpy as np


def train_meta_learner():
    print('Training LightGBM meta learner with synthetic bootstrap data...')
    rng = np.random.default_rng(42)
    X = rng.random((500, 20))
    y = (X[:, 0] * 0.4 + X[:, 1] * 0.3 + X[:, 2] * 0.3 > 0.6).astype(int)
    model = lgb.LGBMClassifier(
        n_estimators=300,
        num_leaves=31,
        learning_rate=0.05,
        feature_fraction=0.8,
        bagging_fraction=0.8,
        bagging_freq=5,
    )
    model.fit(X, y)
    os.makedirs('models/ensemble', exist_ok=True)
    joblib.dump(model, 'models/ensemble/meta_learner.joblib')
    print('Saved models/ensemble/meta_learner.joblib')


if __name__ == '__main__':
    train_meta_learner()
