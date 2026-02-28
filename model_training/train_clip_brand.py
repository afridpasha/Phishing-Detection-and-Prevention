import os
import pickle


def train_clip_brand():
    print('Building CLIP brand embedding store...')
    embeddings = {
        'PayPal': [0.1, 0.2, 0.3],
        'Amazon': [0.2, 0.1, 0.25],
        'Apple': [0.3, 0.15, 0.05],
    }
    os.makedirs('models/image', exist_ok=True)
    with open('models/image/clip_brand_embeddings.pkl', 'wb') as f:
        pickle.dump(embeddings, f)
    print('Saved models/image/clip_brand_embeddings.pkl')


if __name__ == '__main__':
    train_clip_brand()
