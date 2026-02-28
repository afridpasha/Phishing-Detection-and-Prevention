import os

import torch

from backend.url_service.models.tgt_model import TemporalGraphTransformer


def train_tgt():
    print('Training TGT...')
    model = TemporalGraphTransformer()
    # Real training requires prepared graph tensors; this script initializes and saves baseline weights.
    os.makedirs('models/url', exist_ok=True)
    torch.save(model.state_dict(), 'models/url/tgt_model.pt')
    print('Saved models/url/tgt_model.pt')


if __name__ == '__main__':
    train_tgt()
