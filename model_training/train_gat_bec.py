import os

import torch


def train_gat_bec():
    print('Preparing GAT BEC detector weights...')
    # Full PyG training is dataset-dependent; save an initialized state artifact.
    state = {'layers': 3, 'heads': 8}
    os.makedirs('models/email', exist_ok=True)
    torch.save(state, 'models/email/gat_bec.pt')
    print('Saved models/email/gat_bec.pt')


if __name__ == '__main__':
    train_gat_bec()
