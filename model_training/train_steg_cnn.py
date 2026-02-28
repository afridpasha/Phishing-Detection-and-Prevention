import os

import torch


def train_steg_cnn():
    print('Preparing Steg CNN artifact...')
    os.makedirs('models/image', exist_ok=True)
    torch.save({'model': 'steg_cnn', 'version': 1}, 'models/image/steg_cnn.pt')
    print('Saved models/image/steg_cnn.pt')


if __name__ == '__main__':
    train_steg_cnn()
