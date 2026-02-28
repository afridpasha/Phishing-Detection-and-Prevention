import os

import torch


def train_efficientnet_visual():
    print('Preparing EfficientNet visual scorer artifact...')
    os.makedirs('models/image', exist_ok=True)
    torch.save({'model': 'efficientnetv2', 'version': 1}, 'models/image/efficientnetv2_visual.pt')
    print('Saved models/image/efficientnetv2_visual.pt')


if __name__ == '__main__':
    train_efficientnet_visual()
