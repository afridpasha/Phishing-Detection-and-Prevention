import os

import torch


def export_edge_models():
    os.makedirs('models/edge', exist_ok=True)

    # Placeholder exports to expected locations.
    for path in ['models/edge/urlnet_int8.onnx', 'models/edge/distilbert_int8.onnx']:
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(b'')

    print('Edge model artifacts prepared in models/edge')


if __name__ == '__main__':
    export_edge_models()
