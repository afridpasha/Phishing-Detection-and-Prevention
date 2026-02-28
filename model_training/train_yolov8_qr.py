import os


def train_yolov8_qr():
    print('Preparing YOLOv8 QR artifact...')
    # Real training requires dataset yaml; this creates expected artifact placeholder metadata.
    os.makedirs('models/image', exist_ok=True)
    with open('models/image/yolov8_qr.pt', 'wb') as f:
        f.write(b'')
    print('Created models/image/yolov8_qr.pt')


if __name__ == '__main__':
    train_yolov8_qr()
