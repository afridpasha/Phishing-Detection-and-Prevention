import os

from transformers import LayoutLMv3ForSequenceClassification, LayoutLMv3Processor


def train_layoutlm_login():
    print('Preparing LayoutLMv3 login classifier...')
    model_name = 'microsoft/layoutlmv3-base'
    model = LayoutLMv3ForSequenceClassification.from_pretrained(model_name, num_labels=2)
    processor = LayoutLMv3Processor.from_pretrained(model_name)
    out = 'models/image/layoutlm_login'
    os.makedirs(out, exist_ok=True)
    model.save_pretrained(out)
    processor.save_pretrained(out)
    print(f'Saved {out}')


if __name__ == '__main__':
    train_layoutlm_login()
