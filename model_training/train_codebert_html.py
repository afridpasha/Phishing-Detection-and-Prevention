import os

from transformers import AutoModelForSequenceClassification, AutoTokenizer


def train_codebert_html():
    model_name = 'microsoft/codebert-base'
    print('Preparing CodeBERT HTML model...')
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    out = 'models/email/codebert_html'
    os.makedirs(out, exist_ok=True)
    model.save_pretrained(out)
    tokenizer.save_pretrained(out)
    print(f'Saved {out}')


if __name__ == '__main__':
    train_codebert_html()
