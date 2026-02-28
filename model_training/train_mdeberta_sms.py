import os

from transformers import AutoModelForSequenceClassification, AutoTokenizer


def train_mdeberta_sms():
    model_name = 'microsoft/mdeberta-v3-base'
    print('Preparing mDeBERTa SMS model...')
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    out = 'models/sms/mdeberta_sms'
    os.makedirs(out, exist_ok=True)
    model.save_pretrained(out)
    tokenizer.save_pretrained(out)
    print(f'Saved {out}')


if __name__ == '__main__':
    train_mdeberta_sms()
