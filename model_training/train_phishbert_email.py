import os

from transformers import AutoModelForSequenceClassification, AutoTokenizer


def train_phishbert_email():
    model_name = 'facebook/roberta-base'
    print('Preparing PhishBERT (RoBERTa base) model...')
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    out = 'models/email/phishbert_email'
    os.makedirs(out, exist_ok=True)
    model.save_pretrained(out)
    tokenizer.save_pretrained(out)
    print(f'Saved {out}')


if __name__ == '__main__':
    train_phishbert_email()
