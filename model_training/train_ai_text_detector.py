import os

from transformers import AutoModelForSequenceClassification, AutoTokenizer


def train_ai_text_detector():
    model_name = 'microsoft/deberta-v3-base'
    print('Preparing AI text detector model...')
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    out = 'models/email/ai_text_detector'
    os.makedirs(out, exist_ok=True)
    model.save_pretrained(out)
    tokenizer.save_pretrained(out)
    print(f'Saved {out}')


if __name__ == '__main__':
    train_ai_text_detector()
