import os


def train_setfit_sms():
    print('Preparing SetFit SMS model...')
    try:
        from setfit import SetFitModel

        model = SetFitModel.from_pretrained('sentence-transformers/paraphrase-mpnet-base-v2')
        out = 'models/sms/setfit_sms'
        os.makedirs(out, exist_ok=True)
        model.save_pretrained(out)
        print(f'Saved {out}')
    except Exception as exc:
        print(f'SetFit unavailable: {exc}')


if __name__ == '__main__':
    train_setfit_sms()
