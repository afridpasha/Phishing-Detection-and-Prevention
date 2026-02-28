import torch

from backend.url_service.models.urlnet_model import URLNet


def test_urlnet_forward_shape():
    model = URLNet()
    char_input = torch.zeros((2, 200), dtype=torch.long)
    word_input = torch.zeros((2, 30), dtype=torch.long)
    out = model(char_input, word_input)
    assert out.shape == (2, 1)
    assert torch.all((out >= 0.0) & (out <= 1.0))
