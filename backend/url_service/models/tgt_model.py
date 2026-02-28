import torch
import torch.nn as nn
try:
    from torch_geometric.nn import TransformerConv
except Exception:  # pragma: no cover
    class TransformerConv(nn.Module):  # type: ignore
        def __init__(self, in_channels, out_channels, heads=1, concat=False):
            super().__init__()
            self.proj = nn.Linear(in_channels, out_channels)

        def forward(self, x, edge_index):
            return self.proj(x)

from backend.url_service.graph.domain_graph_builder import DomainGraphBuilder


class TemporalGraphTransformer(nn.Module):
    def __init__(self, node_feat_dim=64, hidden_dim=128, num_layers=3):
        super().__init__()
        self.convs = nn.ModuleList(
            [
                TransformerConv(node_feat_dim if i == 0 else hidden_dim, hidden_dim, heads=4, concat=False)
                for i in range(num_layers)
            ]
        )
        self.fc = nn.Linear(hidden_dim, 1)

    def forward(self, x, edge_index, edge_attr=None):
        for conv in self.convs:
            x = torch.relu(conv(x, edge_index))
        x = torch.mean(x, dim=0, keepdim=True)
        return torch.sigmoid(self.fc(x))


class TGTInference:
    def __init__(self, model_path: str, device='cpu'):
        self.device = device
        self.model = TemporalGraphTransformer()
        self.builder = DomainGraphBuilder()
        self.loaded = False
        try:
            self.model.load_state_dict(torch.load(model_path, map_location=device))
            self.model.to(device)
            self.model.eval()
            self.loaded = True
        except Exception:
            self.loaded = False

    async def predict(self, url_or_domain: str) -> float:
        graph = await self.builder.build_domain_graph(url_or_domain)
        age = graph.features.get('domain_age_days', 0.0)
        ip_count = graph.features.get('ip_count', 0.0)
        heuristic = min(1.0, (0.6 if age < 30 else 0.15) + min(0.2, ip_count * 0.05))

        if not self.loaded:
            return float(heuristic)

        try:
            node_count = max(2, len(graph.nodes))
            x = torch.zeros((node_count, 64), dtype=torch.float32, device=self.device)
            x[:, 0] = float(age)
            x[:, 1] = float(ip_count)
            edges = []
            for i in range(1, node_count):
                edges.append([0, i])
                edges.append([i, 0])
            edge_index = torch.tensor(edges, dtype=torch.long, device=self.device).t().contiguous()
            with torch.no_grad():
                score = float(self.model(x, edge_index).item())
            return max(0.0, min(1.0, score))
        except Exception:
            return float(heuristic)
