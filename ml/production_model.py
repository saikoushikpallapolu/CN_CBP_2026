"""Compact ResNet-18 1D, focal loss and held-out temperature calibration."""
import torch
from torch import nn
from torch.nn import functional as F


class ResidualBlock(nn.Module):
    def __init__(self, incoming, outgoing, stride=1):
        super().__init__()
        self.body = nn.Sequential(nn.Conv1d(incoming, outgoing, 3, stride, 1, bias=False),
                                  nn.BatchNorm1d(outgoing), nn.ReLU(),
                                  nn.Conv1d(outgoing, outgoing, 3, 1, 1, bias=False), nn.BatchNorm1d(outgoing))
        self.skip = nn.Identity() if incoming == outgoing and stride == 1 else nn.Sequential(
            nn.Conv1d(incoming, outgoing, 1, stride, bias=False), nn.BatchNorm1d(outgoing))

    def forward(self, x):
        return F.relu(self.body(x) + self.skip(x))


class FlowResNet(nn.Module):
    def __init__(self, num_classes=3, width=16):
        super().__init__()
        self.stem = nn.Sequential(nn.Conv1d(1, width, 7, 2, 3, bias=False), nn.BatchNorm1d(width), nn.ReLU())
        layers = []
        incoming = width
        for stage in range(4):
            outgoing = width * 2 ** stage
            layers.extend([ResidualBlock(incoming, outgoing, 1 if stage == 0 else 2), ResidualBlock(outgoing, outgoing)])
            incoming = outgoing
        self.blocks = nn.Sequential(*layers)
        self.head = nn.Linear(incoming, num_classes)

    def forward(self, x):
        x = x.reshape(x.shape[0], 1, 512)
        return self.head(self.blocks(self.stem(x)).mean(dim=-1))


class FocalLoss(nn.Module):
    def __init__(self, gamma=2.0, weight=None):
        super().__init__()
        self.gamma = gamma
        self.register_buffer("weight", weight)

    def forward(self, logits, targets):
        logp = F.log_softmax(logits, dim=1).gather(1, targets[:, None]).squeeze(1)
        loss = -(1 - logp.exp()).pow(self.gamma) * logp
        if self.weight is not None:
            loss = loss * self.weight[targets]
        return loss.mean()


def calibrate_temperature(logits, labels):
    # Bounded one-dimensional search is stable even on small calibration sets.
    temperatures = torch.logspace(-1, 1.3, 100, device=logits.device)
    losses = torch.stack([F.cross_entropy(logits / t, labels) for t in temperatures])
    return float(temperatures[losses.argmin()])


def probabilities(logits, temperature=1.0, confidence_threshold=.75, entropy_threshold=.8):
    p = F.softmax(logits / temperature, dim=1)
    entropy = -(p * p.clamp_min(1e-12).log()).sum(1) / torch.log(torch.tensor(p.shape[1], device=p.device))
    predicted = p.argmax(1)
    confidence_cutoff = torch.as_tensor(confidence_threshold, device=p.device)
    entropy_cutoff = torch.as_tensor(entropy_threshold, device=p.device)
    if confidence_cutoff.ndim:
        confidence_cutoff = confidence_cutoff[predicted]
    if entropy_cutoff.ndim:
        entropy_cutoff = entropy_cutoff[predicted]
    rejected = (p.max(1).values < confidence_cutoff) | (entropy > entropy_cutoff)
    return p, entropy, rejected
