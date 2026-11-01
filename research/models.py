"""Matched-prefix 1D/2D residual models and a causal feature-fusion ablation."""
import torch
from torch import nn
from ml.production_model import FlowResNet


class Residual2D(nn.Module):
    def __init__(self,incoming,outgoing,stride=1):
        super().__init__()
        self.body=nn.Sequential(nn.Conv2d(incoming,outgoing,3,stride,1,bias=False),nn.BatchNorm2d(outgoing),nn.ReLU(),
                                nn.Conv2d(outgoing,outgoing,3,1,1,bias=False),nn.BatchNorm2d(outgoing))
        self.skip=nn.Identity() if incoming==outgoing and stride==1 else nn.Sequential(nn.Conv2d(incoming,outgoing,1,stride,bias=False),nn.BatchNorm2d(outgoing))
    def forward(self,x):return (self.body(x)+self.skip(x)).relu()


class PrefixModel(nn.Module):
    def __init__(self,kind="1d",hybrid=False):
        super().__init__();self.kind=kind;self.hybrid=hybrid
        if kind=="1d":
            base=FlowResNet(width=16);self.stem=base.stem;self.blocks=base.blocks;embedding=128
        else:
            width=8;self.stem=nn.Sequential(nn.Conv2d(1,width,3,1,1,bias=False),nn.BatchNorm2d(width),nn.ReLU())
            layers=[];incoming=width
            for stage in range(4):
                outgoing=width*2**stage
                layers.extend([Residual2D(incoming,outgoing,1 if stage==0 else 2),Residual2D(outgoing,outgoing)])
                incoming=outgoing
            self.blocks=nn.Sequential(*layers);embedding=incoming
        self.head=nn.Linear(embedding+(18 if hybrid else 0),3)

    def forward(self,x,behavior=None):
        if self.kind=="1d":
            x=x.reshape(x.shape[0],1,-1);x=self.blocks(self.stem(x)).mean(-1)
        else:
            x=x.reshape(x.shape[0],1,-1,32);x=self.blocks(self.stem(x)).mean((-1,-2))
        if self.hybrid:x=torch.cat((x,behavior),dim=1)
        return self.head(x)
