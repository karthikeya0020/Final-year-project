"""
Transformer-Based WAF Classifier Model

A lightweight Transformer encoder that classifies HTTP request feature vectors
into one of 4 classes: Normal, SQL Injection, DDoS, or MITM.
"""

import torch
import torch.nn as nn
import math


# Class labels
CLASSES = ["Normal", "SQL_Injection", "DDoS", "MITM"]
NUM_CLASSES = len(CLASSES)
FEATURE_DIM = 16  # Number of input features per request


class PositionalEncoding(nn.Module):
    """Adds positional information to the feature sequence."""

    def __init__(self, d_model, max_len=64):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        if d_model % 2 == 1:
            pe[:, 1::2] = torch.cos(position * div_term[:-1])
        else:
            pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # (1, max_len, d_model)
        self.register_buffer("pe", pe)

    def forward(self, x):
        # x shape: (batch, seq_len, d_model)
        return x + self.pe[:, : x.size(1), :]


class WAFTransformer(nn.Module):
    """
    Transformer-based Web Application Firewall classifier.

    Architecture:
        Input (16 features) → Linear projection (64d) → Positional Encoding
        → Transformer Encoder (2 layers, 4 heads) → Global Average Pooling
        → Classification Head → 4 classes
    """

    def __init__(
        self,
        input_dim=FEATURE_DIM,
        d_model=64,
        nhead=4,
        num_layers=2,
        dim_feedforward=128,
        num_classes=NUM_CLASSES,
        dropout=0.1,
    ):
        super().__init__()

        self.d_model = d_model

        # Project input features to model dimension
        self.input_projection = nn.Linear(input_dim, d_model)

        # Positional encoding
        self.pos_encoder = PositionalEncoding(d_model)

        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer, num_layers=num_layers
        )

        # Classification head
        self.classifier = nn.Sequential(
            nn.LayerNorm(d_model),
            nn.Linear(d_model, 32),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(32, num_classes),
        )

    def forward(self, x):
        """
        Forward pass.
        Args:
            x: (batch_size, seq_len, input_dim) or (batch_size, input_dim)
        Returns:
            logits: (batch_size, num_classes)
        """
        # If input is 2D, treat each feature as a sequence token
        if x.dim() == 2:
            # Reshape: (batch, 16) → (batch, 16, 1) → project to (batch, 16, d_model)
            x = x.unsqueeze(-1)
            x = x.expand(-1, -1, self.d_model)
            x = self.input_projection(
                torch.zeros(x.size(0), x.size(1), FEATURE_DIM, device=x.device)
            )
            # Actually, let's treat each feature individually
            # Reshape to (batch, seq_len=16, 1) and project
            pass

        # Better approach: treat the 16 features as a sequence of length 16
        # Each feature becomes a single-element token, projected to d_model
        if x.dim() == 2:
            batch_size = x.size(0)
            # (batch, 16) → (batch, 16, 1)
            x = x.unsqueeze(-1)
            # (batch, 16, 1) → (batch, 16, d_model) via linear per-token
            x = self.input_projection.weight[:, 0:1].T * x + self.input_projection.bias

        if x.dim() == 3 and x.size(-1) == FEATURE_DIM:
            x = self.input_projection(x)

        # Add positional encoding
        x = self.pos_encoder(x)

        # Transformer encoding
        x = self.transformer_encoder(x)

        # Global average pooling over sequence dimension
        x = x.mean(dim=1)

        # Classification
        logits = self.classifier(x)
        return logits


class WAFTransformerSimple(nn.Module):
    """
    Simplified Transformer WAF classifier.

    Takes a flat feature vector, reshapes into a sequence of tokens,
    applies transformer encoding, and classifies.
    """

    def __init__(
        self,
        input_dim=FEATURE_DIM,
        d_model=64,
        nhead=4,
        num_layers=2,
        dim_feedforward=128,
        num_classes=NUM_CLASSES,
        dropout=0.1,
        seq_len=4,  # Split 16 features into 4 tokens of 4 features each
    ):
        super().__init__()

        self.seq_len = seq_len
        self.token_dim = input_dim // seq_len  # 16 / 4 = 4 features per token
        self.d_model = d_model

        # Project each token to d_model dimensions
        self.input_projection = nn.Linear(self.token_dim, d_model)

        # Positional encoding
        self.pos_encoder = PositionalEncoding(d_model, max_len=seq_len)

        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer, num_layers=num_layers
        )

        # CLS token (learnable)
        self.cls_token = nn.Parameter(torch.randn(1, 1, d_model))

        # Classification head
        self.classifier = nn.Sequential(
            nn.LayerNorm(d_model),
            nn.Linear(d_model, 32),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(32, num_classes),
        )

    def forward(self, x):
        """
        Args:
            x: (batch_size, input_dim) — flat feature vector of 16 features
        Returns:
            logits: (batch_size, num_classes)
        """
        batch_size = x.size(0)

        # Reshape: (batch, 16) → (batch, 4, 4)
        x = x.view(batch_size, self.seq_len, self.token_dim)

        # Project tokens: (batch, 4, 4) → (batch, 4, d_model)
        x = self.input_projection(x)

        # Add CLS token: (batch, 5, d_model)
        cls_tokens = self.cls_token.expand(batch_size, -1, -1)
        x = torch.cat([cls_tokens, x], dim=1)

        # Add positional encoding (for the 5 tokens)
        # Extend PE to handle CLS token
        x = x + torch.zeros_like(x)  # placeholder; PE applied below
        # Manual positional encoding for CLS + 4 tokens
        pos = torch.arange(x.size(1), device=x.device).unsqueeze(0).float()
        pos_enc = torch.zeros_like(x)
        for i in range(0, self.d_model, 2):
            div = math.exp(-i * math.log(10000.0) / self.d_model)
            pos_enc[:, :, i] = torch.sin(pos * div)
            if i + 1 < self.d_model:
                pos_enc[:, :, i + 1] = torch.cos(pos * div)
        x = x + pos_enc * 0.1  # Scale down PE

        # Transformer encoder
        x = self.transformer_encoder(x)

        # Use CLS token output for classification
        cls_output = x[:, 0, :]

        # Classify
        logits = self.classifier(cls_output)
        return logits


def get_model(device="cpu"):
    """Create and return the WAF Transformer model."""
    model = WAFTransformerSimple(
        input_dim=FEATURE_DIM,
        d_model=64,
        nhead=4,
        num_layers=2,
        dim_feedforward=128,
        num_classes=NUM_CLASSES,
        dropout=0.1,
    )
    return model.to(device)


def load_model(path="waf_model.pth", device="cpu"):
    """Load a pre-trained WAF model from disk."""
    model = get_model(device)
    model.load_state_dict(torch.load(path, map_location=device, weights_only=True))
    model.eval()
    return model
