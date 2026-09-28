import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import classification_report

from ml.dataset import train_loader, val_loader
from ml.model import TrafficCNN


# ============================================================
# Reproducibility
# ============================================================

SEED = 42

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.cuda.manual_seed_all(SEED)

torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False


# ============================================================
# Device
# ============================================================

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print("Using device:", device)


# ============================================================
# Model
# ============================================================

model = TrafficCNN(num_classes=3).to(device)


# ============================================================
# Class-weighted loss
# ============================================================

# Dataset contains 2000 images per class.
# These weights are intentionally mild so the model does not
# completely ignore any class.

class_weights = torch.tensor(
    [1.10, 1.20, 0.90],
    dtype=torch.float32
).to(device)

criterion = nn.CrossEntropyLoss(weight=class_weights)


# ============================================================
# Optimizer
# ============================================================

optimizer = optim.Adam(
    model.parameters(),
    lr=0.001,
    weight_decay=1e-4
)


# ============================================================
# Training settings
# ============================================================

EPOCHS = 30
PATIENCE = 7

best_val_accuracy = 0.0
epochs_without_improvement = 0

CHECKPOINT = "ml/checkpoints/cycle4_model.pth"

os.makedirs("ml/checkpoints", exist_ok=True)


# ============================================================
# Training
# ============================================================

for epoch in range(EPOCHS):

    # --------------------------------------------------------
    # Training
    # --------------------------------------------------------

    model.train()

    running_loss = 0.0
    correct = 0
    total = 0

    for images, labels in train_loader:

        images = images.to(device)
        labels = labels.to(device)

        optimizer.zero_grad()

        outputs = model(images)

        loss = criterion(outputs, labels)

        loss.backward()

        optimizer.step()

        running_loss += loss.item()

        predictions = outputs.argmax(dim=1)

        total += labels.size(0)
        correct += (predictions == labels).sum().item()

    train_accuracy = 100 * correct / total


    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    model.eval()

    val_correct = 0
    val_total = 0

    all_labels = []
    all_predictions = []

    with torch.no_grad():

        for images, labels in val_loader:

            images = images.to(device)
            labels = labels.to(device)

            outputs = model(images)

            predictions = outputs.argmax(dim=1)

            val_total += labels.size(0)
            val_correct += (predictions == labels).sum().item()

            all_labels.extend(labels.cpu().tolist())
            all_predictions.extend(predictions.cpu().tolist())

    val_accuracy = 100 * val_correct / val_total


    # --------------------------------------------------------
    # Print metrics
    # --------------------------------------------------------

    print(
        f"Epoch [{epoch + 1}/{EPOCHS}] "
        f"Loss: {running_loss / len(train_loader):.4f} "
        f"Train Acc: {train_accuracy:.2f}% "
        f"Val Acc: {val_accuracy:.2f}%"
    )


    # --------------------------------------------------------
    # Save best model
    # --------------------------------------------------------

    if val_accuracy > best_val_accuracy:

        best_val_accuracy = val_accuracy
        epochs_without_improvement = 0

        torch.save(
            {
                "model_state_dict": model.state_dict(),
                "classes": ["benign", "botnet", "ddos"],
                "image_size": 64,
                "architecture": "cycle4"
            },
            CHECKPOINT
        )

        print("  ✓ Cycle 4 model saved")

        print(
            classification_report(
                all_labels,
                all_predictions,
                target_names=["benign", "botnet", "ddos"],
                digits=2,
                zero_division=0
            )
        )

    else:

        epochs_without_improvement += 1


    # --------------------------------------------------------
    # Early stopping
    # --------------------------------------------------------

    if epochs_without_improvement >= PATIENCE:

        print("\nEarly stopping triggered.")

        break


# ============================================================
# Complete
# ============================================================

print("\nCycle 4 training complete.")
print(f"Best validation accuracy: {best_val_accuracy:.2f}%")
print(f"Checkpoint: {CHECKPOINT}")