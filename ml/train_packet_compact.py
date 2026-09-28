import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Subset
from torchvision import datasets, transforms
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score

import sys
from pathlib import Path

# Allow imports from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Using device:", device)

# ============================================================
# Dataset and Chronological Split
# ============================================================
DATA_DIR = "data/processed_packet_compact"
BATCH_SIZE = 32

transform = transforms.Compose([
    transforms.Grayscale(num_output_channels=1),
    transforms.ToTensor(),
    transforms.Normalize((0.5,), (0.5,))
])

dataset = datasets.ImageFolder(DATA_DIR, transform=transform)

# Ensure chronological order by sorting samples based on path
dataset.samples.sort(key=lambda x: x[0])
dataset.imgs = dataset.samples

train_indices = []
val_indices = []
test_indices = []

class_counts = {c: 0 for c in range(len(dataset.classes))}

for idx, (path, class_idx) in enumerate(dataset.samples):
    count = class_counts[class_idx]
    if count < 1400:
        train_indices.append(idx)
    elif count < 1700:
        val_indices.append(idx)
    else:
        test_indices.append(idx)
    class_counts[class_idx] += 1

train_dataset = Subset(dataset, train_indices)
val_dataset = Subset(dataset, val_indices)
test_dataset = Subset(dataset, test_indices)

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

print("Classes:", dataset.classes)
print("Total Dataset Size:", len(dataset))
print("Train Size:", len(train_dataset))
print("Validation Size:", len(val_dataset))
print("Test Size:", len(test_dataset))

# ============================================================
# Model, Loss, Optimizer
# ============================================================
model = TrafficCNN(num_classes=3).to(device)

class_weights = torch.tensor([1.10, 1.20, 0.90], dtype=torch.float32).to(device)
criterion = nn.CrossEntropyLoss(weight=class_weights)

optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)

EPOCHS = 30
PATIENCE = 7
best_val_accuracy = 0.0
epochs_without_improvement = 0

CHECKPOINT = "ml/checkpoints/packet_compact_model.pth"
os.makedirs("ml/checkpoints", exist_ok=True)

best_epoch = 0

# ============================================================
# Training
# ============================================================
for epoch in range(EPOCHS):
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

    # Validation
    model.eval()
    val_correct = 0
    val_total = 0
    
    with torch.no_grad():
        for images, labels in val_loader:
            images = images.to(device)
            labels = labels.to(device)
            outputs = model(images)
            predictions = outputs.argmax(dim=1)
            val_total += labels.size(0)
            val_correct += (predictions == labels).sum().item()

    val_accuracy = 100 * val_correct / val_total
    print(f"Epoch [{epoch + 1}/{EPOCHS}] Loss: {running_loss / len(train_loader):.4f} Train Acc: {train_accuracy:.2f}% Val Acc: {val_accuracy:.2f}%")

    if val_accuracy > best_val_accuracy:
        best_val_accuracy = val_accuracy
        epochs_without_improvement = 0
        best_epoch = epoch + 1
        torch.save({
            "model_state_dict": model.state_dict(),
            "classes": dataset.classes,
            "architecture": "TrafficCNN"
        }, CHECKPOINT)
        print("  - Model saved")
    else:
        epochs_without_improvement += 1

    if epochs_without_improvement >= PATIENCE:
        print(f"\nEarly stopping triggered at epoch {epoch + 1}.")
        break

print("\nTraining complete.")
print(f"Best validation accuracy: {best_val_accuracy:.2f}% at epoch {best_epoch}")

# ============================================================
# Testing
# ============================================================
print("\nLoading best model for testing...")
checkpoint = torch.load(CHECKPOINT, map_location=device)
model.load_state_dict(checkpoint["model_state_dict"])
model.eval()

y_true = []
y_pred = []

with torch.no_grad():
    for images, labels in test_loader:
        images = images.to(device)
        outputs = model(images)
        predictions = outputs.argmax(dim=1).cpu()
        y_true.extend(labels.tolist())
        y_pred.extend(predictions.tolist())

accuracy = accuracy_score(y_true, y_pred)
macro_f1 = f1_score(y_true, y_pred, average="macro")
weighted_f1 = f1_score(y_true, y_pred, average="weighted")
print(f"\nTest Accuracy: {accuracy * 100:.2f}%")
print(f"Macro F1: {macro_f1:.4f}")
print(f"Weighted F1: {weighted_f1:.4f}\n")
print("Classification Report:")
print(classification_report(y_true, y_pred, target_names=dataset.classes, digits=4))
print("Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))
