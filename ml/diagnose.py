import torch
from collections import Counter
from ml.dataset import val_loader
from ml.model import TrafficCNN

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

model = TrafficCNN().to(device)

checkpoint = torch.load(
    "ml/checkpoints/cycle3_model.pth",
    map_location=device
)

model.load_state_dict(checkpoint["model_state_dict"])
model.eval()

classes = checkpoint["classes"]

true_counts = Counter()
pred_counts = Counter()

correct = 0
total = 0

with torch.no_grad():
    for images, labels in val_loader:
        images = images.to(device)

        outputs = model(images)
        predictions = outputs.argmax(dim=1).cpu()

        for label in labels:
            true_counts[classes[label.item()]] += 1

        for pred in predictions:
            pred_counts[classes[pred.item()]] += 1

        correct += (predictions == labels).sum().item()
        total += len(labels)

print("Validation accuracy:", round(correct / total * 100, 2), "%")

print("\nActual validation distribution:")
for c in classes:
    print(c, ":", true_counts[c])

print("\nPredicted validation distribution:")
for c in classes:
    print(c, ":", pred_counts[c])