import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from ml.dataset import test_loader

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Using device:", device)


class TrafficCNN(nn.Module):
    def __init__(self, num_classes=3):
        super().__init__()

        self.features = nn.Sequential(
            nn.Conv2d(1, 32, 3, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(),
            nn.MaxPool2d(2),

            nn.Conv2d(32, 64, 3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(),
            nn.MaxPool2d(2),

            nn.Conv2d(64, 128, 3, padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(),
            nn.MaxPool2d(2)
        )

        self.classifier = nn.Sequential(
            nn.AdaptiveAvgPool2d((4, 4)),
            nn.Flatten(),
            nn.Linear(128 * 4 * 4, 128),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(128, num_classes)
        )

    def forward(self, x):
        x = self.features(x)
        return self.classifier(x)


# Load Cycle 3 model
model = TrafficCNN().to(device)

checkpoint = torch.load(
    "ml/checkpoints/cycle4_model.pth",
    map_location=device
)

model.load_state_dict(checkpoint["model_state_dict"])
model.eval()

classes = checkpoint["classes"]

print("Loaded model classes:", classes)

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

print("\nTest Accuracy: {:.2f}%".format(accuracy * 100))

print("\nClassification Report:")
print(
    classification_report(
        y_true,
        y_pred,
        target_names=classes,
        digits=2
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))