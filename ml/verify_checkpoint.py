import os
import sys
from pathlib import Path
import torch
import torch.nn.functional as F
from PIL import Image
from torchvision import transforms

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.model import TrafficCNN

def verify():
    checkpoint_path = os.path.join(PROJECT_ROOT, "ml", "checkpoints", "best_model.pth")
    if not os.path.exists(checkpoint_path):
        print(f"[-] Checkpoint not found at: {checkpoint_path}")
        return False

    print(f"[+] Found checkpoint at: {checkpoint_path}")
    checkpoint = torch.load(checkpoint_path, map_location="cpu")

    classes = checkpoint.get("classes", ["benign", "botnet", "ddos"])
    print(f"[*] Registered classes: {classes}")
    print(f"[*] Checkpoint saved at epoch: {checkpoint.get('epoch')}")
    print(f"[*] Best validation accuracy: {checkpoint.get('best_val_acc', 0):.2f}%")

    model = TrafficCNN(num_classes=len(classes))
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    # Test inference with dummy 64x64 tensor
    dummy_input = torch.randn(1, 1, 64, 64)
    with torch.no_grad():
        output = model(dummy_input)
        probs = F.softmax(output, dim=1).squeeze().tolist()
        pred_idx = int(torch.argmax(output, dim=1).item())

    print(f"[+] Dummy tensor test output shape: {list(output.shape)}")
    print(f"[+] Inferred Class: {classes[pred_idx]} ({probs[pred_idx]*100:.1f}%)")
    print(f"[+] Probability breakdown: {dict(zip(classes, [round(p, 4) for p in probs]))}")

    # Test on a real sample from data/processed if available
    sample_img_path = os.path.join(PROJECT_ROOT, "data", "processed", "ddos", "ddos_0001.png")
    if os.path.exists(sample_img_path):
        transform = transforms.Compose([
            transforms.Grayscale(num_output_channels=1),
            transforms.ToTensor(),
            transforms.Normalize((0.5,), (0.5,))
        ])
        img = Image.open(sample_img_path)
        tensor = transform(img).unsqueeze(0)
        with torch.no_grad():
            real_out = model(tensor)
            real_probs = F.softmax(real_out, dim=1).squeeze().tolist()
            real_pred = int(torch.argmax(real_out, dim=1).item())
        print(f"\n[+] Real sample test ({sample_img_path}):")
        print(f"    Ground Truth: ddos")
        print(f"    Predicted:    {classes[real_pred]} ({real_probs[real_pred]*100:.1f}%)")
        print(f"    Probabilities: {dict(zip(classes, [round(p, 4) for p in real_probs]))}")

    print("\n[OK] CHECKPOINT VERIFICATION PASSED SUCCESSFULLY!")
    return True

if __name__ == "__main__":
    verify()
