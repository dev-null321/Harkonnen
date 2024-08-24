import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from torch.optim.lr_scheduler import ReduceLROnPlateau
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from tqdm import tqdm

MAX_INPUT_SIZE = 512 * 1024  # 512 KB in bytes
CHUNK_SIZE = 512  # Size of each chunk in bytes
MAX_CHUNKS = MAX_INPUT_SIZE // CHUNK_SIZE

def read_and_preprocess_binaries(directory, label, verbose=False):
    data = []
    for root, _, files in os.walk(directory):
        if verbose:
            print(f"Reading and preprocessing {len(files)} files from {directory}...")
        for i, file in enumerate(files):
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                byte_data = f.read(MAX_INPUT_SIZE)
            data.append((file_path, byte_data, label))
            if verbose and (i + 1) % 100 == 0:
                print(f"Processed {i + 1}/{len(files)} files")
    return data

class ChunkedDataset(Dataset):
    def __init__(self, data):
        self.data = data

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        _, byte_data, label = self.data[idx]
        chunks = [byte_data[i:i+CHUNK_SIZE] for i in range(0, len(byte_data), CHUNK_SIZE)]
        chunks = chunks[:MAX_CHUNKS]
        chunks = [chunk.ljust(CHUNK_SIZE, b'\0') for chunk in chunks]
        while len(chunks) < MAX_CHUNKS:
            chunks.append(b'\0' * CHUNK_SIZE)
        tensor_data = torch.tensor([list(chunk) for chunk in chunks], dtype=torch.float32)
        return tensor_data, torch.tensor([label], dtype=torch.float32)  # Return label as a 1D tensor

class LightweightCNN(nn.Module):
    def __init__(self, input_size, output_size):
        super(LightweightCNN, self).__init__()
        self.conv1 = nn.Conv1d(MAX_CHUNKS, 16, kernel_size=3, stride=1, padding=1)
        self.pool = nn.MaxPool1d(kernel_size=2, stride=2)
        self.conv2 = nn.Conv1d(16, 32, kernel_size=3, stride=1, padding=1)
        self.fc1 = nn.Linear(32 * (input_size // 4), 32)
        self.fc2 = nn.Linear(32, output_size)

    def forward(self, x):
        x = self.pool(torch.relu(self.conv1(x)))
        x = self.pool(torch.relu(self.conv2(x)))
        x = x.view(x.size(0), -1)
        x = torch.relu(self.fc1(x))
        x = self.fc2(x)
        return x

def train_model(train_loader, val_loader, num_epochs=15, learning_rate=0.001, accumulation_steps=8):
    model = LightweightCNN(input_size=CHUNK_SIZE, output_size=1).to(device)
    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    scheduler = ReduceLROnPlateau(optimizer, 'min', patience=3, factor=0.1, verbose=True)

    print(f"Starting training for {num_epochs} epochs...")
    print(f"Train batches: {len(train_loader)}, Validation batches: {len(val_loader)}")

    for epoch in range(num_epochs):
        model.train()
        total_loss = 0.0
        correct_predictions = 0
        total_predictions = 0
        optimizer.zero_grad()

        train_pbar = tqdm(train_loader, desc=f"Epoch {epoch+1}/{num_epochs} [Train]", leave=False)
        for i, (inputs, targets) in enumerate(train_pbar):
            try:
                inputs, targets = inputs.to(device), targets.to(device)
                outputs = model(inputs)
                loss = criterion(outputs, targets)
                loss = loss / accumulation_steps
                loss.backward()

                # Update metrics
                total_loss += loss.item() * accumulation_steps
                predicted = torch.sigmoid(outputs) > 0.5
                correct_predictions += (predicted == targets).sum().item()
                total_predictions += targets.numel()

                if (i + 1) % accumulation_steps == 0 or (i + 1) == len(train_loader):
                    optimizer.step()
                    optimizer.zero_grad()

                # Update progress bar
                avg_loss = total_loss / (i + 1)
                accuracy = correct_predictions / total_predictions
                train_pbar.set_postfix({"Loss": f"{avg_loss:.4f}", "Acc": f"{accuracy:.4f}"})
            except RuntimeError as e:
                print(f"Error during training: {str(e)}")
                continue

        model.eval()
        val_loss = 0.0
        val_correct_predictions = 0
        val_total_predictions = 0

        val_pbar = tqdm(val_loader, desc=f"Epoch {epoch+1}/{num_epochs} [Val]", leave=False)
        with torch.no_grad():
            for inputs, targets in val_pbar:
                try:
                    inputs, targets = inputs.to(device), targets.to(device)
                    outputs = model(inputs)
                    loss = criterion(outputs, targets)
                    val_loss += loss.item()

                    # Update metrics
                    predicted = torch.sigmoid(outputs) > 0.5
                    val_correct_predictions += (predicted == targets).sum().item()
                    val_total_predictions += targets.numel()

                    # Update progress bar
                    avg_val_loss = val_loss / (val_pbar.n + 1)
                    val_accuracy = val_correct_predictions / val_total_predictions
                    val_pbar.set_postfix({"Loss": f"{avg_val_loss:.4f}", "Acc": f"{val_accuracy:.4f}"})
                except RuntimeError as e:
                    print(f"Error during validation: {str(e)}")
                    continue

        avg_train_loss = total_loss / len(train_loader)
        avg_val_loss = val_loss / len(val_loader)
        train_accuracy = correct_predictions / total_predictions
        val_accuracy = val_correct_predictions / val_total_predictions

        print(f'Epoch [{epoch + 1}/{num_epochs}]:')
        print(f'  Train Loss: {avg_train_loss:.4f}, Train Accuracy: {train_accuracy:.4f}')
        print(f'  Val Loss: {avg_val_loss:.4f}, Val Accuracy: {val_accuracy:.4f}')

        scheduler.step(avg_val_loss)

    print("Training completed.")
    return model

def test_model(model, test_loader):
    model.eval()
    y_pred = []
    y_true = []
    with torch.no_grad():
        for inputs, targets in test_loader:
            inputs = inputs.to(device)
            outputs = model(inputs)
            predicted = (torch.sigmoid(outputs) > 0.5).long().cpu().numpy()
            y_pred.extend(predicted.flatten())
            y_true.extend(targets.cpu().numpy().flatten())
    return y_true, y_pred

def main():
    global device
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"Using device: {device}")

    train_malicious_dir = ''
    train_benign_dir = ''

    malicious_data = read_and_preprocess_binaries(train_malicious_dir, 1, verbose=True)
    benign_data = read_and_preprocess_binaries(train_benign_dir, 0, verbose=True)
    all_data = malicious_data + benign_data

    train_val_data, test_data = train_test_split(all_data, test_size=0.2, random_state=42)
    train_data, val_data = train_test_split(train_val_data, test_size=0.2, random_state=42)

    train_dataset = ChunkedDataset(train_data)
    val_dataset = ChunkedDataset(val_data)
    test_dataset = ChunkedDataset(test_data)

    train_loader = DataLoader(train_dataset, batch_size=4, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=4)
    test_loader = DataLoader(test_dataset, batch_size=4)

    trained_model = train_model(train_loader, val_loader, num_epochs=15, learning_rate=0.001, accumulation_steps=8)

    torch.save(trained_model.state_dict(), 'trained_model.pth')
    print("Model trained and saved successfully.")

    y_true, y_pred = test_model(trained_model, test_loader)

    cm = confusion_matrix(y_true, y_pred)
    print("Confusion Matrix:")
    print(cm)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)

    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")

if __name__ == "__main__":
    main()
