import pickle
from collections import defaultdict, Counter



def load_passwords():
    with open('rockyou.txt', 'r', encoding='latin-1') as f:
        return [line.strip() for line in f]

def build_model(passwords, order=2):
    model = defaultdict(Counter)
    for pw in passwords:
        padded = '~' * order + pw + '~'
        for i in range(len(padded) - order):
            context = padded[i:i+order]
            next_char = padded[i+order]
            model[context][next_char] += 1
    return model

passwords = load_passwords()
print(f"Loaded {len(passwords)} passwords")

model = build_model(passwords)
print("Model built")

with open('model.pkl', 'wb') as f:
    pickle.dump(dict(model), f)
print("Saved to model.pkl")