import random

FILE_PATH = 'files/bye_message'

def print_message():
    with open(FILE_PATH, 'r', encoding='utf-8') as f:
        messages = [line.strip() for line in f if line.strip()]

    if messages:
        text = random.choice(messages)
        print(f"\n{text}\n")
    else:
        exit()