import sys

if len(sys.argv) < 2:
    print("Usage: python detect_unicode_error.py input.csv")
    sys.exit(1)

input_path = sys.argv[1]

try:
    with open(input_path, encoding='utf-8') as f:
        for i, line in enumerate(f, 1):
            pass  # Just read all lines
    print(f"No UnicodeDecodeError detected in {input_path}")
except UnicodeDecodeError as e:
    print(f"UnicodeDecodeError detected in {input_path}: {e}")
    sys.exit(2)
