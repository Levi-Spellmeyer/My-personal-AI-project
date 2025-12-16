import hashlib
import base64
from detector import detect_string_type

def generate_samples():
    text = "hello world"

    samples = {}

    # MD5 (32 hex chars)
    samples["md5"] = hashlib.md5(text.encode()).hexdigest()

    # SHA1 (40 hex)
    samples["sha1"] = hashlib.sha1(text.encode()).hexdigest()

    # SHA256 (64 hex)
    samples["sha256"] = hashlib.sha256(text.encode()).hexdigest()

    # SHA512 (128 hex)
    samples["sha512"] = hashlib.sha512(text.encode()).hexdigest()

    # Base64
    samples["base64"] = base64.b64encode(text.encode()).decode()

    return samples

if __name__ == "__main__":
    samples = generate_samples()
    for name, value in samples.items():
        print(f"\n{name}: {value}")
        guesses = detect_string_type(value)
        print("Top guess:", guesses[0])
