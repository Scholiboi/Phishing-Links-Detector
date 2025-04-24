import random
from transformers import pipeline, set_seed
import pandas as pd

# Load the segmented dataset
segmented_url_path = './Generation/segmented_url.csv'
segmented_url_data = pd.read_csv(segmented_url_path)

# Combine subdomain and SLD for fallback
domain_data = segmented_url_data.dropna(subset=["subdomain", "sld"])
domain_data = domain_data.apply(lambda row: f"{row['subdomain']}.{row['sld']}", axis=1).tolist()

# Initialize Hugging Face generator with upgraded model and sampling parameters
set_seed(42)
generator = pipeline("text-generation", model="gpt2-large")

# Refined generate_domain() using the transformer generator with sampling and error handling
def generate_domain():
    prompt = random.choice("abcdefghijklmnopqrstuvwxyz")  # start with a random letter
    try:
        output = generator(prompt, max_length=15, num_return_sequences=1, do_sample=True, temperature=0.7)[0]['generated_text']
    except Exception as e:
        print(f"Generation error: {e}")
        subdomain, sld = random.choice(domain_data).split(".")
        return f"{subdomain}.{sld}"  # fallback
    generated = output.strip().split()[0].strip()  # take first token as domain candidate
    print(f"Generated domain: {generated}")
    if "." not in generated or generated.startswith(".") or generated.endswith("."):
        subdomain, sld = random.choice(domain_data).split(".")
        generated = f"{subdomain}.{sld}"  # fallback
    return generated

# Generate synthetic URL remains unchanged
def generate_url():
    protocol = random.choice(["http", "https"])
    domain = generate_domain()
    if "." in domain:
        subdomain, sld = domain.split(".", 1)
    else:
        subdomain, sld = "default", "example"
    tlds = ['com', 'org', 'net', 'io', 'gov', 'edu', 'xyz', 'info']
    tld = random.choice(tlds)
    port = f":{random.choice([80, 443, 8080])}" if random.random() > 0.5 else ""
    subdirectory = f"/{random.choice(['home', 'about', 'products', 'services', 'contact'])}"
    path = f"/{random.choice(['index.html', 'page1', 'api', 'data'])}"
    url = f"{protocol}://{subdomain}.{sld}.{tld}{port}{subdirectory}{path}"
    return url

# Generate synthetic URLs and save to CSV
num_urls_to_generate = 200
synthetic_urls = [generate_url() for _ in range(num_urls_to_generate)]
output_file_path = './Generation/synthetic_urls_validated.csv'
synthetic_urls_df = pd.DataFrame(synthetic_urls, columns=["url"])
synthetic_urls_df.to_csv(output_file_path, index=False)

print(f"Synthetic URLs saved to: {output_file_path}")
