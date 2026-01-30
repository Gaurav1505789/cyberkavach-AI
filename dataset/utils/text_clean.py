import re

def clean_text(text):
    """
    Clean text for fraud detection by:
    1. Converting to lowercase
    2. Removing URLs
    3. Keeping alphanumeric characters and spaces
    4. Removing extra whitespace
    """
    if not isinstance(text, str):
        return ""
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove URLs
    text = re.sub(r"http\S+|www\S+", "", text)
    
    # Remove email addresses
    text = re.sub(r"\S+@\S+", "", text)
    
    # Keep only alphanumeric and spaces
    text = re.sub(r"[^a-z0-9\s]", "", text)
    
    # Remove extra whitespace
    text = re.sub(r"\s+", " ", text).strip()
    
    return text