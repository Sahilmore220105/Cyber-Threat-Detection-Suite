import re
import pandas as pd
import tldextract

def get_features(url):
    """Extracts features from a URL to match the PhiUSIIL dataset format."""
    features = {
        'URLLength': len(url),
        'NoOfLettersInURL': sum(c.isalpha() for c in url),
        'NoOfDegitsInURL': sum(c.isdigit() for c in url),
        'NoOfOtherSpecialCharsInURL': len(re.findall(r'[^a-zA-Z0-9]', url)),
        'NoOfSubDomain': len(tldextract.extract(url).subdomain.split('.')) if tldextract.extract(url).subdomain else 0,
        'IsHTTPS': 1 if url.startswith('https') else 0
    }
    return pd.DataFrame([features])