def extract_features(url):
    return {
        'url_length': len(url),
        'has_https': int('https' in url.lower()),
        'count_dots': url.count('.'),
        'count_hyphens': url.count('-'),
        'count_digits': sum(char.isdigit() for char in url),
        'has_suspicious_word': int(any(word in url.lower() for word in ['login', 'verify', 'secure', 'bvn', 'update', 'free', 'alert'])),
        'ends_with_com': int(url.lower().endswith('.com')),
    }
