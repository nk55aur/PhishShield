import re
import whois # type: ignore
from urllib.parse import urlparse
from datetime import datetime

class URLAnalyzer:
    def __init__(self, brand_names, suspicious_tlds, official_domains):
        self.brand_names = brand_names
        self.suspicious_tlds = suspicious_tlds
        self.official_domains = official_domains

    def analyze_url_features(self, url):
        """Enhanced URL structure analysis for phishing indicators"""
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            domain_no_tld = '.'.join(domain.split('.')[:-1])  # Remove TLD
            
            # Basic URL analysis
            features['long_url'] = len(url) > 75
            features['has_ip'] = bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc))
            features['is_shortened'] = self.check_url_shortener(domain)
            features['has_at_symbol'] = '@' in url
            features['has_dash'] = '-' in domain
            features['multiple_subdomains'] = len(domain.split('.')) > 3
            features['suspicious_tld'] = any(domain.endswith(tld) for tld in self.suspicious_tlds)
            features['no_https'] = parsed.scheme != 'https'
            features['mixed_case'] = any(c.isupper() for c in url) and any(c.islower() for c in url)
            features['has_encoding'] = '%' in url  # URL encoding
            
            # ENHANCED: Advanced phishing detection
            features['exact_brand_phishing'] = self.check_exact_brand_phishing(domain)
            features['brand_impersonation'] = self.check_brand_impersonation(domain)
            features['typosquatting_risk'] = self.check_typosquatting(domain)
            features['suspicious_pattern'] = self.check_suspicious_patterns(domain)
            features['brand_in_subdomain'] = self.check_brand_in_subdomain(domain)
            features['domain_age_risk'] = self.check_domain_age(domain)
            features['official_domain'] = self.check_official_domain(domain)
            features['url_shortener'] = self.check_url_shortener(domain)
            
            return features
            
        except Exception as e:
            print(f"   Error in URL analysis: {e}")
            return {}

    def check_url_shortener(self, domain):
        """Check if domain is a URL shortener"""
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
        return any(shortener in domain for shortener in shorteners)

    def check_exact_brand_phishing(self, domain):
        """Check for exact brand names in phishing domains"""
        domain_no_tld = '.'.join(domain.split('.')[:-1])
        
        for brand in self.brand_names:
            # If domain contains exact brand name but is not the official domain
            if brand in domain_no_tld and not self.is_official_domain(domain, brand):
                # Check for common phishing prefixes/suffixes
                phishing_terms = ['secure', 'verify', 'update', 'login', 'account', 
                                'security', 'confirm', 'validation', 'authenticate',
                                'support', 'help', 'service', 'billing', 'payment']
                for term in phishing_terms:
                    if term in domain_no_tld:
                        return True
                # If brand is the main part of the domain, still high risk
                if brand == domain_no_tld or f"{brand}-" in domain_no_tld or f"-{brand}" in domain_no_tld:
                    return True
        return False

    def check_official_domain(self, domain):
        """Check if domain is official"""
        for brand, official_domains in self.official_domains.items():
            for official_domain in official_domains:
                if domain == official_domain or domain.endswith('.' + official_domain):
                    return True
        return False

    def is_official_domain(self, domain, brand):
        """Check if domain is official for a specific brand"""
        if brand in self.official_domains:
            return any(official_domain in domain for official_domain in self.official_domains[brand])
        return False

    def check_brand_impersonation(self, domain):
        """Enhanced brand impersonation detection"""
        domain_lower = domain.lower()
        
        for brand in self.brand_names:
            if brand in domain_lower:
                # Check if it's NOT the official domain
                if not self.is_official_domain(domain_lower, brand):
                    return True
        return False

    def check_typosquatting(self, domain):
        """Enhanced typosquatting detection with number substitutions"""
        domain_no_tld = '.'.join(domain.split('.')[:-1])
        
        # Common typos - EXPANDED LIST with number substitutions
        typos = {
            'google': ['googie', 'goggle', 'gooogle', 'googlee', 'g00gle', 'googIe', 'g0ogle', '9oogle'],
            'youtube': ['y0utube', 'youtub', 'youtibe', 'youtubee', 'y0utub3', 'youtubbe', 'youtub3', 'y0utube'],
            'apple': ['aplle', 'appel', 'aple', 'appie', 'app1e', 'aple', 'appl3', '4pple'],
            'microsoft': ['microsft', 'mircosoft', 'micr0soft', 'microsoftt', 'm1crosoft', 'm1cr0s0ft'],
            'paypal': ['paypai', 'palpay', 'paypa1', 'paypai', 'payypal', 'paypa1', 'p4ypal'],
            'amazon': ['amaz0n', 'amazn', 'amazonn', 'amazoon', 'amaz0n', '4mazon'],
            'facebook': ['faceb00k', 'facebok', 'facebookk', 'facebooks', 'facedook', 'f4cebook'],
            'twitter': ['tw1tter', 'twiter', 'twitterr', 'twiiter', 'tw1tter', 'tw1tt3r'],
            'instagram': ['instagran', 'instagran', 'instagran', 'instgram', '1nstagram'],
            'whatsapp': ['whatsap', 'whatsappp', 'whatsapp', 'whatsapp0', 'whats4pp'],
            'netflix': ['netfl1x', 'netfl1x', 'netfl1x', 'n3tflix'],
            'spotify': ['spot1fy', 'spot1fy', 'sp0tify'],
            'github': ['g1thub', 'g1thub', 'g1thub']
        }
        
        for brand, variations in typos.items():
            for variation in variations:
                # Check if variation exists in domain and brand is not the correct spelling
                if variation in domain_no_tld:
                    # If the correct brand name is NOT in the domain, it's typosquatting
                    if brand not in domain_no_tld:
                        return True
                    # Special case: if both variation and brand are present, but it's still suspicious
                    elif variation != brand:
                        return True
        
        # Additional check for number substitutions
        number_subs = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '4', 
            's': '5', 't': '7', 'b': '8', 'g': '9'
        }
        
        for brand in self.brand_names:
            if len(brand) > 3:  # Only check meaningful brand names
                # Generate possible number-substituted versions
                possible_typos = []
                for i, char in enumerate(brand):
                    if char in number_subs:
                        typo = brand[:i] + number_subs[char] + brand[i+1:]
                        possible_typos.append(typo)
                
                # Check if any number-substituted version matches the domain
                for typo in possible_typos:
                    if typo in domain_no_tld and brand not in domain_no_tld:
                        return True
        
        return False

    def check_suspicious_patterns(self, domain):
        """Enhanced suspicious pattern detection"""
        patterns = [
            'update-', 'verify-', 'security-', 'login-', 'account-',
            'secure-', 'confirm-', 'validation-', 'authenticate-',
            'support-', 'help-', 'service-', 'billing-', 'payment-',
            '-update', '-verify', '-security', '-login', '-account',
            'secure.', 'verify.', 'login.', 'account.', 'security.'
        ]
        
        return any(pattern in domain for pattern in patterns)

    def check_brand_in_subdomain(self, domain):
        """Check if brand appears in subdomain"""
        parts = domain.split('.')
        if len(parts) > 2:
            for part in parts[:-2]:  # Exclude main domain and TLD
                if any(brand in part.lower() for brand in self.brand_names):
                    return True
        return False

    def check_domain_age(self, domain):
        """Check if domain is new (high risk)"""
        try:
            info = whois.whois(domain)
            if info.creation_date:
                if isinstance(info.creation_date, list):
                    create_date = info.creation_date[0]
                else:
                    create_date = info.creation_date
                
                age_days = (datetime.now() - create_date).days
                return age_days < 30  # High risk if less than 30 days old
        except:
            pass
        return False  # Return False if we can't check or domain is old

    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return url.lower()