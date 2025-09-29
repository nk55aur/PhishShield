import requests

class ContentAnalyzer:
    def __init__(self, brand_names):
        self.brand_names = brand_names

    def analyze_content_features(self, url):
        """Analyze website content with better error handling"""
        features = {
            'domain_unreachable': False,
            'domain_reachable': False,
            'has_login_form': False,
            'suspicious_keywords': 0
        }
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=True)
            
            features['domain_reachable'] = True
            features['domain_unreachable'] = False
            
            content = response.text.lower()
            
            # Enhanced content analysis
            features['has_login_form'] = '<form' in content and ('password' in content or 'login' in content)
            features['suspicious_keywords'] = sum(1 for brand in self.brand_names if brand in content)
            
            print(f"   ✅ Website is reachable (Status: {response.status_code})")
            
        except requests.exceptions.ConnectionError:
            features['domain_unreachable'] = True
            features['domain_reachable'] = False
            print("   🚨 Domain is unreachable - HIGH RISK INDICATOR")
        except requests.exceptions.Timeout:
            features['domain_unreachable'] = True
            features['domain_reachable'] = False
            print("   ⚠️  Connection timeout - website may be slow or blocking requests")
        except Exception as e:
            features['domain_unreachable'] = True
            features['domain_reachable'] = False
            print(f"   ⚠️  Connection failed: {str(e)[:50]}...")
            
        return features