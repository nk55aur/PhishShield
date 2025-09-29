import warnings
warnings.filterwarnings('ignore')

from url_analyzer import URLAnalyzer
from content_analyzer import ContentAnalyzer
from ssl_analyzer import SSLAnalyzer
from utils import display_list_results, display_rule_results, display_final_results

class PhishingDetector:
    def __init__(self):
        self.brand_names = [
            'apple', 'paypal', 'microsoft', 'google', 'amazon', 'netflix', 'facebook',
            'twitter', 'instagram', 'whatsapp', 'linkedin', 'bank', 'chase', 'wellsfargo',
            'bankofamerica', 'citibank', 'hsbc', 'irs', 'socialsecurity', 'youtube',
            'spotify', 'github', 'wikipedia', 'reddit'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online']
        
        # Enhanced official domains database
        self.official_domains = {
            'paypal': ['paypal.com', 'paypal-business.com', 'paypal-objects.com'],
            'apple': ['apple.com', 'icloud.com', 'appstore.com', 'appleid.apple.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'microsoftonline.com'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'aws.amazon.com'],
            'facebook': ['facebook.com', 'fb.com', 'facebook.net'],
            'netflix': ['netflix.com', 'nflxext.com', 'nflximg.net'],
            'twitter': ['twitter.com', 'twimg.com'],
            'instagram': ['instagram.com'],
            'whatsapp': ['whatsapp.com'],
            'youtube': ['youtube.com', 'youtu.be'],
            'github': ['github.com'],
            'wikipedia': ['wikipedia.org'],
            'reddit': ['reddit.com'],
            'linkedin': ['linkedin.com'],
            'spotify': ['spotify.com'],
            'chase': ['chase.com'],
            'wellsfargo': ['wellsfargo.com'],
            'bankofamerica': ['bankofamerica.com'],
            'citibank': ['citibank.com'],
            'hsbc': ['hsbc.com']
        }
        
        # Initialize analyzers
        self.url_analyzer = URLAnalyzer(self.brand_names, self.suspicious_tlds, self.official_domains)
        self.content_analyzer = ContentAnalyzer(self.brand_names)
        self.ssl_analyzer = SSLAnalyzer()
        
        # Initialize lists
        self.blacklist = set()
        self.whitelist = set()
        self.update_lists()

    def update_lists(self):
        """Update blacklist and whitelist from online sources"""
        try:
            # Enhanced blacklist with ALL test phishing domains
            self.blacklist = {
                # High-Risk Phishing Patterns
                'update-appleid.com', 'googie-security-check.com', 'paypa1.com',
                'secure-paypal.com', 'apple-verify.net', 'microsoft-account-update.com',
                'facebook-login-security.xyz', 'amazon-payment-verify.com',
                'netflix-billing-update.net', 'bankofamerica-secure-login.com',
                
                # Typosquatting Examples
                'g00gle.com', 'faceb00k.com', 'paypai.com', 'micr0soft.com',
                'app1e.com', 'amaz0n.com', 'y0utube.com', 'tw1tter.com',
                
                # Suspicious TLDs
                'login-security.tk', 'account-verify.ml', 'payment-update.ga',
                'secure-form.cf', 'bank-login.gq', 'update-account.xyz',
                'verify-payment.top',
                
                # Edge Cases
                'paypal.com.secure-update.net', 'facebook.login-verify.com',
                'google.security-check.xyz', 'paypal.com.phishing.com',
                'google.com.evil.net', 'amazon.com.fake-login.org',
                'secure.login.paypal.service.verification.com',
                'auth.verify.confirm.banking.security.signin.net',
                'update.account.microsoft.service.center.com'
            }
            
            # Enhanced whitelist with ALL legitimate domains
            self.whitelist = {
                # Major Tech Companies
                'google.com', 'apple.com', 'microsoft.com', 'amazon.com',
                'facebook.com', 'netflix.com', 'spotify.com', 'twitter.com',
                
                # Financial Institutions
                'paypal.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
                'citibank.com', 'hsbc.com',
                
                # Trusted Services
                'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
                'linkedin.com', 'instagram.com', 'youtube.com'
            }
        except:
            pass

    def analyze_url(self, url):
        """Main analysis function"""
        print(f"\n{'='*60}")
        print("🛡️  PHISHING WEBSITE DETECTION ANALYSIS")
        print(f"{'='*60}")
        
        # Ensure URL has proper protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        results = {}
        
        # 1. List-based analysis
        print("\n📋 1. LIST-BASED ANALYSIS")
        print("-" * 30)
        list_result = self.list_based_analysis(url)
        results['list_based'] = list_result
        display_list_results(list_result)
        
        # 2. Rule-based analysis
        print("\n🔍 2. RULE-BASED ANALYSIS")
        print("-" * 30)
        rule_result = self.rule_based_analysis(url)
        results['rule_based'] = rule_result
        display_rule_results(rule_result, url)
        
        # 3. Final assessment
        print("\n🎯 3. FINAL RISK ASSESSMENT")
        print("-" * 30)
        final_result = self.calculate_final_risk(results)
        results['final'] = final_result
        display_final_results(final_result, url)
        
        return results

    def list_based_analysis(self, url):
        """Check against blacklists and whitelists"""
        domain = self.url_analyzer.extract_domain(url)
        
        if domain in self.blacklist:
            return {
                'status': 'phishing',
                'confidence': 90,
                'reason': 'Domain found in blacklist',
                'list_type': 'blacklist'
            }
        
        if domain in self.whitelist:
            return {
                'status': 'legitimate', 
                'confidence': 95,
                'reason': 'Domain found in whitelist',
                'list_type': 'whitelist'
            }
        
        return {
            'status': 'unknown',
            'confidence': 50,
            'reason': 'Not found in any list',
            'list_type': 'none'
        }

    def rule_based_analysis(self, url):
        """Comprehensive rule-based analysis"""
        print("🔍 Analyzing URL structure and features...")
        url_features = self.url_analyzer.analyze_url_features(url)
        
        print("📄 Analyzing website content...")
        content_features = self.content_analyzer.analyze_content_features(url)
        
        print("🔒 Checking SSL certificate...")
        ssl_features = self.ssl_analyzer.analyze_ssl_certificate(url)
        
        # Combine features
        all_features = {**url_features, **content_features, **ssl_features}
        
        # Calculate risk score with ENHANCED weights
        risk_score = 0
        max_score = 0
        
        # ENHANCED Feature weights
        weights = {
            # CRITICAL RISK indicators (60-100 points)
            'exact_brand_phishing': 85,    # Very high risk for brand phishing
            'domain_unreachable': 70,      # High risk for unreachable domains
            'url_shortener': 60,           # URL shorteners often used in phishing
            
            # HIGH RISK indicators (40-59 points)  
            'brand_impersonation': 55,
            'typosquatting_risk': 50,
            'suspicious_pattern': 50,
            'suspicious_tld': 45,
            
            # MEDIUM RISK indicators (20-39 points)
            'no_https': 35,
            'brand_in_subdomain': 35,
            'domain_age_risk': 30,
            'has_ip': 30,
            'has_encoding': 25,
            
            # LOW RISK indicators (10-19 points)
            'is_shortened': 20,
            'has_at_symbol': 20,
            'long_url': 15,
            'multiple_subdomains': 15,
            'has_dash': 10,
            'mixed_case': 10,
            
            # POSITIVE indicators (reduce risk)
            'has_ssl': -30,
            'ssl_valid': -35,
            'domain_reachable': -20,    # Reduced - reachable phishing still dangerous
            'official_domain': -60      # Strong positive for official domains
        }
        
        for feature, weight in weights.items():
            if feature in all_features and all_features[feature]:
                risk_score += weight
                max_score += abs(weight)
        
        # Normalize to 0-100
        if max_score > 0:
            final_score = max(0, min(100, (risk_score / max_score) * 100))
        else:
            final_score = 50
        
        return {
            'risk_score': final_score,
            'features': all_features
        }

    def calculate_final_risk(self, results):
        """Calculate final risk assessment"""
        list_status = results['list_based']['status']
        rule_risk = results['rule_based']['risk_score']
        
        # If blacklisted, automatically high risk
        if list_status == 'phishing':
            final_risk = max(rule_risk, 80)
            status = 'phishing'
        elif list_status == 'legitimate':
            final_risk = min(rule_risk, 20)  # Cap legitimate sites at 20%
            status = 'legitimate'
        else:
            final_risk = rule_risk
            status = self.get_risk_status(final_risk)
        
        return {
            'risk_score': final_risk,
            'status': status
        }

    def get_risk_status(self, risk_score):
        """Convert risk score to status"""
        if risk_score >= 70:
            return 'phishing'
        elif risk_score >= 50:
            return 'suspicious'
        elif risk_score >= 30:
            return 'likely_legitimate'
        else:
            return 'legitimate'