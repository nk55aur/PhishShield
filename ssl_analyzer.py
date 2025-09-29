import ssl
import socket
from urllib.parse import urlparse

class SSLAnalyzer:
    def analyze_ssl_certificate(self, url):
        """Check SSL certificate with better error handling"""
        features = {'has_ssl': False, 'ssl_valid': False}
        
        try:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((parsed.netloc, 443), timeout=8) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                        cert = ssock.getpeercert()
                        features['has_ssl'] = True
                        features['ssl_valid'] = True
                        print("   ✅ Valid SSL certificate found")
            else:
                print("   ⚠️  No HTTPS - using insecure HTTP connection")
        except Exception as e:
            if url.startswith('https://'):
                print("   ❌ SSL certificate error or HTTPS not properly configured")
        
        return features