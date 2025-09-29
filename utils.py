def display_list_results(result):
    """Display list-based analysis results"""
    status = result['status']
    if status == 'phishing':
        print(f"🔴 Status: PHISHING (Confidence: {result['confidence']}%)")
    elif status == 'legitimate':
        print(f"🟢 Status: LEGITIMATE (Confidence: {result['confidence']}%)")
    else:
        print(f"🟡 Status: UNKNOWN (Confidence: {result['confidence']}%)")
    print(f"📝 Reason: {result['reason']}")

def display_rule_results(result, url):
    """Display rule-based analysis results"""
    risk_score = result['risk_score']
    features = result['features']
    
    print(f"📊 Risk Score: {risk_score:.1f}%")
    print("\n🔍 Detailed Feature Analysis:")
    
    # Show CRITICAL risk indicators first
    critical_risk = False
    
    if features.get('exact_brand_phishing'):
        print("   🚨 CRITICAL: EXACT BRAND PHISHING - Domain uses brand name for phishing")
        critical_risk = True
        
    if features.get('domain_unreachable'):
        print("   🚨 DOMAIN UNREACHABLE - Website does not exist")
        critical_risk = True
        
    if features.get('url_shortener'):
        print("   🚨 URL SHORTENER - Often used to hide phishing links")
        critical_risk = True
        
    if features.get('brand_impersonation'):
        print("   🚨 BRAND IMPERSONATION - Domain mimics well-known brand")
        critical_risk = True
        
    if features.get('typosquatting_risk'):
        print("   🚨 TYPOSQUATTING - Possible misspelled brand name")
        critical_risk = True
        
    if features.get('suspicious_pattern'):
        print("   🚨 SUSPICIOUS PATTERN - Uses common phishing terms")
        critical_risk = True
        
    # Show other indicators
    if features.get('no_https'):
        print("   ⚠️  NO HTTPS - No secure connection")
        
    if features.get('domain_age_risk'):
        print("   ⚠️  NEW DOMAIN - Recently created (high risk)")
        
    if features.get('brand_in_subdomain'):
        print("   ⚠️  BRAND IN SUBDOMAIN - Common phishing tactic")
        
    if features.get('suspicious_tld'):
        print("   ⚠️  SUSPICIOUS TLD - Uses high-risk domain extension")
        
    if features.get('has_ip'):
        print("   ⚠️  USES IP ADDRESS - Direct IP instead of domain name")
        
    if features.get('has_encoding'):
        print("   ⚠️  URL ENCODING - Possible attempt to hide malicious content")
        
    if features.get('mixed_case'):
        print("   ⚠️  MIXED CASE - Suspicious capitalization patterns")
        
    # Show positive indicators
    if features.get('domain_reachable'):
        print("   ✅ DOMAIN REACHABLE - Website is accessible")
        
    if features.get('has_ssl'):
        print("   ✅ HTTPS - Secure connection enabled")
        
    if features.get('ssl_valid'):
        print("   ✅ VALID SSL - Certificate is properly configured")
        
    if features.get('official_domain'):
        print("   ✅ OFFICIAL DOMAIN - Verified legitimate website")

    # Show appropriate final message
    if critical_risk:
        print("   🚨 MULTIPLE PHISHING INDICATORS DETECTED")
    elif features.get('domain_reachable') and features.get('official_domain'):
        print("   ✅ No concerning features detected - Verified legitimate")
    elif features.get('domain_reachable') and not features.get('official_domain'):
        print("   ⚠️  Website accessible but not verified as official")
    else:
        print("   🔍 No major concerning features detected")

def display_final_results(result, url):
    """Display final results and recommendations"""
    risk_score = result['risk_score']
    status = result['status']
    
    print(f"🎯 FINAL RISK SCORE: {risk_score:.1f}%")
    print(f"📋 STATUS: {status.upper()}")
    
    print(f"\n{'='*60}")
    print("🔍 SECURITY RECOMMENDATIONS")
    print(f"{'='*60}")
    
    if risk_score >= 70:
        print("""
🚨 CRITICAL WARNING - HIGH RISK PHISHING WEBSITE 🚨

IMMEDIATE ACTIONS REQUIRED:
❌ DO NOT enter any personal information
❌ DO NOT download any files
❌ DO NOT provide passwords or financial details
✅ Close this website immediately
✅ Report to your IT department
✅ Use official company websites directly

REASONS FOR HIGH RISK:
• Domain impersonates well-known brand
• Uses suspicious patterns common in phishing
• No secure HTTPS connection
• New or unreachable domain
        """)
    elif risk_score >= 50:
        print("""
⚠️  HIGH SUSPICION - LIKELY PHISHING WEBSITE

STRONG CAUTION ADVISED:
• Avoid entering any sensitive information
• Verify through official channels
• Use alternative, trusted websites
• Check for valid SSL certificate

SUSPICIOUS INDICATORS:
• Brand impersonation detected
• Suspicious domain patterns
• Security issues found
        """)
    elif risk_score >= 30:
        print("""
🔍 SUSPICIOUS WEBSITE - EXERCISE CAUTION

RECOMMENDATIONS:
• Be cautious with personal information
• Verify website authenticity
• Look for trust indicators
• Use strong passwords if logging in
        """)
    else:
        print("""
✅ LIKELY LEGITIMATE WEBSITE

STANDARD SECURITY PRACTICES:
• Website appears safe but maintain normal caution
• Verify SSL certificate details
• Check for official contact information
• Use strong, unique passwords
        """)