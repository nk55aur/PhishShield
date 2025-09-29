from detector import PhishingDetector

def main():
    print("🛡️  COMPREHENSIVE PHISHING WEBSITE DETECTOR")
    print("="*50)
    print("This tool analyzes websites using:")
    print("• List-based detection (Blacklists/Whitelists)")
    print("• Rule-based analysis (URL structure & content)")
    print("• Advanced pattern recognition")
    print("="*50)
    
    detector = PhishingDetector()
    
    # Comprehensive test domains from your list
    test_scenarios = {
        "1. Basic Phishing Test": [
            "http://update-appleid.com",
            "http://googIe-security-check.com", 
            "https://www.google.com"
        ],
        "2. Typosquatting Test": [
            "http://paypa1.com",
            "http://g00gle.com",
            "http://faceb00k.com",
            "https://www.paypal.com"
        ],
        "3. Mixed Test Batch": [
            "http://secure-login.tk",
            "https://www.github.com", 
            "http://apple-verify.net",
            "https://www.microsoft.com"
        ],
        "4. High-Risk Phishing Patterns": [
            "http://secure-paypal.com",
            "http://apple-verify.net",
            "http://microsoft-account-update.com"
        ],
        "5. Legitimate Websites": [
            "https://www.google.com",
            "https://www.paypal.com",
            "https://www.github.com"
        ]
    }
    
    while True:
        print(f"\nChoose an option:")
        print("1. Enter custom URL")
        print("2. Run Basic Phishing Test")
        print("3. Run Typosquatting Test") 
        print("4. Run Mixed Test Batch")
        print("5. Run High-Risk Phishing Test")
        print("6. Test Legitimate Websites")
        print("7. Exit")
        
        choice = input("\nEnter choice (1-7): ").strip()
        
        if choice == '1':
            url = input("Enter URL to analyze: ").strip()
            detector.analyze_url(url)
            
        elif choice in ['2', '3', '4', '5', '6']:
            scenario_key = list(test_scenarios.keys())[int(choice) - 2]
            print(f"\n{scenario_key}")
            print("=" * 40)
            for url in test_scenarios[scenario_key]:
                detector.analyze_url(url)
                
        elif choice == '7':
            print("Thank you for using Phishing Detector! Stay safe! 👋")
            break
            
        else:
            print("Invalid choice. Please enter 1-7.")

if __name__ == "__main__":
    main()