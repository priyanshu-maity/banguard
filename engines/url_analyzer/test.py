from url_analyzer import URLAnalyzer


test_urls = [
    'http://testsafebrowsing.appspot.com/s/malware.html',
    'http://btcmx.net/NDM3MmI3N2Q3OWVkNDgxZHY0Q1VLb1NwcUJEN3NtVy9QeVU2emR6REppWFJxYVdQdDkrZ0NpYXlReUVzeUt5Nmp6N1ZOeHlSRXEySEJmTmE',
    # # Normal websites
    # 'https://google.com',
    #
    # # Embedded credentials
    # 'https://admin:password@example.com',
    #
    # # IP addresses
    # 'http://8.8.8.8',
    # 'http://[2001:4860:4860::8888]',
    #
    # # Excessive hyphens
    # 'https://secure-account-verification-login.com',
    #
    # # Excessive subdomains
    # 'https://login.account.verify.security.example.com',
    #
    # # Typosquatting
    # 'https://paypa1.com',
    #
    # # Punycode and homograph
    # 'https://xn--80ak6aa92e.com',
    # 'https://раypal.com',
    #
    # # Brand in subdomain
    # 'https://paypal.login.example.org',
    #
    # # Suspicious keywords
    # 'https://example.com/secure/banking/verify-account',
    #
    # # DNS edge cases
    # 'https://nonexistent-domain-837291.invalid',
    #
    # # Redirect chains
    # 'https://httpbin.org/redirect/3',
    #
    # # Cross-domain redirect
    # 'https://httpbin.org/redirect-to?url=https://google.com',
    #
    # # URL shortener
    # 'https://bit.ly/3example',
    #
    # # SSRF
    # 'http://169.254.169.254',
]

def display_result(result):
    print('\nURL ANALYSIS RESULTS')
    print('=' * 80)

    # for field, value in vars(result).items():
    #     print(f'\n{field.replace("_", " ").title()}')
    #
    #     if isinstance(value, tuple) and len(value) == 2:
    #         detected, evidence = value
    #
    #         if detected is None:
    #             print('  Status: Unavailable')
    #         else:
    #             print(f'  Detected: {"Yes" if detected else "No"}')
    #
    #         if evidence:
    #             if isinstance(evidence, list):
    #                 for item in evidence:
    #                     print(f'  • {item}')
    #             else:
    #                 print(f'  Evidence: {evidence}')
    #         else:
    #             print('  Evidence: None')
    #     else:
    #         print(f'  Value: {value}')
    #
    # print('\n[ THREAT INTELLIGENCE ]')

    print('\nVirusTotal:')
    print(f'  Malicious: {result.virustotal_malicious}')
    print(f'  Suspicious: {result.virustotal_suspicious}')
    print(f'  Harmless engines: {result.virustotal_harmless_count}')
    print(f'  Undetected engines: {result.virustotal_undetected_count}')
    print(f'  Reputation: {result.virustotal_reputation}')
    print(f'  Categories: {result.virustotal_categories}')

    print('\nProvider Status:')
    for provider, status in result.threat_intelligence_provider_status.items():
        print(f'  {provider}: {status}')

    print('\n' + '=' * 80)


def run_tests():
    for url in test_urls:
        print(f'\nTesting URL: {url}')

        try:
            analyzer = URLAnalyzer(url)
            result = analyzer.analyze()

            display_result(result)

        except Exception as error:
            print(f'Analysis failed: {type(error).__name__}: {error}')


if __name__ == '__main__':
    run_tests()