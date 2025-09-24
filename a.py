import re
from bs4 import BeautifulSoup
import requests
import requests.exceptions as request_exception


def extract_emails(response_text: str) -> set[str]:
    """
    Extracts all email addresses from the provided HTML text.

    :param response_text: The raw HTML content of a webpage.
    :return: A set of email addresses found within the content.
    """
    email_pattern = r'[a-z0-9\.\-+]+@[a-z0-9\.\-+]+\.[a-z]+'
    return set(re.findall(email_pattern, response_text, re.I))


def scrape_page(url: str) -> set[str]:
    """
    Scrapes a single webpage to collect email addresses.

    :param url: The URL of the page to scrape.
    :return: A set of email addresses found on the page.
    """
    try:
        print(f'Processing {url}')
        response = requests.get(url)
        response.raise_for_status()
    except (request_exception.RequestException, request_exception.MissingSchema, request_exception.ConnectionError):
        print('There was a request error')
        return set()

    emails = extract_emails(response.text)
    return emails


try:
    user_url = input('[+] Enter URL to scan: ')
    emails = scrape_page(user_url)

    # Display collected emails
    if emails:
        print('\n[+] Found emails:')
        for email in emails:
            print(email)
    else:
        print('[-] No emails found.')
except KeyboardInterrupt:
    print('[-] Closing!')
