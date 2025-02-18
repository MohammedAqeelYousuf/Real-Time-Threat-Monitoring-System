import requests
import ssl
import socket
import csv
import os
import re
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from pymongo import MongoClient


def is_https(url):
    """Check if the URL uses HTTPS."""
    return url.startswith('https://')


def is_ssl_certificate_valid(url):
    """Check if the SSL certificate of the URL is valid."""
    try:
        parsed_url = requests.utils.urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
        return True
    except Exception as e:
        print(f"SSL certificate validation failed: {e}")
        return False


def scrape_nciipc():
    """Scrape data from NCIIPC website."""
    url = "https://nciipc.gov.in/alerts_advisories_more_2023.html"
    options = Options()
    options.headless = True
    driver = webdriver.Firefox(options=options)

    driver.get(url)
    WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.CLASS_NAME, "liList")))

    vulnerability_elements = driver.find_elements(By.CLASS_NAME, "liList")
    vulnerabilities = []

    for elem in vulnerability_elements:
        cwe_name = elem.find_element(By.TAG_NAME, "b").text
        summary = elem.find_element(By.CLASS_NAME, "advisoryFont").text.strip()

        vulnerability = {
            "cwe_name": cwe_name,
            "summary": summary
        }
        vulnerabilities.append(vulnerability)

    csv_path = os.path.expanduser("~/Desktop/FinalProject/new_data.csv")
    with open(csv_path, mode='w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ["cwe_name", "summary"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(vulnerabilities)

    print("NCIIPC scraping completed and data saved to new_data.csv")
    driver.quit()


def scrape_cyware():
    """Scrape data from Cyware website."""
    url = "https://cyware.com/search?search=india"
    driver = webdriver.Firefox()
    driver.get(url)
    time.sleep(2)

    articles = driver.find_elements(By.CSS_SELECTOR, ".cy-panel.cy-card.mb-4")
    news_data = []

    for article in articles:
        cwe_name = article.find_element(By.CLASS_NAME, "cy-card__title").text.strip() if article.find_elements(
            By.CLASS_NAME, "cy-card__title") else None
        summary = article.find_element(By.CLASS_NAME, "cy-card__summary").text.strip() if article.find_elements(
            By.CLASS_NAME, "cy-card__summary") else None

        news_item = {
            "cwe_name": cwe_name,
            "summary": summary
        }
        news_data.append(news_item)

    csv_path = os.path.expanduser("~/Desktop/FinalProject/new_data.csv")
    with open(csv_path, mode='w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ["cwe_name", "summary"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(news_data)

    print("Cyware scraping completed and data saved to new_data.csv")
    driver.quit()


def main():
    url = input("Enter the URL to scrape: ").strip()

    if not is_https(url):
        print("URL does not use HTTPS.")
    elif not is_ssl_certificate_valid(url):
        print("SSL certificate is not valid.")
    else:
        if "nciipc.gov.in" in url:
            scrape_nciipc()
        elif "cyware.com" in url:
            scrape_cyware()
        else:
            print("Unsupported URL.")


if __name__ == "__main__":
    main()
