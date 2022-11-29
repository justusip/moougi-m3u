import atexit
import json
import re

from selenium import webdriver
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.core.utils import ChromeType


def scrape(sniff_urls: [str]):
    print("Starting Selenium...")

    options = webdriver.ChromeOptions()
    for option in [
        "--headless",
        "--disable-gpu",
        "--window-size=1920,1200",
        "--ignore-certificate-errors",
        "--disable-extensions",
        "--no-sandbox",
        "--disable-dev-shm-usage"]:
        options.add_argument(option)

    caps = DesiredCapabilities().CHROME
    caps['goog:loggingPrefs'] = {'performance': 'ALL'}

    options.add_experimental_option('perfLoggingPrefs', {
        'traceCategories': "devtools.timeline",
        'enableNetwork': True
    })

    # caps["pageLoadStrategy"] = "eager"
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager(chrome_type=ChromeType.CHROMIUM).install()),
        options=options,
        desired_capabilities=caps
    )
    atexit.register(driver.quit)
    # driver.maximize_window()

    results = {}

    for sniff_url in sniff_urls:
        print(f"Sniffing {sniff_url}...")
        driver.get(sniff_url)

        def process_browser_log_entry(entry):
            response = json.loads(entry['message'])['message']
            return response

        browser_log = driver.get_log('performance')
        events = [process_browser_log_entry(entry) for entry in browser_log]
        with open("test.json", "w") as f:
            f.write(json.dumps(events, indent=4))

        for event in events:
            if event["method"] != "Tracing.dataCollected":
                continue
            if event["params"]["name"] != "ResourceSendRequest":
                continue
            url = event["params"]["args"]["data"]["url"]
            if re.match(r"http.*\.(m3u8|flv).*", url):
                if url == "https://www.google.com/video/playlist.m3u8":
                    continue
                results[sniff_url] = url
                print(f"Sniffed {sniff_url} -> {url}")
                break
        else:
            results[sniff_url] = None
        return results


def sniff():
    with open("def.json") as f:
        defs = json.load(f)
    sniffed_urls = scrape(defs)
    with open("sniff.json", "w") as f:
        json.dump(sniffed_urls, f, indent=4)


if __name__ == "__main__":
    sniff()
