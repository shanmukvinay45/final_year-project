import re
import ipaddress
import urllib.request
import requests
from bs4 import BeautifulSoup
from datetime import date
import socket
import numpy as np
import whois
from urllib.parse import urlparse

def using_ip(url):
    try:
        domain = urlparse(url).netloc
        ipaddress.ip_address(domain)
        return -1
    except:
        return 1

def long_url(url):
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1

def short_url(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
    if match:
        return -1
    return 1

def symbol(url):
    if re.findall("@", url):
        return -1
    return 1

def redirecting(url):
    if url.rfind('//') > 6:
        return -1
    return 1

def prefix_suffix(domain):
    try:
        match = re.findall('\-', domain)
        if match:
            return -1
        return 1
    except:
        return -1

def sub_domains(url):
    domain = urlparse(url).netloc
    dot_count = len(re.findall("\.", domain))
    if dot_count == 1:
        return 1
    elif dot_count == 2:
        return 0
    return -1

def https(url):
    try:
        if re.match(r"^https://", url):
            return 1
        return -1
    except:
        return 1

def domain_reg_len(whois_response):
    try:
        expiration_date = whois_response.expiration_date
        creation_date = whois_response.creation_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if expiration_date and creation_date:
            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            if age >= 12:
                return 1
        return -1
    except:
        return -1

def favicon(soup, url, domain):
    try:
        for head in soup.find_all('head'):
            for link in head.find_all('link', href=True):
                if 'icon' in link.get('rel', []):
                    dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                    if url in link['href'] or len(dots) == 1 or domain in link['href']:
                        return 1
        return -1
    except:
        return -1

def non_std_port(domain):
    try:
        port = domain.split(":")
        if len(port) > 1:
            return -1
        return 1
    except:
        return -1

def https_domain_url(domain):
    try:
        if 'https' in domain:
            return -1
        return 1
    except:
        return -1

def request_url(soup, url, domain):
    try:
        i, success = 0, 0
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or domain in img['src'] or len(dots) == 1:
                success += 1
            i += 1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                success += 1
            i += 1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                success += 1
            i += 1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                success += 1
            i += 1

        if i == 0:
            return 1
        
        percentage = success / float(i) * 100
        if percentage < 22.0:
            return 1
        elif 22.0 <= percentage < 61.0:
            return 0
        else:
            return -1
    except:
        return -1

def anchor_url(soup, url, domain):
    try:
        i, unsafe = 0, 0
        for a in soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe += 1
            i += 1

        if i == 0:
            return 1
        
        percentage = unsafe / float(i) * 100
        if percentage < 31.0:
            return 1
        elif 31.0 <= percentage < 67.0:
            return 0
        else:
            return -1
    except:
        return -1

def links_in_script_tags(soup, url, domain):
    try:
        i, success = 0, 0
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success += 1
            i += 1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domain in script['src'] or len(dots) == 1:
                success += 1
            i += 1

        if i == 0:
            return 1
        
        percentage = success / float(i) * 100
        if percentage < 17.0:
            return 1
        elif 17.0 <= percentage < 81.0:
            return 0
        else:
            return -1
    except:
        return -1

def server_form_handler(soup, url, domain):
    try:
        if len(soup.find_all('form', action=True)) == 0:
            return 1
        else:
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif url not in form['action'] and domain not in form['action']:
                    return 0
                else:
                    return 1
    except:
        return -1

def info_email(soup):
    try:
        if re.findall(r"[mail\(\)|mailto:?]", str(soup)):
            return -1
        else:
            return 1
    except:
        return -1

def abnormal_url(response_url, domain):
    try:
        if domain in response_url:
            return 1
        else:
            return -1
    except:
        return -1

def website_forwarding(response_history):
    try:
        if len(response_history) <= 1:
            return 1
        elif len(response_history) <= 4:
            return 0
        else:
            return -1
    except:
        return -1

def status_bar_cust(response_text):
    try:
        if re.findall("<script>.+onmouseover.+</script>", response_text):
            return 1
        else:
            return -1
    except:
        return -1

def disable_right_click(response_text):
    try:
        if re.findall(r"event.button ?== ?2", response_text):
            return 1
        else:
            return -1
    except:
        return -1

def using_popup_window(response_text):
    try:
        if re.findall(r"alert\(", response_text):
            return 1
        else:
            return -1
    except:
        return -1

def iframe_redirection(response_text):
    try:
        if re.findall(r"[<iframe>|<frameBorder>]", response_text):
            return 1
        else:
            return -1
    except:
        return -1

def age_of_domain(whois_response):
    try:
        creation_date = whois_response.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        today = date.today()
        if creation_date:
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            if age >= 6:
                return 1
        return -1
    except:
        return -1

def dns_recording(whois_response):
    try:
        return age_of_domain(whois_response)
    except:
        return -1

def website_traffic(url):
    return 0

def page_rank(domain):
    return 0

def google_index(url):
    return 0

def links_pointing_to_page(response_text):
    try:
        number_of_links = len(re.findall(r"<a href=", response_text))
        if number_of_links == 0:
            return 1
        elif number_of_links <= 2:
            return 0
        else:
            return -1
    except:
        return -1

def stats_report(url, domain):
    try:
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        try:
            ip_address = socket.gethostbyname(domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except:
            return 1
    except:
        return 1

def get_features_list(url):
    try:
        domain = urlparse(url).netloc
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        whois_response = whois.whois(domain)
        features = [
            using_ip(url),
            long_url(url),
            short_url(url),
            symbol(url),
            redirecting(url),
            prefix_suffix(domain),
            sub_domains(url),
            https(url),
            domain_reg_len(whois_response),
            favicon(soup, url, domain),
            non_std_port(domain),
            https_domain_url(domain),
            request_url(soup, url, domain),
            anchor_url(soup, url, domain),
            links_in_script_tags(soup, url, domain),
            server_form_handler(soup, url, domain),
            info_email(soup),
            abnormal_url(response.url, domain),
            website_forwarding(response.history),
            status_bar_cust(response.text),
            disable_right_click(response.text),
            using_popup_window(response.text),
            iframe_redirection(response.text),
            age_of_domain(whois_response),
            dns_recording(whois_response),
            website_traffic(url),
            page_rank(domain),
            google_index(url),
            links_pointing_to_page(response.text),
            stats_report(url, domain)
        ]
        return features
    except Exception as e:
        return [-1] * 30

def get_features_array(url):
    features_list = get_features_list(url)
    features_array = np.array(features_list)
    return features_array

if __name__ == "__main__":
    url = "https://example.com"
    try:
        features_array = get_features_array(url)
        print(features_array)
    except Exception as e:
        print(f"An error occurred: {str(e)}")