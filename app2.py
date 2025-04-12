import streamlit as st
import pickle
import numpy as np
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
import openai
import os
from dotenv import load_dotenv
import groq
# Load environment variables
load_dotenv()
from langchain_groq import ChatGroq

# Initialize OpenAI client
groq_api_key=os.getenv('GROQ_API_KEY')


llm=ChatGroq(groq_api_key=groq_api_key,
             model_name="Llama3-8b-8192")


# Load the trained model
with open("rf_model.pkl", "rb") as file:
    model = pickle.load(file)

# Feature names
feature_names = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-", 
    "SubDomains", "HTTPS", "DomainRegLen", "Favicon", "NonStdPort", "HTTPSDomainURL", 
    "RequestURL", "AnchorURL", "LinksInScriptTags", "ServerFormHandler", "InfoEmail", 
    "AbnormalURL", "WebsiteForwarding", "StatusBarCust", "DisableRightClick", 
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording", 
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport"
]

# Initialize session state for chat history
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# Phishing Awareness Q&A responses
PHISHING_RESPONSES = {
    "greeting": [
        "Hello! I'm your Phishing Awareness Assistant. How can I help you today?",
        "Hi there! I'm here to help you learn about phishing and cybersecurity. What would you like to know?",
        "Welcome! I'm your cybersecurity guide. Feel free to ask me about phishing and online safety."
    ],
    "what_is_phishing": [
        "Phishing is a cybercrime where attackers try to trick you into giving them sensitive information like passwords, credit card numbers, or personal details. They often do this by pretending to be a trustworthy entity through fake emails, websites, or messages.",
        "Phishing is like digital fishing - cybercriminals 'fish' for your personal information by creating fake websites or emails that look legitimate. They try to lure you into giving away sensitive data like passwords or bank details."
    ],
    "spot_fake_website": [
        "Here are key signs of a fake website:\n1. Check the URL carefully - look for misspellings or unusual domains\n2. Look for HTTPS in the address bar\n3. Check for poor grammar and spelling\n4. Be wary of urgent or threatening messages\n5. Hover over links to see where they actually lead\n6. Check for contact information and physical address\n7. Look for trust indicators like security badges",
        "To spot a fake website:\n- Examine the URL carefully\n- Look for HTTPS security\n- Check for professional design\n- Verify contact information\n- Be cautious of urgent requests\n- Check for spelling errors\n- Verify security certificates"
    ],
    "entered_details": [
        "If you've entered details on a phishing site:\n1. Immediately change your passwords\n2. Contact your bank if financial info was shared\n3. Enable two-factor authentication\n4. Monitor your accounts for suspicious activity\n5. Report the phishing attempt to relevant authorities\n6. Consider freezing your credit if sensitive data was shared",
        "Take these steps if you've entered details on a phishing site:\n- Change passwords immediately\n- Contact financial institutions\n- Enable additional security measures\n- Monitor for unauthorized activity\n- Report the incident"
    ],
    "prevention_tips": [
        "To prevent phishing attacks:\n1. Never click suspicious links\n2. Use strong, unique passwords\n3. Enable two-factor authentication\n4. Keep software updated\n5. Use security software\n6. Verify sender addresses\n7. Don't share sensitive info via email",
        "Stay safe from phishing:\n- Use strong passwords\n- Enable 2FA\n- Keep systems updated\n- Verify senders\n- Use security tools\n- Be cautious with links"
    ],
    "out_of_scope": [
        "I'm specifically trained to help with phishing and cybersecurity questions. Please ask me about topics related to online security, phishing prevention, or how to stay safe online.",
        "I focus on phishing awareness and cybersecurity. Feel free to ask me about:\n- What phishing is\n- How to spot fake websites\n- What to do if you've been phished\n- How to prevent phishing attacks\n- General cybersecurity tips"
    ]
}

def get_llm_response(user_input):
    """Get response from Groq's LLM model using LangChain."""
    try:
        system_prompt = """You are a cybersecurity expert specializing in phishing awareness and prevention. 
        Your role is to provide accurate, helpful, and concise information about phishing and online security.
        Keep your responses focused on cybersecurity topics only. If the question is not related to cybersecurity,
        politely redirect the user to ask about phishing or online security instead.
        
        Guidelines:
        1. Be concise and clear
        2. Use bullet points for lists
        3. Include practical tips
        4. Stay focused on cybersecurity
        5. Be professional but friendly
        6. Use emojis sparingly and appropriately
        7. Keep responses under 200 words
        8. If unsure, stick to basic security principles"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input}
        ]
        
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        st.error(f"Error with LLM: {str(e)}")
        return None

def get_phishing_response(user_input):
    """Get response using either LLM or predefined responses."""
    try:
        llm_response = get_llm_response(user_input)
        if llm_response:
            return llm_response
    except:
        pass
    
    # Fallback to predefined responses
    user_input = user_input.lower()
    
    # Check for greetings
    if any(word in user_input for word in ['hi', 'hello', 'hey', 'greetings']):
        return np.random.choice(PHISHING_RESPONSES['greeting'])
    
    # Check for phishing definition
    if any(word in user_input for word in ['what is phishing', 'explain phishing', 'define phishing']):
        return np.random.choice(PHISHING_RESPONSES['what_is_phishing'])
    
    # Check for spotting fake websites
    if any(word in user_input for word in ['spot fake', 'identify fake', 'recognize fake', 'how to spot']):
        return np.random.choice(PHISHING_RESPONSES['spot_fake_website'])
    
    # Check for entered details
    if any(word in user_input for word in ['entered details', 'gave information', 'shared information', 'what to do']):
        return np.random.choice(PHISHING_RESPONSES['entered_details'])
    
    # Check for prevention tips
    if any(word in user_input for word in ['prevent', 'avoid', 'stop', 'protection', 'safe']):
        return np.random.choice(PHISHING_RESPONSES['prevention_tips'])
    
    # Out of scope response
    return np.random.choice(PHISHING_RESPONSES['out_of_scope'])

# Function to extract features from a URL
def extract_features(url):
    features = []
    domain = ""
    whois_response = ""
    parsed_url = ""
    response = ""
    soup = ""

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        pass

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
    except:
        pass

    try:
        whois_response = whois.whois(domain)
    except:
        pass

    # 1.UsingIp
    def check_using_ip():
        try:
            ipaddress.ip_address(url)
            return -1
        except:
            return 1

    # 2.longUrl
    def check_long_url():
        if len(url) < 54:
            return 1
        if len(url) >= 54 and len(url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def check_short_url():
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

    # 4.Symbol@
    def check_symbol():
        if re.findall("@", url):
            return -1
        return 1
    
    # 5.Redirecting//
    def check_redirecting():
        if url.rfind('//') > 6:
            return -1
        return 1
    
    # 6.prefixSuffix
    def check_prefix_suffix():
        try:
            match = re.findall('\-', domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains
    def check_subdomains():
        dot_count = len(re.findall("\.", url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    def check_https():
        try:
            https = parsed_url.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def check_domain_reg_len():
        try:
            expiration_date = whois_response.expiration_date
            creation_date = whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12 + (expiration_date.month-creation_date.month)
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def check_favicon():
        try:
            for head in soup.find_all('head'):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def check_non_std_port():
        try:
            port = domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def check_https_domain_url():
        try:
            if 'https' in domain:
                return -1
            return 1
        except:
            return -1
    
    # 13. RequestURL
    def check_request_url():
        try:
            i, success = 0, 0
            for img in soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if url in img['src'] or domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for audio in soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for embed in soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for iframe in soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    # 14. AnchorURL
    def check_anchor_url():
        try:
            i, unsafe = 0, 0
            for a in soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1
        except:
            return -1

    # 15. LinksInScriptTags
    def check_links_in_script_tags():
        try:
            i, success = 0, 0
        
            for link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if url in link['href'] or domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            for script in soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if url in script['src'] or domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i + 1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler
    def check_server_form_handler():
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

    # 17. InfoEmail
    def check_info_email():
        try:
            if re.findall(r"[mail\(\)|mailto:?]", soup.text):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def check_abnormal_url():
        try:
            if response.text == whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def check_website_forwarding():
        try:
            if len(response.history) <= 1:
                return 1
            elif len(response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. StatusBarCust
    def check_status_bar_cust():
        try:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 21. DisableRightClick
    def check_disable_right_click():
        try:
            if re.findall(r"event.button ?== ?2", response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 22. UsingPopupWindow
    def check_using_popup_window():
        try:
            if re.findall(r"alert\(", response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 23. IframeRedirection
    def check_iframe_redirection():
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 24. AgeofDomain
    def check_age_of_domain():
        try:
            creation_date = whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording    
    def check_dns_recording():
        try:
            creation_date = whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic   
    def check_website_traffic():
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            if (int(rank) < 100000):
                return 1
            return 0
        except:
            return -1

    # 27. PageRank
    def check_page_rank():
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": domain})
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    # 28. GoogleIndex
    def check_google_index():
        try:
            site = search(url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage
    def check_links_pointing_to_page():
        try:
            number_of_links = len(re.findall(r"<a href=", response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def check_stats_report():
        try:
            url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
            ip_address = socket.gethostbyname(domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1

    features.append(check_using_ip())
    features.append(check_long_url())
    features.append(check_short_url())
    features.append(check_symbol())
    features.append(check_redirecting())
    features.append(check_prefix_suffix())
    features.append(check_subdomains())
    features.append(check_https())
    features.append(check_domain_reg_len())
    features.append(check_favicon())
    
    features.append(check_non_std_port())
    features.append(check_https_domain_url())
    features.append(check_request_url())
    features.append(check_anchor_url())
    features.append(check_links_in_script_tags())
    features.append(check_server_form_handler())
    features.append(check_info_email())
    features.append(check_abnormal_url())
    features.append(check_website_forwarding())
    features.append(check_status_bar_cust())
    
    features.append(check_disable_right_click())
    features.append(check_using_popup_window())
    features.append(check_iframe_redirection())
    features.append(check_age_of_domain())
    features.append(check_dns_recording())
    features.append(check_website_traffic())
    features.append(check_page_rank())
    features.append(check_google_index())
    features.append(check_links_pointing_to_page())
    features.append(check_stats_report())
    
    return features

# Function to make prediction
def make_prediction(features):
    sample_features = np.array([features])
    return model.predict(sample_features)[0]

# Streamlit UI
st.set_page_config(page_title="Phishing Website Detector", page_icon="🔍", layout="centered")

st.title("🔍 Phishing Website Detection")
st.write("Check if a website is **Safe** 🛡️ or **Phishing** ⚠️ by entering features manually or providing a URL.")

# Create a container for the chat interface
chat_container = st.container()

# Create tabs
tab1, tab2, tab3 = st.tabs(["🔗 Analyze URL", "✍️ Manual Input", "💬 Phishing Awareness Q&A"])

def url_exists(url):
    """Check if the URL exists."""
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

with tab1:
    st.header("Analyze a URL")
    url_input = st.text_input("Enter the URL to analyze:", placeholder="https://example.com")
    
    if st.button("🔎 Analyze URL"):
        if url_input:
            with st.spinner("Extracting features from URL..."):
                try:
                    # Extract features
                    features = extract_features(url_input)
                    
                    # Display extracted features
                    st.subheader("Extracted Features")
                    feature_col1, feature_col2 = st.columns(2)
                    
                    for i, (feature, value) in enumerate(zip(feature_names, features)):
                        with feature_col1 if i % 2 == 0 else feature_col2:
                            st.write(f"**{feature}:** {value}")
                    
                    # Make prediction
                    prediction = make_prediction(features)
                    
                    # Display result
                    st.subheader("Analysis Result")
                    if prediction == 1:
                        if not url_exists(url_input):
                            st. warning("⚠️ No such website exists. Please check the URL spelling and try again.")
                        else:
                            st.success("🛡️ Safe Website")
                            st.write("This website appears **safe** ✅.") 
                    else:
                        st.error("⚠️ Phishing Website Detected!")
                        st.write("🚨 This website is **phishing**! Do not enter sensitive information.")
                except Exception as e:
                    st.error(f"Error analyzing URL: {str(e)}")
        else:
            st.warning("Please enter a URL to analyze.")

with tab2:
    st.header("Manual Feature Input")
    st.write("Enter the website features below:")
    
    # Layout for user input (2 columns)
    features = []
    col1, col2 = st.columns(2)

    for i, feature in enumerate(feature_names):
        with col1 if i % 2 == 0 else col2:
            features.append(st.selectbox(f"{feature}", [-1, 0, 1], index=1))

    # Prediction button
    if st.button("🔎 Check Website Safety"):
        prediction = make_prediction(features)
        
        # Safe Website
        if prediction == 1:
            st.success("🛡️ Safe Website")
            st.write("This website appears **safe** ✅.")
        # Phishing Website
        else:
            st.error("⚠️ Phishing Website Detected!")
            st.write("🚨 This website is **phishing**! Do not enter sensitive information.")

with tab3:
    st.header("💬 Phishing Awareness Q&A")
    st.write("Ask me anything about phishing and cybersecurity! I'm here to help you stay safe online.")
    
    
    # Display chat history
    for message in st.session_state.chat_history:
        with st.chat_message(message["role"]):
            st.write(message["content"])
    
    # Display suggested questions
    st.sidebar.subheader("Suggested Questions")
    suggested_questions = [
        "What is phishing?",
        "How can I spot a fake website?",
        "What should I do if I entered details on a phishing site?",
        "How can I prevent phishing attacks?",
        "What are common signs of a phishing email?",
        "How do I create a strong password?",
        "What is two-factor authentication?",
        "How can I check if a website is secure?",
        "What should I do if I receive a suspicious email?",
        "How can I protect my personal information online?"
    ]
    
    for question in suggested_questions:
        if st.sidebar.button(question):
            st.session_state.chat_history.append({"role": "user", "content": question})
            with st.chat_message("user"):
                st.write(question)
            
            with st.spinner("Thinking..."):
                response = get_phishing_response(question)
                st.session_state.chat_history.append({"role": "assistant", "content": response})
                with st.chat_message("assistant"):
                    st.write(response)

# Move chat input outside of tabs
with chat_container:
    if prompt := st.chat_input("Ask me about phishing and cybersecurity..."):
        # Add user message to chat history
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)
        
        # Get and display assistant response
        with st.spinner("Thinking..."):
            response = get_phishing_response(prompt)
            st.session_state.chat_history.append({"role": "assistant", "content": response})
            with st.chat_message("assistant"):
                st.write(response)

