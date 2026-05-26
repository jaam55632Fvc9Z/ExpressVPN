import requests
from bs4 import BeautifulSoup
import re
import os
import html
import json
import base64
import urllib.parse
from datetime import datetime, timezone

# =============================================================
#  بخش تنظیمات (Settings)
# =============================================================
PINNED_CONFIGS = [
    "ss://bm9uZTpmOGY3YUN6Y1BLYnNGOHAz@lil:360?#.",
]

MY_CHANNEL_ID = ""
CUSTOM_SEPARATOR = "|"
NOT_FOUND_FLAG = "🌐"

SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://', 'ss://', 'shadowsocks://']

EXPIRY_HOURS = 72       # حذف از دیتابیس فقط پس از 144 ساعت
SEARCH_LIMIT_HOURS = 1   # بررسی پیام‌های 1 ساعت اخیر
ROTATION_LIMIT = 65      
ROTATION_LIMIT_2 = 1000   
ROTATION_LIMIT_3 = 100000   
# =============================================================

def get_only_flag(text):
    if not text: return NOT_FOUND_FLAG
    try:
        text = urllib.parse.unquote(urllib.parse.unquote(str(text)))
    except: pass
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    flags = flag_pattern.findall(text)
    return flags[0] if flags else NOT_FOUND_FLAG

def parse_vmess_uri(config):
    try:
        b64_str = config[8:]
        b64_str += "=" * (-len(b64_str) % 4)
        data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
        return data, True
    except:
        return None, False

def get_config_fingerprint(config):
    """ ساخت یک اثر انگشت منحصر به فرد و نرمال شده برای تشخیص دقیق تکراری‌ها """
    try:
        config = config.strip()
        # 1. مدیریت VMess (چون JSON است)
        if config.startswith("vmess://"):
            data, ok = parse_vmess_uri(config)
            if ok:
                # استخراج فیلدهای حیاتی و مرتب‌سازی آن‌ها
                keys = ['add', 'port', 'id', 'net', 'tls', 'path', 'host', 'sni']
                return "vmess:" + "|".join(str(data.get(k, '')).lower() for k in keys)
        
        # 2. مدیریت سایر پروتکل‌ها (VLESS, Trojan, SS, ...)
        base_part = config.split('#')[0]
        parsed = urllib.parse.urlparse(base_part)
        
        # استخراج پارامترها و مرتب‌سازی حروف الفبایی برای خنثی کردن جابه‌جایی
        query_params = urllib.parse.parse_qsl(parsed.query)
        # حذف پارامترهای غیرفنی مثل نام یا رمارک که ممکن است در کوئری باشد
        filtered_params = sorted([(k.lower(), v.lower()) for k, v in query_params if k.lower() not in ['remark', 'ps', 'name']])
        normalized_query = urllib.parse.urlencode(filtered_params)
        
        # ترکیب: پروتکل + یوزر و آدرس (حروف کوچک) + مسیر + پارامترهای مرتب شده
        return f"{parsed.scheme}:{parsed.netloc.lower()}{parsed.path.lower()}?{normalized_query}"
    except:
        return config

def analyze_and_rename(config, channel_name):
    try:
        config = config.strip()
        clean_source = channel_name.replace("https://t.me/", "@").replace("t.me/", "@")
        if not clean_source.startswith("@"): clean_source = f"@{clean_source}"

        transport, security, flag = "TCP", "None", NOT_FOUND_FLAG
        
        if config.startswith("vmess://"):
            data, ok = parse_vmess_uri(config)
            if ok:
                flag = get_only_flag(data.get('ps', ''))
                t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'h2': 'H2', 'quic': 'QUIC', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
                transport = t_map.get(data.get('net', 'tcp').lower(), 'TCP')
                security = 'TLS' if data.get('tls', '').lower() == 'tls' else 'None'
                data['ps'] = f"{flag} {transport}-{security} {CUSTOM_SEPARATOR} {clean_source}"
                return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')

        # سایر پروتکل‌ها
        base_url, raw_fragment = config.split('#', 1) if '#' in config else (config, "")
        flag = get_only_flag(raw_fragment)
        
        parsed = urllib.parse.urlparse(base_url)
        params = {k.lower(): v.lower() for k, v in urllib.parse.parse_qsl(parsed.query)}

        if 'security' in params:
            if params['security'] in ['tls', 'xtls', 'ssl']: security = 'TLS'
            elif params['security'] == 'reality': security = 'Reality'
        elif 'sni' in params or 'pbk' in params: security = 'Reality' if 'pbk' in params else 'TLS'

        t_val = params.get('type', params.get('net', 'tcp'))
        t_map = {'tcp': 'TCP', 'ws': 'WS', 'grpc': 'GRPC', 'kcp': 'KCP', 'httpupgrade': 'HTTPUpgrade', 'xhttp': 'XHTTP'}
        transport = t_map.get(t_val, 'TCP')

        if config.startswith(('hysteria2://', 'hy2://')): transport, security = "Hysteria", "TLS"
        elif config.startswith(('ss://', 'shadowsocks://')):
            transport, security = "TCP", "None"
            # بررسی پلاگین در شدوساکس
            plugin = urllib.parse.unquote(params.get('plugin', '')).lower()
            if 'tls' in plugin or 'ssl' in plugin: security = "TLS"
            if 'ws' in plugin or 'websocket' in plugin: transport = "WS"
            elif 'grpc' in plugin: transport = "GRPC"

        final_name = f"{flag} {transport}-{security} {CUSTOM_SEPARATOR} {clean_source}"
        return f"{base_url}#{urllib.parse.quote(final_name)}"
    except:
        return config

def extract_configs_logic(msg_div):
    for img in msg_div.find_all("img"):
        if 'emoji' in img.get('class', []) and img.get('alt'): img.replace_with(img['alt'])
    for br in msg_div.find_all("br"): br.replace_with("\n")
    full_text = html.unescape(msg_div.get_text())
    extracted = []
    for line in full_text.split('\n'):
        line = line.strip()
        for proto in SUPPORTED_PROTOCOLS:
            if proto in line:
                start_idx = line.find(proto)
                extracted.append(line[start_idx:].strip())
                break
    return extracted

def run():
    if not os.path.exists('channels.txt'): return
    with open('channels.txt', 'r') as f:
        channels = [line.strip() for line in f if line.strip()]

    db_data = []
    if os.path.exists('data.temp'):
        with open('data.temp', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|', 2)
                if len(parts) == 3: db_data.append(parts)

    now = datetime.now().timestamp()
    all_raw_seen = {d[2] for d in db_data} # برای جلوگیری از سنگین شدن دیتابیس در همان لحظه

    # دریافت کانفیگ‌های جدید
    for ch in channels:
        try:
            resp = requests.get(f"https://t.me/s/{ch}", timeout=15)
            if resp.status_code != 200: continue
            soup = BeautifulSoup(resp.text, 'html.parser')
            for wrap in soup.find_all('div', class_='tgme_widget_message_wrap'):
                time_tag = wrap.find('time')
                if not time_tag: continue
                msg_time = datetime.fromisoformat(time_tag['datetime'])
                if (datetime.now(timezone.utc) - msg_time).total_seconds() > (SEARCH_LIMIT_HOURS * 3600): continue
                msg_text = wrap.find('div', class_='tgme_widget_message_text')
                if not msg_text: continue
                for c in extract_configs_logic(msg_text):
                    if c not in all_raw_seen:
                        db_data.append([str(now), ch, c])
                        all_raw_seen.add(c)
        except: continue

    # فیلتر انقضای دیتابیس (فقط حذف موارد قدیمی‌تر از 144 ساعت)
    valid_items = [item for item in db_data if now - float(item[0]) < (EXPIRY_HOURS * 3600)]

    # === سیستم فیلتر تکراری‌های هوشمند برای فایل‌های خروجی ===
    unique_pool = []
    fingerprints_seen = set()
    # افزودن پین شده‌ها به لیست "دیده شده"
    for pin in PINNED_CONFIGS: fingerprints_seen.add(get_config_fingerprint(pin))
    
    for item in valid_items:
        fp = get_config_fingerprint(item[2])
        if fp not in fingerprints_seen:
            unique_pool.append(item)
            fingerprints_seen.add(fp)

    # مدیریت پوینتر و چرخش
    current_index = 0
    if os.path.exists('pointer.txt'):
        try:
            with open('pointer.txt', 'r') as f: current_index = int(f.read().strip())
        except: current_index = 0
    
    pool_size = len(unique_pool)
    if current_index >= pool_size: current_index = 0

    def get_rotated_batch(size):
        if pool_size == 0: return []
        actual_size = min(size, pool_size)
        if current_index + actual_size <= pool_size:
            return unique_pool[current_index : current_index + actual_size]
        else:
            return unique_pool[current_index:] + unique_pool[:actual_size - (pool_size - current_index)]

    # ذخیره فایل‌های متنی
    def save_output(filename, batch):
        with open(filename, 'w', encoding='utf-8') as f:
            for pin in PINNED_CONFIGS: f.write(pin + "\n\n")
            for ts, source_ch, raw_cfg in batch:
                f.write(analyze_and_rename(raw_cfg, source_ch) + "\n\n")

    save_output('configs.txt', get_rotated_batch(ROTATION_LIMIT))
    save_output('configs2.txt', get_rotated_batch(ROTATION_LIMIT_2))
    save_output('configs3.txt', unique_pool[-ROTATION_LIMIT_3:])
    save_output('configs4.txt', [item for item in unique_pool if now - float(item[0]) < 3600])

    # بروزرسانی دیتابیس (بدون پاکسازی، فقط حذف منقضی شده‌ها)
    with open('data.temp', 'w', encoding='utf-8') as f:
        for item in valid_items: f.write("|".join(item) + "\n")
    
    # ذخیره پوینتر جدید
    with open('pointer.txt', 'w', encoding='utf-8') as f:
        f.write(str((current_index + ROTATION_LIMIT) % pool_size if pool_size > 0 else 0))

if __name__ == "__main__":
    run()
