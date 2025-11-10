SaitScan
> Full Passive Site Checker | بررسی‌کننده‌ی غیرفعال سایت

---

## [i] Description | توضیحات
A fast **passive (GET-only)** scanner for quick reconnaissance and heuristic checks of common web issues.  
ابزاری سریع و غیرفعال (فقط GET) برای جمع‌آوری اطلاعات اولیه و تشخیص هئورستیک مشکلات متداول وب.

---

## [*] Features | قابلیت‌ها
- Passive (GET-only) — no exploits run.  
  غیرفعال (فقط GET) — هیچ اکسپلویتی اجرا نمی‌شود.
- Parallel checks (threads) for speed.  
  اجرای موازی با threads برای سرعت بالاتر.
- Find common sensitive files: `.env`, `wp-config.php`, `.git/HEAD`.  
  پیدا کردن فایل‌های حساس رایج.
- Detect admin/login pages and password fields.  
  تشخیص صفحات ادمین/ورود و بررسی وجود فیلد پسورد.
- Check directory listing on common paths.  
  بررسی directory listing در مسیرهای رایج.
- Passive reflection & SQL-error heuristics.  
  تست بازتاب پارامترها و علائم خطای SQL (هئورستیک).
- Clean terminal output with `rich`.  
  خروجی ترمینال مرتب با کتابخانه‌ی `rich`.

---

## [#] Requirements | پیش‌نیازها
- Python 3.10+ (۳٫۱۰ به بالا)  
- pip  
- Python packages: `requests`, `rich`

Create `requirements.txt`:

requests>=2.28 rich>=13.0

---

## [→] Installation | نصب
```bash
git clone https://github.com/mostafapanahi2009-star/<site_scan2.py>.git
cd <site_scan2.py>

# optional virtual env
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt


---

[!] Usage | اجرا

Run the scanner (example):

python3 site_scan2.py

When prompted enter a domain or IP (e.g. example.com or 192.168.1.1).
این برنامه از تو می‌پرسد که آیا مالک سایت هستی — حتماً تأیید کن تا ادامه بده.


---

[~] Proxy support | پشتیبانی پراکسی

To use proxies, add a proxies.txt file in repo root (one http://user:pass@host:port per line) and adapt safe_get() to read/use them.
برای پراکسی، فایل proxies.txt بساز و هر خط را شکل بالا قرار بده؛ سپس safe_get() را برای خواندن/استفاده از آن تغییر بده.


---

[⚖] Legal / Ethics | هشدار قانونی

Only scan sites you own or have explicit permission to test. Unauthorized scanning may be illegal.
فقط سایت‌هایی را اسکن کن که مالکش هستی یا اجازه صریح داری — اسکن بدون اجازه ممکن است قانونی نباشد.


---

[✍] Author | نویسنده

Mostafa — mostafapanahi2009-star
Contact: @Mo303067


---

License

Recommended: MIT

اگر می‌خوای همین فایل رو به‌صورت واقعی در مخزن ایجاد کنم یا اصلاحاتی مثل اضافه کردن لینک مستقیم به مخزن، مثال خروجی (screenshot/GIF) یا تغییر نام فایل اسکریپت انجام بدم، بگو تا ویرایش کنم.
