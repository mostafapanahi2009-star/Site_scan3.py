markdown
# SaitScan — Full Passive Site Checker / بررسی‌کننده‌ی غیرفعال سایت

A fast, **passive (GET-only)** site scanner for initial reconnaissance and heuristic detection of common web issues. Designed for legal use (by owners or authorized testers).

یک اسکنر **غیرفعال (فقط درخواست GET)** و سریع برای جمع‌آوری اطلاعات اولیه و تشخیص هئورستیک مشکلات رایج سایت. طراحی شده برای استفاده قانونی (مالکین یا تستر با اجازه).

## قابلیت‌ها | Features ♦

- 🟢 **Passive (GET-only)** — No exploits executed / هیچ اکسپلویتی اجرا نمیشود
- ⚡ **Parallel checks (threads)** — Fast & lightweight / سریع و کم‌مصرف
- 🔍 **Find sensitive files** (e.g., `.env`, `wp-config.php`, `.git/HEAD`) / پیدا کردن فایل‌های حساس
- 🔐 **Detect admin/login pages** and check for password fields / تشخیص صفحات admin/login و وجود فیلد پسورد
- 📁 **Directory listing checks** / بررسی فعال بودن directory listing
- 🧠 **Parameter reflection** and basic SQL error detection / تست بازتاب پارامترها و علائم خطای SQL
- 🎨 **Beautiful terminal output** with `rich` / خروجی ترمینال زیبا

## پیش‌نیازها | Prerequisites 📃

- Python 3.10+
- `pip`
- Packages: `requests`, `rich`

## نصب و اجرا | Installation & Usage ⚙️

```bash
git clone https://github.com/<your-username>/SaitScan.git
cd SaitScan
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 SaitScan.py
```

استفاده از پروکسی | Proxy Usage 🔁

Create a proxies.txt file (one proxy per line: http://user:pass@host:port). The scanner can read this file and use proxies for requests.

برای پروکسی می‌تونی فایل proxies.txt را بسازی (هر خط: http://user:pass@host:port) تا اسکنر از آن برای درخواست‌ها استفاده کند.

نکات مهم | Important Notes ⚠️

· Only run on sites you own or have explicit permission to test. / فقط روی سایت‌هایی که مالک‌ش هستی یا اجازه داری اجرا کن.
· Unauthorized scanning is illegal. / اسکن بدون اجازه قانونی نیست.
· This is a passive tool; its purpose is initial info gathering and education. / این ابزار غیرفعال است؛ هدفش جمع‌آوری اطلاعات اولیه و آموزش است.

نویسنده | Author ✍️

Mostafa.hk — @Mo303067

مجوز | License

