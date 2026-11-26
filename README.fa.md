<div dir="rtl">

# A11yPilot — راهنمای کامل فارسی

**موتور خودکارسازی دسکتاپ بدون اسکرین‌شات، سرور خالص STDIO MCP و استودیوی کنترل X-Ray با سرعت 60fps بر پایه درخت دسترس‌پذیری بومی سیستم‌عامل**

> [بازگشت به نسخه دوزبانه (English & فارسی)](README.md)

---

## A11yPilot چیست و چه مشکلی را حل می‌کند؟

بیشتر ایجنت‌های کنترل کامپیوتر برای هر کلیک یک اسکرین‌شات کامل می‌گیرند و آن را به مدل‌های Vision می‌فرستند؛ این کار مصرف توکن را بسیار بالا می‌برد، تاخیر ایجاد می‌کند و احتمال خطا در حدس مختصات پیکسلی را بالا می‌برد.

**A11yPilot** به جای پردازش تصویر، مستقیماً ساختار معنایی رابط کاربری را از سیستم‌عامل می‌خواند:

- **پشتیبانی بومی از درخت دسترس‌پذیری:** روی ویندوز مستقیم به `Windows UI Automation` (`IUIAutomation` / `comtypes`) از طریق یک ترد اختصاصی COM و `SendInput` شصت‌وچهار بیتی متصل می‌شود، برای macOS (`AXUIElement`) و Linux (`AT-SPI2`) آداپتور دارد و یک `MockBackend` کامل برای اجرای بدون نمایشگر و تست‌های CI ارائه می‌دهد.
- **کاهش ~۸۴٪ تا ۸۹٪ مصرف توکن:** پنجره‌های شلوغ را هرس و مسطح‌سازی می‌کند (`max_depth=8`, `max_nodes=300`, `timeout=2.5s`) و کنترل‌های واقعی را با شناسه‌های `@e1`, `@e2`, ... برچسب‌گذاری می‌کند.
- **موتور ایمنی و تایید انسانی (HITL):** عملیات پرخطر (`Delete`, `Format`, `Pay`, رمز عبور، پنجره‌های ترمینال، کلیدهای ترکیبی خطرناک) را شناسایی و پیش از اجرا متوقف می‌کند تا اپراتور در استودیو دکمه **Approve** یا **Deny** را بزند.
- **حذف خودکار رمز عبور در مبدا:** فیلدهای رمز عبور یا فیلدهایی با نام `API Secret` / `Password` قبل از خروج از بک‌اند به `[REDACTED:PASSWORD]` تبدیل می‌شوند.
- **محافظت در برابر تغییر ناگهانی UI (`STALE_ELEMENT_REF`):** پیش از کلیک یا تایپ، وجود، نقش و عنوان المان دوباره بررسی می‌شود تا روی کنترل اشتباهی کلیک نشود.
- **استودیوی وب X-Ray:** رابط کاربری کاملاً آفلاین و امن روی `127.0.0.1` با بوم گرافیکی وایرفریم 60fps، همگام‌سازی دوطرفه با درخت المان‌ها، ضبط/پخش ماکروهای YAML، دکمه توقف اضطراری (`Emergency Stop`) و نمایش زنده آمار توکن.

---

## مقایسه مصرف توکن و سرعت

| سناریو | ایجنت مبتنی بر اسکرین‌شات (1080p) | خروجی A11yPilot | میزان صرفه‌جویی |
| :--- | :--- | :--- | :--- |
| **`MockBackend` (`CloudOps Console`)** | `3,200` توکن | `373` توکن (`1,489` بایت، `11` شناسه) | **`88.34%`** |
| **ویندوز واقعی (`WindowsUIABackend`)** | `3,200` توکن | `514–525` توکن (`18` شناسه، `~141–149 ms`) | **`83.6%–83.94%`** |

---

## نصب و راه‌اندازی (پایتون 3.11+)

```powershell
git clone https://github.com/AryaMehr-Nam/a11ypilot.git
cd a11ypilot
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

---

## آموزش کار با دستورات CLI و دمو

### ۱. اجرای دمو به همراه استودیوی زنده X-Ray

```bash
a11ypilot demo
# یا اجرای بدون مرورگر با شبیه‌ساز Mock:
a11ypilot demo --backend mock --no-open
```

### ۲. دستورات روزمره خط فرمان

```bash
# لیست پنجره‌های دسکتاپ
a11ypilot windows --backend auto
a11ypilot windows --backend mock --json

# دریافت درخت فشرده پنجره و آمار توکن
a11ypilot snapshot "CloudOps" --backend mock
a11ypilot snapshot "CloudOps" --backend mock --format json

# پیش‌نمایش یا اجرای دستور روی یک المان
a11ypilot act "CloudOps" click @e10 --backend mock --mode dry-run
a11ypilot act "CloudOps" type @e4 --text "payments-gateway" --backend mock

# اجرای استودیوی مستقل روی پورت 8780
a11ypilot studio --port 8780 --backend auto --mode safe

# اجرای ماکروی YAML با انتخابگرهای معنایی
a11ypilot macro run demo/sample_macro.yaml --mode dry-run --backend mock
```

---

## اتصال به Claude Desktop و Cursor (MCP)

در فایل `claude_desktop_config.json` یا `.cursor/mcp.json` اضافه کنید:

```json
{
  "mcpServers": {
    "a11ypilot": {
      "command": "C:\\path\\to\\a11ypilot\\.venv\\Scripts\\python.exe",
      "args": [
        "-m",
        "a11ypilot.mcp.server",
        "--backend",
        "auto",
        "--mode",
        "safe",
        "--studio-port",
        "8780"
      ]
    }
  }
}
```

ابزارهای در دسترس برای ایجنت:
`list_windows`, `inspect_window`, `find_elements`, `click_element`, `type_text`, `toggle_element`, `select_option`, `scroll_element`, `press_hotkey`, `run_macro`.

---

## تست و بررسی کیفیت کد

```bash
ruff check src tests demo
ruff format --check src tests demo
mypy src
pytest -v
```

</div>
