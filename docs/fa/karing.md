---
icon: material/vector-polyline
---

# Karing

[Karing](https://karing.app) بر پایه sing-box ساخته شده و برای قوانین مسیریابی سفارشی (diversion) قالب
خودش را دارد. `karing.json` یک فایل قوانین آماده در همین قالب است که از rule-setهای sing-box این پروژه
استفاده می‌کند.

## دریافت فایل قوانین

[:material-download: دانلود karing.json](https://github.com/aliraghebi/routing-rules/releases/latest/download/karing.json){ .md-button .md-button--primary }

## وارد کردن

1. فایل را با دکمه بالا دانلود کنید. متن را از زبانه مرورگر کپی نکنید: انتخاب ناقص فایل را خراب می‌کند
   (Karing خطای `FormatException: Unterminated string` می‌دهد).
2. در Karing صفحه قوانین مسیریابی سفارشی را باز کنید و فایل را وارد کنید؛ همان صفحه‌ای که Karing فایل
   `diversion_rules_custom.json` را از آن خروجی می‌گیرد.
3. مطمئن شوید هر دو گروه قوانین روشن هستند.

Karing خودش rule-setها را دانلود و به‌روز می‌کند، پس با تغییر فهرست‌ها لازم نیست دوباره وارد کنید.

## محتوا

| گروه | عمل | rule-setها |
|------|-----|-----------|
| 🚫 Block | `block` | `geoip-ir-injected` (آدرس‌های صفحه مسدودسازی DNS)، `geosite-malware`، `geoip-malware`، `geosite-phishing`، `geoip-phishing`، `geosite-cryptominers`، `geosite-ads` |
| ✅ Direct | `direct` | `geosite-private`، `geoip-private` (نام‌های محلی و بازه‌های خصوصی)، `geosite-ir`، `geoip-ir` |

بقیه ترافیک از پراکسی‌ای که در Karing انتخاب کرده‌اید عبور می‌کند. `geosite-ir` دامنه‌های `.ir` و
`.ایران` را هم شامل می‌شود، پس قانون جداگانه‌ای برای `.ir` لازم نیست.

!!! tip "افزودن قوانین خودتان"
    می‌توانید دامنه‌های خودتان (مثلاً `domain_suffix` یا `domain_regex`) را در Karing به هر کدام از گروه‌ها
    اضافه کنید. وارد کردن نسخه جدید این فایل ممکن است آن تغییرات را پاک کند، پس قوانین خودتان را در گروهی
    جداگانه نگه دارید.

برای rule-setهای بیشتر (`geosite-nsfw`، `geoip-telegram` و …) نشانی `.srs` آن‌ها را به یک گروه اضافه
کنید؛ ببینید [نشانی فایل‌ها](urls.md#sing-box-rule-sets-binary).
