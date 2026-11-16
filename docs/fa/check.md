---
icon: material/magnify
---

# بررسی دامنه

ببینید پیکربندی‌های پیش‌فرض با یک دامنه، نشانی وب یا آدرس IP چه می‌کنند: مسدود، مستقیم یا از طریق پراکسی.
همه چیز در مرورگر شما و با فهرست‌های منتشرشده انجام می‌شود.

<form id="vr-check-form" class="vr-check" autocomplete="off" data-lists="../../dl/lists/">
  <input id="vr-check-input" class="vr-check__input" type="text" dir="ltr" placeholder="digikala.com, https://example.com/page or 2.144.0.1" aria-label="دامنه، نشانی وب یا آدرس IP">
  <button class="md-button md-button--primary" type="submit">بررسی</button>
</form>

<div id="vr-check-result" class="vr-check__result" aria-live="polite"></div>

!!! note "چگونه تصمیم می‌گیرد"
    قوانین با همان ترتیب پیکربندی‌های پیش‌فرض بررسی می‌شوند: آدرس‌های صفحه مسدودسازی DNS ایران، بدافزار،
    فیشینگ، استخراج رمزارز و تبلیغات مسدود می‌شوند؛ سایت‌های تحریمی از پراکسی عبور می‌کنند؛ دامنه‌های `.ir`،
    سایت‌های ایرانی و بازه‌های IP ایران مستقیم می‌روند؛ بقیه از پراکسی عبور می‌کنند. اولین بار فهرست‌ها (چند
    مگابایت) دانلود می‌شوند، پس اولین بررسی کمی طول می‌کشد.

می‌توانید به نتیجه لینک بدهید: `https://aliraghebi.github.io/routing-rules/fa/check/?q=example.com`.
اگر نتیجه‌ای اشتباه به نظر می‌رسد، [گزارش دهید](https://github.com/aliraghebi/routing-rules/issues/new/choose).
