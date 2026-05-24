#!/usr/bin/env python3
from pathlib import Path
from textwrap import wrap

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = ROOT / "report_assets"

BG = "#f6f7fb"
PANEL = "#ffffff"
INK = "#1f2937"
MUTED = "#64748b"
BLUE = "#2563eb"
GREEN = "#16a34a"
ORANGE = "#d97706"
RED = "#dc2626"
BORDER = "#d6dbe6"


def main():
    ASSET_DIR.mkdir(exist_ok=True)
    make_architecture()
    make_popup()
    make_page_signals()
    make_safe_browsing()
    make_build_pipeline()
    make_model_training()
    make_secure_dev()
    make_project_structure()
    print(ASSET_DIR)


def font(size, bold=False):
    candidates = [
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/timesbd.ttf" if bold else "C:/Windows/Fonts/times.ttf",
    ]
    for item in candidates:
        if Path(item).exists():
            return ImageFont.truetype(item, size)
    return ImageFont.load_default()


def canvas(width=1400, height=850, title=None):
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    if title:
        draw.text((40, 28), title, fill=INK, font=font(32, bold=True))
    return image, draw


def box(draw, xy, title, lines=None, fill=PANEL, outline=BORDER, accent=BLUE):
    x1, y1, x2, y2 = xy
    draw.rounded_rectangle(xy, radius=18, fill=fill, outline=outline, width=2)
    draw.rectangle((x1, y1, x1 + 10, y2), fill=accent)
    draw.text((x1 + 28, y1 + 20), title, fill=INK, font=font(22, bold=True))
    y = y1 + 58
    for line in lines or []:
        for chunk in wrap(line, 34):
            draw.text((x1 + 28, y), chunk, fill=MUTED, font=font(17))
            y += 24
        y += 3


def arrow(draw, start, end, color="#475569"):
    draw.line((*start, *end), fill=color, width=4)
    ex, ey = end
    sx, sy = start
    if ex >= sx:
        points = [(ex, ey), (ex - 14, ey - 8), (ex - 14, ey + 8)]
    else:
        points = [(ex, ey), (ex + 14, ey - 8), (ex + 14, ey + 8)]
    draw.polygon(points, fill=color)


def make_architecture():
    image, draw = canvas(title="Архитектура расширения Web Safe")
    box(draw, (50, 130, 330, 285), "Popup UI", ["балл риска", "причины оценки", "история проверок"], accent=GREEN)
    box(draw, (420, 120, 720, 295), "background.js", ["сбор сигналов", "координация проверок", "badge и история"], accent=BLUE)
    box(draw, (820, 70, 1190, 210), "riskEngine.js", ["объединение сигналов", "нормализация оценки 0-100"], accent=ORANGE)
    box(draw, (820, 260, 1190, 420), "Источники угроз", ["OpenPhish", "Phishing.Database", "Google Safe Browsing backend"], accent=RED)
    box(draw, (420, 380, 720, 545), "Анализ страницы", ["формы и поля", "iframe, scripts, links", "брендовая подмена"], accent=GREEN)
    box(draw, (820, 500, 1190, 680), "DNS/RDAP + PSL", ["DNS over HTTPS", "возраст домена", "registrable domain"], accent=BLUE)
    box(draw, (50, 430, 330, 585), "URL-модель", ["обучаемые веса", "структура адреса", "score_url_model.py"], accent=ORANGE)
    arrow(draw, (330, 205), (420, 205))
    arrow(draw, (720, 205), (820, 145))
    arrow(draw, (720, 205), (820, 335))
    arrow(draw, (570, 380), (570, 295))
    arrow(draw, (330, 505), (420, 260))
    arrow(draw, (720, 475), (820, 590))
    image.save(ASSET_DIR / "architecture.png")


def make_popup():
    image, draw = canvas(900, 1000, "Интерфейс popup после анализа сайта")
    x, y, w, h = 260, 100, 380, 790
    draw.rounded_rectangle((x, y, x + w, y + h), radius=24, fill="#fff8ef", outline=BORDER, width=2)
    draw.text((x + 24, y + 24), "Risk Check", fill="#a8441d", font=font(14, bold=True))
    draw.text((x + 24, y + 52), "Web Safe", fill=INK, font=font(30, bold=True))
    draw.text((x + 24, y + 92), "Быстрая проверка активной вкладки", fill=MUTED, font=font(15))
    draw.rounded_rectangle((x + 18, y + 130, x + w - 18, y + 250), radius=18, fill="#ffffff", outline=BORDER)
    draw.ellipse((x + 34, y + 148, x + 114, y + 228), fill=GREEN)
    draw.text((x + 58, y + 172), "18", fill="white", font=font(24, bold=True))
    draw.text((x + 135, y + 160), "Низкий риск", fill=INK, font=font(21, bold=True))
    draw.text((x + 135, y + 194), "example.com", fill=MUTED, font=font(15))
    draw.rounded_rectangle((x + 18, y + 270, x + w - 18, y + 318), radius=12, fill="#bb4f21")
    draw.text((x + 110, y + 284), "Повторить проверку", fill="white", font=font(16, bold=True))
    facts = [("HTTPS", "OK"), ("База угроз", "2 ист."), ("Google SB", "чисто"), ("Страница", "норма"), ("URL-модель", "3%"), ("DNS", "2")]
    fx, fy = x + 24, y + 345
    for i, (k, v) in enumerate(facts):
        cx = fx + (i % 2) * 165
        cy = fy + (i // 2) * 64
        draw.rounded_rectangle((cx, cy, cx + 150, cy + 50), radius=10, fill="#ffffff", outline=BORDER)
        draw.text((cx + 10, cy + 8), k, fill=MUTED, font=font(12))
        draw.text((cx + 10, cy + 26), v, fill=INK, font=font(15, bold=True))
    draw.text((x + 24, y + 555), "Причины оценки", fill=INK, font=font(18, bold=True))
    reasons = ["Явных подозрительных признаков не найдено.", "Домен старше 90 дней.", "Google Safe Browsing не выявил угроз."]
    yy = y + 590
    for item in reasons:
        draw.text((x + 34, yy), f"• {item}", fill=INK, font=font(14))
        yy += 28
    draw.text((x + 24, y + 700), "История", fill=INK, font=font(18, bold=True))
    draw.rounded_rectangle((x + 24, y + 730, x + w - 24, y + 785), radius=10, fill="#ffffff", outline=BORDER)
    draw.ellipse((x + 38, y + 740, x + 72, y + 774), fill=GREEN)
    draw.text((x + 47, y + 747), "18", fill="white", font=font(12, bold=True))
    draw.text((x + 86, y + 740), "example.com", fill=INK, font=font(14, bold=True))
    draw.text((x + 86, y + 760), "Низкий риск · только что", fill=MUTED, font=font(12))
    image.save(ASSET_DIR / "popup.png")


def make_page_signals():
    image, draw = canvas(title="Анализ содержимого веб-страницы")
    box(draw, (60, 140, 370, 300), "DOM страницы", ["формы", "input password/email/tel", "hidden-поля"], accent=BLUE)
    box(draw, (520, 80, 870, 240), "Сбор признаков", ["form action host", "external links/scripts", "iframe sources"], accent=GREEN)
    box(draw, (1010, 120, 1340, 300), "Риск-факторы", ["внешняя форма с паролем", "упоминание бренда", "срочность + сбор данных"], accent=RED)
    box(draw, (520, 380, 870, 560), "Брендовая подмена", ["Google, PayPal, Meta", "сверка с официальным доменом", "учёт registrable domain"], accent=ORANGE)
    box(draw, (1010, 430, 1340, 600), "Итоговый скоринг", ["добавление весов", "объяснение причины", "отображение в popup"], accent=BLUE)
    arrow(draw, (370, 220), (520, 160))
    arrow(draw, (870, 160), (1010, 210))
    arrow(draw, (370, 220), (520, 470))
    arrow(draw, (870, 470), (1010, 515))
    image.save(ASSET_DIR / "page_signals.png")


def make_safe_browsing():
    image, draw = canvas(title="Интеграция Google Safe Browsing через backend")
    box(draw, (70, 210, 360, 390), "Расширение", ["не хранит API-ключ", "отправляет только URL", "работает при отказе backend"], accent=GREEN)
    box(draw, (540, 190, 870, 410), "Backend proxy", ["127.0.0.1 для разработки", "переменная окружения", "rate limit в production"], accent=BLUE)
    box(draw, (1050, 210, 1330, 390), "Google API", ["threatMatches.find", "SOCIAL_ENGINEERING", "MALWARE"], accent=RED)
    arrow(draw, (360, 300), (540, 300))
    arrow(draw, (870, 300), (1050, 300))
    draw.text((405, 260), "POST /safe-browsing/check", fill=MUTED, font=font(17))
    draw.text((910, 260), "API key only here", fill=MUTED, font=font(17))
    image.save(ASSET_DIR / "safe_browsing.png")


def make_build_pipeline():
    image, draw = canvas(title="Сборочный pipeline Web Safe")
    steps = [
        ("1", "Public Suffix List", "tools/update_public_suffix_list.py"),
        ("2", "Обучение модели", "tools/train_url_model.py"),
        ("3", "Проверки", "manifest, imports, py_compile"),
        ("4", "Пакет расширения", "dist/web-safe.zip"),
    ]
    x = 70
    for num, title, subtitle in steps:
        draw.ellipse((x, 250, x + 90, 340), fill=BLUE)
        draw.text((x + 34, 276), num, fill="white", font=font(28, bold=True))
        box(draw, (x - 35, 390, x + 230, 540), title, [subtitle], accent=BLUE)
        if num != "4":
            arrow(draw, (x + 120, 295), (x + 260, 295))
        x += 330
    image.save(ASSET_DIR / "build_pipeline.png")


def make_model_training():
    image, draw = canvas(title="Результат обучения URL-модели")
    terminal = (
        "PS C:\\Web safe> py tools\\build.py\\n"
        "public suffix rules updated: 9917 exact, 283 wildcard, 8 exception\\n"
        "trained on 12677 rows, tested on 3323 rows\\n"
        "{\\n"
        "  accuracy: 0.9904, precision: 1.0, recall: 0.9814,\\n"
        "  falsePositive: 0, falseNegative: 32\\n"
        "}\\n"
        "zip ready: C:\\Web safe\\dist\\web-safe.zip"
    )
    draw.rounded_rectangle((90, 140, 1310, 620), radius=18, fill="#111827")
    y = 175
    for line in terminal.splitlines():
        draw.text((125, y), line, fill="#d1fae5" if "accuracy" in line else "#e5e7eb", font=font(22))
        y += 48
    image.save(ASSET_DIR / "model_training.png")


def make_secure_dev():
    image, draw = canvas(title="Контур безопасной разработки")
    items = [
        ("Требования", "модель угроз, privacy-by-design"),
        ("Секреты", ".env, backend API key, .gitignore"),
        ("Код", "минимальные permissions, DOMParser не используется"),
        ("Зависимости", "стандартная библиотека Python, внешние фиды"),
        ("Сборка", "build.py, PSL, обучение модели, dist zip"),
        ("Проверка", "py_compile, manifest, smoke-test модели"),
    ]
    for idx, (title, line) in enumerate(items):
        col = idx % 3
        row = idx // 3
        x = 85 + col * 430
        y = 160 + row * 260
        box(draw, (x, y, x + 340, y + 165), title, [line], accent=[BLUE, GREEN, ORANGE, RED, BLUE, GREEN][idx])
    image.save(ASSET_DIR / "secure_dev.png")


def make_project_structure():
    image, draw = canvas(title="Структура проекта")
    text = [
        "Web safe/",
        "  manifest.json",
        "  popup/",
        "    popup.html, popup.css, popup.js",
        "  src/",
        "    background.js, riskEngine.js",
        "    threatFeeds.js, networkSignals.js",
        "    safeBrowsing.js, urlFeatureModel.js",
        "    domainUtils.js, publicSuffixData.js",
        "  backend/",
        "    safe_browsing_proxy.py",
        "  tools/",
        "    build.py, train_url_model.py",
        "    update_public_suffix_list.py",
        "  data/",
        "    public_suffix_rules.json",
    ]
    draw.rounded_rectangle((110, 120, 1290, 720), radius=20, fill="#ffffff", outline=BORDER, width=2)
    y = 155
    for line in text:
        color = BLUE if line.endswith("/") else INK
        draw.text((150, y), line, fill=color, font=font(24 if line.endswith("/") else 21, bold=line.endswith("/")))
        y += 33
    image.save(ASSET_DIR / "project_structure.png")


if __name__ == "__main__":
    main()
