#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "web_safe_practice_report_draft.md"
BACKUP = ROOT / "reports" / "web_safe_practice_report_draft_v1.md"


TOC = """# Содержание

Введение

1 Анализ современных угроз фишинга и средств антифишинговой защиты

1.1 Актуальность защиты пользователей веб-браузеров

1.2 Статистические данные по фишинговым атакам

1.3 Типовой сценарий попадания пользователя на фишинговую страницу

1.4 Теоретические основы фишинга и оценки риска веб-сайтов

1.5 Обзор современных подходов к антифишинговой защите

1.6 Требования, предъявляемые к разрабатываемому расширению

2 Проектирование и реализация браузерного расширения Web Safe

2.1 Общая архитектурная модель расширения

2.2 Источники данных и сигналы риска

2.3 Линейная модель оценки URL-риска

2.4 Алгоритмы анализа веб-страницы и формирования итогового риска

2.5 Пользовательский интерфейс и сценарии использования

2.6 Сборка, обновление данных и жизненный цикл приложения

2.7 Детализация модулей и проектные решения

3 Безопасная разработка

3.1 Значение безопасной разработки для проекта

3.2 Защищаемые активы и требования безопасности

3.3 Управление секретами и внешними API

3.4 Минимизация данных и защита приватности пользователя

3.5 Защита пользовательского интерфейса

3.6 Управление разрешениями расширения

3.7 Отказоустойчивость внешних проверок

3.8 Безопасность сборочной среды

4 Тестирование и оценка защищённости Web Safe

4.1 Цели и задачи тестирования

4.2 Методики тестирования

4.3 Тестирование URL-модели и качества классификации

4.4 Проверка backend Google Safe Browsing

4.5 Функциональное тестирование расширения в Mozilla Firefox

4.6 Проверка приватности и защиты popup-интерфейса

4.7 Ограничения текущей реализации и направления развития

Заключение

Список использованных источников
"""


def main():
    source = BACKUP if BACKUP.exists() else REPORT
    original = source.read_text(encoding="utf-8")
    if not BACKUP.exists():
        BACKUP.write_text(original, encoding="utf-8")

    sections = split_h1_sections(original)
    new_report = build_report(sections)
    REPORT.write_text(new_report, encoding="utf-8")
    print(f"restructured: {REPORT}")


def split_h1_sections(text):
    matches = list(re.finditer(r"(?m)^# .+$", text))
    sections = {}

    for index, match in enumerate(matches):
        title = match.group(0)[2:].strip()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[title] = text[start:end].strip()

    return sections


def build_report(sections):
    intro = sections.get("1. Введение", "")
    conclusion = sections.get("16. Заключение", "")
    sources = sections.get("17. Список источников", "")

    parts = [
        "# Отчёт о преддипломной практике",
        "",
        "## Тема",
        "",
        "**Разработка браузерного расширения Web Safe для оценки риска веб-сайтов и выявления признаков фишинга**",
        "",
        "## Пробная структура отчёта",
        "",
        (
            "Данная версия Markdown-файла переработана под структуру, близкую к отчёту по преддипломной практике: "
            "четыре крупные главы, подробные подпункты, отдельная глава безопасной разработки и отдельная глава "
            "тестирования. Материал основан на текущем проекте Web Safe: расширении для Firefox/Chromium, "
            "backend-прокси Google Safe Browsing, URL-модели, DNS/RDAP-проверках, Public Suffix List и анализе "
            "DOM-признаков страницы."
        ),
        "",
        "---",
        "",
        TOC,
        "",
        "---",
        "",
        "# Введение",
        "",
        cleanup_body(intro),
        "",
        "---",
        "",
        "# 1 Анализ современных угроз фишинга и средств антифишинговой защиты",
        "",
        render_h2_sections(
            sections.get("2. Актуальность задачи антифишинговой защиты", ""),
            [
                "1.1 Актуальность защиты пользователей веб-браузеров",
                "1.2 Статистические данные по фишинговым атакам",
                "1.3 Типовой сценарий попадания пользователя на фишинговую страницу",
            ],
        ),
        "",
        render_whole_section(
            "1.4 Теоретические основы фишинга и оценки риска веб-сайтов",
            sections.get("3. Теоретические основы фишинга и оценки риска сайтов", ""),
        ),
        "",
        render_whole_section(
            "1.5 Обзор современных подходов к антифишинговой защите",
            sections.get("4. Обзор существующих подходов к защите пользователя", ""),
        ),
        "",
        render_whole_section(
            "1.6 Требования, предъявляемые к разрабатываемому расширению",
            sections.get("5. Постановка задачи и требования к Web Safe", ""),
        ),
        "",
        "---",
        "",
        "# 2 Проектирование и реализация браузерного расширения Web Safe",
        "",
        render_whole_section(
            "2.1 Общая архитектурная модель расширения",
            sections.get("6. Архитектура разработанного расширения", ""),
        ),
        "",
        render_whole_section(
            "2.2 Источники данных и сигналы риска",
            sections.get("7. Источники данных и сигналы риска", ""),
        ),
        "",
        render_whole_section(
            "2.3 Линейная модель оценки URL-риска",
            sections.get("8. Линейная модель оценки URL-риска", ""),
        ),
        "",
        render_whole_section(
            "2.4 Алгоритмы анализа веб-страницы и формирования итогового риска",
            sections.get("9. Алгоритмы работы приложения", ""),
        ),
        "",
        render_whole_section(
            "2.5 Пользовательский интерфейс и сценарии использования",
            sections.get("10. Пользовательский интерфейс и сценарии использования", ""),
        ),
        "",
        render_whole_section(
            "2.6 Сборка, обновление данных и жизненный цикл приложения",
            sections.get("12. Сборка, обновление данных и эксплуатация", ""),
        ),
        "",
        render_whole_section(
            "2.7 Детализация модулей и проектные решения",
            sections.get("15. Детализация модулей, псевдокод и проектные решения", ""),
        ),
        "",
        "---",
        "",
        "# 3 Безопасная разработка",
        "",
        render_h2_sections(
            sections.get("11. Безопасная разработка", ""),
            [
                "3.1 Значение безопасной разработки для проекта",
                "3.2 Защищаемые активы и требования безопасности",
                "3.3 Управление секретами и внешними API",
                "3.4 Минимизация данных и защита приватности пользователя",
                "3.5 Защита пользовательского интерфейса",
                "3.6 Управление разрешениями расширения",
                "3.7 Отказоустойчивость внешних проверок",
                "3.8 Безопасность сборочной среды",
            ],
        ),
        "",
        "---",
        "",
        "# 4 Тестирование и оценка защищённости Web Safe",
        "",
        render_h2_sections(
            sections.get("13. Тестирование и оценка качества", ""),
            [
                "4.1 Цели и задачи тестирования",
                "4.2 Методики тестирования",
                "4.3 Тестирование URL-модели и качества классификации",
                "4.4 Проверка backend Google Safe Browsing",
                "4.5 Функциональное тестирование расширения в Mozilla Firefox",
                "4.6 Проверка приватности и защиты popup-интерфейса",
            ],
        ),
        "",
        render_whole_section(
            "4.7 Ограничения текущей реализации и направления развития",
            sections.get("14. Ограничения текущей реализации и направления развития", ""),
        ),
        "",
        "---",
        "",
        "# Заключение",
        "",
        cleanup_body(conclusion),
        "",
        "---",
        "",
        "# Список использованных источников",
        "",
        cleanup_body(sources),
    ]

    return "\n".join(part for part in parts if part is not None).strip() + "\n"


def render_h2_sections(body, titles, overflow_title=None):
    chunks = split_h2_chunks(body)
    if not chunks:
        return ""

    rendered = []
    for index, (_, chunk_body) in enumerate(chunks):
        if index < len(titles):
            title = titles[index]
        elif overflow_title:
            title = overflow_title if index == len(titles) else f"{overflow_title}.{index - len(titles) + 1}"
        else:
            title = titles[-1]

        rendered.append(f"## {title}\n\n{demote_headings(cleanup_body(chunk_body), 1)}")

    return "\n\n".join(rendered)


def render_whole_section(title, body):
    body = cleanup_body(body)
    if not body:
        return f"## {title}"

    return f"## {title}\n\n{demote_headings(body, 1)}"


def split_h2_chunks(body):
    body = cleanup_body(body)
    matches = list(re.finditer(r"(?m)^## .+$", body))
    if not matches:
        return [(None, body)] if body else []

    chunks = []
    prefix = body[: matches[0].start()].strip()
    if prefix:
        chunks.append((None, prefix))

    for index, match in enumerate(matches):
        heading = strip_number(match.group(0)[3:].strip())
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        chunks.append((heading, body[start:end].strip()))

    return chunks


def demote_headings(text, offset):
    def replace(match):
        hashes = match.group(1)
        title = strip_number(match.group(2).strip())
        return "#" * (len(hashes) + offset) + " " + title

    return re.sub(r"(?m)^(#{2,6})\s+(.+)$", replace, text)


def cleanup_body(body):
    body = body.strip()
    body = re.sub(r"\n{3,}", "\n\n", body)
    return body


def strip_number(title):
    return re.sub(r"^\d+(?:\.\d+)*\.?\s+", "", title).strip()


if __name__ == "__main__":
    main()
