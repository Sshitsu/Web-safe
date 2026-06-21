# Web Safe

MVP браузерного расширения, которое оценивает риск сайта по URL, базам известных угроз, DNS/RDAP сигналам и признакам страницы.

## Что уже умеет

- анализировать активную вкладку в Firefox, Chrome и Edge
- проверять сайт по открытым фидам известных фишинговых URL/доменов
- учитывать возраст домена через RDAP
- учитывать DNS-сигналы через DNS over HTTPS
- считать URL-риск через обучаемую линейную модель
- показывать итоговый балл, уровень риска и причины
- учитывать URL, протокол, домен, слова-триггеры и признаки страницы
- выявлять внешние обработчики форм, брендовые подмены и подозрительный сбор чувствительных данных на странице
- автоматически запускать анализ при открытии popup
- сохранять историю последних проверок
- показывать badge на иконке расширения после анализа
- проверять Google Safe Browsing через локальный backend без хранения API-ключа в расширении
- использовать Public Suffix List для корректного выделения registrable domain
- обновлять модель и Public Suffix List во время сборки

## Как запускать в Firefox

1. Открой `about:debugging`
2. Перейди в `This Firefox`
3. Нажми `Load Temporary Add-on`
4. Выбери любой файл внутри папки проекта, обычно `C:\Web safe\manifest.json`

По данным Firefox Extension Workshop, временная установка для отладки делается именно через `about:debugging` -> `This Firefox` -> `Load Temporary Add-on`, после чего можно нажимать `Reload` для подхвата изменений.

## Как запускать в Chrome или Edge

1. Открой `chrome://extensions/` или `edge://extensions/`
2. Включи `Developer mode`
3. Нажми `Load unpacked`
4. Выбери папку проекта `C:\Web safe`

## Google Safe Browsing backend

API-ключ Google Safe Browsing не хранится в расширении. Вместо этого расширение обращается к локальному backend:

```text
http://127.0.0.1:8787/safe-browsing/check
```

Запуск backend:

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_API_KEY"
py backend\safe_browsing_proxy.py
```

Проверка backend:

```powershell
Invoke-RestMethod http://127.0.0.1:8787/health
```

Если backend не запущен или ключ не задан, расширение продолжит анализ по OpenPhish, Phishing.Database, DNS/RDAP и URL-модели. В popup для Google SB будет показано `недоступно` или `нет ключа`.

## Почему manifest сделан так

Сейчас проект использует один `manifest.json` для нескольких браузеров:

- для Chromium-браузеров используется `background.service_worker`
- для Firefox используется `background.scripts`
- `preferred_environment` просит Firefox/Safari использовать background document, если он доступен
- общий код при этом лежит в одних и тех же файлах

По документации MDN, Firefox не поддерживает `background.service_worker`, но поддерживает `background.scripts`; при этом в Manifest V3 можно описать оба варианта в одном манифесте для кроссбраузерной совместимости.

## Как работает оценка

Скоринг складывается из нескольких групп сигналов:

- совпадение с OpenPhish Community Feed
- совпадение с Phishing.Database active domains
- возраст домена из RDAP
- наличие A/AAAA и NS DNS-записей
- очень короткий DNS TTL
- URL-риск по модели `src/urlFeatureModel.js`
- отсутствие `HTTPS`
- IP вместо домена
- подозрительная доменная зона
- punycode в имени домена
- слишком длинный URL
- подозрительные слова на странице или в адресе
- наличие пароля на странице без HTTPS
- отправка формы с паролем или чувствительными полями на внешний домен
- упоминание известного бренда на неофициальном домене
- срочные формулировки рядом со сбором данных
- высокая доля внешних ссылок, скриптов или iframe
- дополнительные слабые сигналы, например много форм или iframe

## Обучение URL-модели

Скрипт обучения лежит в `tools/train_url_model.py`. Он скачивает реальные фишинговые URL из OpenPhish и Phishing.Database, легитимные домены из Tranco, обучает логистическую модель и перезаписывает `src/urlModelWeights.js`.

Запуск:

```powershell
python tools\train_url_model.py --positive-limit 8000 --negative-limit 8000 --epochs 120
```

Если на Windows команда `python` открывает Microsoft Store, нужно установить Python с python.org или отключить App Execution Alias для `python.exe`.

Что означают метрики:

- `accuracy` показывает общую долю правильных ответов
- `precision` показывает, насколько редко модель ошибочно ругается на нормальные сайты
- `recall` показывает, какую долю фишинговых URL модель поймала
- `falsePositive` это нормальные URL, ошибочно помеченные как фишинг
- `falseNegative` это фишинговые URL, которые модель пропустила

Быстрая проверка модели на отдельных URL:

```powershell
py tools\score_url_model.py "https://google.com/" "http://192.168.0.1/login"
```

## Сборка

Полная сборка обновляет Public Suffix List, переобучает URL-модель и собирает расширение в `dist\web-safe` и `dist\web-safe.zip`.

```powershell
py tools\build.py
```

Быстрая сборка без переобучения:

```powershell
py tools\build.py --skip-train
```

Быстрая сборка без обновления Public Suffix List:

```powershell
py tools\build.py --skip-psl
```

Для теста собранного билда в Firefox можно выбрать:

```text
C:\Web safe\dist\web-safe\manifest.json
```

## Public Suffix List

`tools/update_public_suffix_list.py` скачивает официальный список Public Suffix List и генерирует:

- `data/public_suffix_rules.json` для Python-скриптов
- `src/publicSuffixData.js` для расширения

Это нужно, чтобы корректно отличать registrable domain от публичного суффикса. Например, для `shop.example.co.uk` registrable domain должен быть `example.co.uk`, а не `co.uk`.

## Источники сигналов

- OpenPhish Community Feed: `https://openphish.com/feed.txt`
- Phishing.Database active domains: `https://phish.co.za/latest/phishing-domains-ACTIVE.txt`
- RDAP bootstrap endpoint: `https://rdap.org/domain/{domain}`
- Cloudflare DNS over HTTPS JSON API: `https://cloudflare-dns.com/dns-query`
- Tranco top list для benign-выборки: `https://tranco-list.eu/top-1m.csv.zip`
- Google Safe Browsing Lookup API v4: `https://developers.google.com/safe-browsing/v4/lookup-api`
- Public Suffix List: `https://publicsuffix.org/list/public_suffix_list.dat`

## Extended ML model, CI and store preparation

Current version adds a second linear model layer in `src/siteFeatureModel.js`.
Unlike the older URL-only model, this model can use combined URL, DOM, DNS and RDAP features.

Important files:

- `src/siteFeatureModel.js` extracts runtime features for the extended model.
- `src/siteModelWeights.js` stores trained site-model weights.
- `data/site_model_training_examples.csv` contains labeled DOM/DNS/RDAP training examples.
- `tools/train_site_model.py` trains the extended model.
- `tests/run_app_functional_tests.mjs` contains deterministic functional tests.
- `.github/workflows/ci.yml` runs tests, security scans and extension build in GitHub Actions.
- `store/` contains publication drafts for Chrome Web Store and Firefox Add-ons.

Train the extended model:

```powershell
py tools\train_site_model.py --positive-limit 8000 --negative-limit 8000 --epochs 120
```

Run local tests:

```powershell
& "C:\Program Files\nodejs\npm.cmd" test
```

Run a fast build:

```powershell
py tools\build.py --skip-train --skip-psl
```

Run Mozilla lint:

```powershell
& "C:\Program Files\nodejs\npx.cmd" --yes web-ext lint -s dist\web-safe
```


