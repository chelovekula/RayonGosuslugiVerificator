# Проверка XML СТД-ПФР (Госуслуги)

Утилита `stdpfrverify` проверяет встроенную подпись XMLDSig в выписке электронной трудовой книжки (формат СТД-ПФР): целостность по `DigestValue`, подпись `SignatureValue` (ГОСТ 2012), опционально цепочку до УЦ и политику подписанта.

## Вывод

**По умолчанию в stdout выводится один JSON-объект** (удобно для скриптов и CI). Поле `success` равно `true`, только если все запрошенные проверки прошли.

```bash
./stdpfrverify файл.xml
./stdpfrverify --pretty файл.xml   # с отступами
./stdpfrverify --text файл.xml     # человекочитаемый текст вместо JSON
```

## Сборка

```bash
go build -o stdpfrverify ./cmd/stdpfrverify
```

## Флаги

| Флаг | Назначение |
|------|------------|
| `--integrity-only` | Только `Reference` / `DigestValue` (без `SignatureValue`). |
| `--ca-path` | Файл или каталог PEM для `openssl verify` (цепочка УЦ). |
| `--policy-std-pfr` | Проверка, что подписант похож на ПФР/СФР (по CN). |
| `--xmlsec-fallback` | После неудачи в Go вызвать `xmlsec1 --verify`. |
| `--pretty` | Форматировать JSON с отступами. |
| `--text` | Текстовый отчёт вместо JSON. |

## Установка КриптоПро CSP и сертификатов на Ubuntu Linux

Ниже типовой порядок действий; точные имена `.deb` и версии берите с [официального сайта КриптоПро](https://www.cryptopro.ru/products/csp/downloads) и [документации](https://docs.cryptopro.ru/), т.к. они меняются.

### 1. Подготовка системы

```bash
sudo apt update
sudo apt install -y wget ca-certificates unzip build-essential libpcsclite1 pcscd opensc
```

Если нужна работа с Рутокен/JaCarta по USB, установите драйверы токена по инструкции производителя и убедитесь, что `pcscd` запущен: `sudo systemctl enable --now pcscd`.

### 2. Установка КриптоПро CSP (Linux)

1. Скачайте архив **КриптоПро CSP для Linux** с сайта CryptoPro (нужна регистрация/личный кабинет или дистрибутив от поставщика).
2. Распакуйте и установите пакеты в порядке, указанном в `readme.txt` из дистрибутива. Обычно это что-то вроде:

```bash
cd linux-amd64   # имя каталога из вашего архива
sudo dpkg -i ./lsb-cprocsp-*.deb ./cprocsp-pki-*.deb ./cprocsp-curl-*.deb ./cprocsp-rdr-*.deb ...
sudo apt-get install -f -y   # добить зависимости, если dpkg ругается
```

3. Проверка:

```bash
/opt/cprocsp/bin/amd64/csptest -keyset
/opt/cprocsp/bin/amd64/cryptcp -help
```

Путь к `amd64` может быть `ia32` на 32-bit системах.

### 3. Лицензия КриптоПро

Без действующей лицензии CSP работает в ограниченном режиме. Ключ лицензии вводится по инструкции CryptoPro (утилита `cpconfig` / графический мастер из поставки).

### 4. OpenSSL с поддержкой ГОСТ (для `openssl verify` и иногда xmlsec)

Варианты:

- Поставить **ossl-provider-gost** или пакет **openssl-gost-engine** из репозитория дистрибутива / PPA, если есть для вашей версии Ubuntu.
- Или использовать **OpenSSL из поставки КриптоПро** (см. документацию «Интеграция с OpenSSL» в `docs.cryptopro.ru`).

Проверка провайдера (пример для OpenSSL 3):

```bash
openssl list -providers
openssl list -digest-algorithms  | grep -i gost || true
```

Настройте `OPENSSL_CONF` и `OPENSSL_MODULES`, если провайдер ГОСТ установлен отдельно (пути зависят от пакета).

### 5. xmlsec с ГОСТ (опционально, для `--xmlsec-fallback`)

Стандартный `xmlsec1` из Ubuntu часто **без** алгоритмов `cpxmlsec`/ГОСТ. Нужна сборка **xmlsec** с libxml2/openssl, к которым подключены ГОСТ-провайдеры, либо готовый пакет от CryptoPro/интегратора. После установки:

```bash
xmlsec1 --version
xmlsec1 --verify ваш.xml
```

### 6. Корневые и промежуточные сертификаты НУЦ / доверенные УЦ РФ

1. Актуальные доверенные корни и промежуточные сертификаты для квалифицированной ЭП в РФ публикуются на ресурсах **Минцифры / НУЦ** (например, пакеты «доверенные корневые сертификаты», «сертификаты аккредитованных УЦ»). Ссылки меняются — используйте официальный сайт `gosuslugi.ru` / `digital.gov.ru` / реестр НУЦ.
2. Скачайте архив с `.cer` / `.crt`, конвертируйте в PEM при необходимости:

```bash
openssl x509 -inform DER -in cert.cer -out cert.pem
```

3. Соберите каталог доверия (hash-ссылки для `-CApath`) или один файл:

```bash
cat intermediate.pem root.pem > bundle.pem
```

4. Передайте в утилиту:

```bash
./stdpfrverify --ca-path /path/to/bundle.pem файл.xml
# или каталог с PEM для openssl verify -CApath
```

Для проверки только целостности без цепочки УЦ:

```bash
./stdpfrverify --integrity-only файл.xml
```

### 7. Проверка XML через КриптоПро

Для встроенной XMLDSig (как в СТД-ПФР) обычно используют средства CSP/API, описанные в документации CryptoPro (не всегда обычный `cryptcp -verify` для «голого» DER). Уточняйте раздел про **XML-подпись** в документации вашей версии CSP. Утилита `stdpfrverify` при наличии `cryptcp` сообщает путь в поле `cryptopro_cryptcp_path` JSON-ответа.

## Зависимости (разработка)

- Go-библиотеки: `goxmldsig`, `gogost`, `moov-io/signedxml`.
- Опционально в рантайме: `openssl`, `xmlsec1` с ГОСТ, КриптоПро CSP.
