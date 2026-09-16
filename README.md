# SSH Brute Force Detector

## English

A Python educational project that detects five failed SSH login attempts from the same IP address within any five-minute window.

The project uses only Python standard libraries.

This project was created with the assistance of AI for further independent study and analysis.

## Running the Project

Open a terminal in the project directory.

### Windows

```powershell
py -3 detector.py
py -3 -m unittest -v
```

### Linux / macOS

Use `python3` instead of `py`:

```bash
python3 detector.py
python3 -m unittest -v
```

Python 3 is required.

If `py -3` is unavailable and you are using the built-in Python 3 runtime from Codex, run:

```powershell
& "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" detector.py
```

## Sample Data

All events in `sample_auth.log` are synthetic. The IP addresses are taken from documentation ranges.

| IP Address | Scenario | Expected Result |
|---|---|---|
| `192.0.2.10` | Two failed attempts followed by a successful login | No alert |
| `198.51.100.23` | Five failed attempts within 4 minutes 20 seconds | Alert |
| `203.0.113.7` | Five failed attempts with 10-minute intervals | No alert |

Expected output:

```text
[ALERT] 198.51.100.23: 5 failed logins | 10:00:10 - 10:04:30 UTC
```

## How It Works

1. The script extracts timestamps and IP addresses from lines containing `Failed password`.
2. Events are sorted by timestamp.
3. For each IP address, a queue stores failed attempts from the last five minutes.
4. Attempts older than five minutes are removed from the beginning of the queue.
5. When the threshold of five failed attempts is reached, the first alert for that IP address is generated.

The detector uses a **sliding time window**. The five-minute interval is calculated relative to each new failed attempt rather than using fixed time blocks.

An attempt exactly five minutes from the earliest event is included.

Successful logins do not reset the failed-attempt counter.

## Limitations

- Only the educational log format is supported: UTC timestamps such as `2026-09-16T10:00:00Z`, IPv4 addresses, and `Failed password` messages. Other lines are ignored.
- This is not a universal Linux log parser.
- The entire file is processed in memory; real-time monitoring is not supported.
- Only one alert per IP address is generated during each run, even if another suspicious sequence occurs later.
- Duplicate log lines are treated as separate login attempts.
- An alert indicates frequent failed login attempts but does not prove that an attack or compromise occurred.
- A shared IP address used by multiple users may cause a false positive.
- Slow or distributed brute-force attempts may remain undetected.
- The script does not connect to servers or automatically block IP addresses.

## First Exercise

Add four failed login attempts from a new IP address, for example `192.0.2.55`, to `sample_auth.log` within a five-minute period.

Run the detector.

Then add a fifth failed attempt and run the detector again.

Explain why the result changed.

---

# Қазақша

## SSH Brute Force Detector

Бұл — бір IP мекенжайынан кез келген бес минут ішінде жасалған бес сәтсіз SSH кіру әрекетін анықтайтын Python тіліндегі оқу жобасы.

Жоба тек Python стандартты кітапханаларын пайдаланады.

Жоба жасанды интеллект көмегімен жасалды және кейін өз бетінше зерттеу мен талдауға арналған.

## Жобаны іске қосу

Терминалды жоба орналасқан бумада ашыңыз.

### Windows

```powershell
py -3 detector.py
py -3 -m unittest -v
```

### Linux / macOS

`py` орнына `python3` пайдаланыңыз:

```bash
python3 detector.py
python3 -m unittest -v
```

Python 3 қажет.

Егер `py -3` қолжетімсіз болса және Codex ішіндегі Python 3 ортасын пайдалансаңыз:

```powershell
& "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" detector.py
```

## Тестілік деректер

`sample_auth.log` файлындағы барлық оқиғалар синтетикалық болып табылады. IP мекенжайлары құжаттамаға арналған диапазондардан алынған.

| IP мекенжайы | Сценарий | Күтілетін нәтиже |
|---|---|---|
| `192.0.2.10` | Екі сәтсіз әрекеттен кейін сәтті кіру | Ескерту жоқ |
| `198.51.100.23` | 4 минут 20 секунд ішінде бес сәтсіз әрекет | Ескерту |
| `203.0.113.7` | 10 минуттық аралықпен бес сәтсіз әрекет | Ескерту жоқ |

Күтілетін нәтиже:

```text
[ALERT] 198.51.100.23: 5 failed logins | 10:00:10 - 10:04:30 UTC
```

## Қалай жұмыс істейді

1. Скрипт `Failed password` жолдарынан уақыт белгісін және IP мекенжайын алады.
2. Оқиғалар уақыт бойынша сұрыпталады.
3. Әр IP мекенжайы үшін соңғы бес минуттағы сәтсіз әрекеттер кезекте сақталады.
4. Бес минуттан ескі әрекеттер кезектің басынан жойылады.
5. Бес сәтсіз әрекет шегіне жеткен кезде сол IP мекенжайы үшін алғашқы ескерту жасалады.

Детектор **жылжымалы уақыт терезесін (sliding time window)** пайдаланады. Бес минуттық аралық бекітілген уақыт блоктары бойынша емес, әрбір жаңа сәтсіз әрекетке қатысты есептеледі.

Дәл бес минуттық шекарадағы әрекет есепке алынады.

Сәтті кіру сәтсіз әрекеттер санағын нөлге түсірмейді.

## Шектеулер

- Тек оқу мақсатындағы лог форматы қолдау табады: `2026-09-16T10:00:00Z` сияқты UTC уақыт белгілері, IPv4 мекенжайлары және `Failed password` хабарламалары. Басқа жолдар еленбейді.
- Бұл әмбебап Linux лог-парсері емес.
- Файл толығымен жадта өңделеді; нақты уақыт режиміндегі мониторинг қарастырылмаған.
- Бір іске қосу кезінде әр IP мекенжайы үшін тек бір ескерту жасалады, тіпті кейін тағы бір күмәнді әрекеттер тізбегі орын алса да.
- Қайталанатын лог жолдары жеке кіру әрекеттері ретінде есептеледі.
- Ескерту жиі орын алған сәтсіз кіру әрекеттерін көрсетеді, бірақ шабуыл немесе жүйенің бұзылғанын дәлелдемейді.
- Бірнеше пайдаланушы ортақ IP мекенжайын қолданса, жалған ескерту пайда болуы мүмкін.
- Баяу немесе таратылған brute-force әрекеттері анықталмай қалуы мүмкін.
- Скрипт серверлерге қосылмайды және IP мекенжайларын автоматты түрде бұғаттамайды.

## Алғашқы жаттығу

`sample_auth.log` файлына жаңа IP мекенжайынан, мысалы `192.0.2.55`, бес минут ішінде төрт сәтсіз кіру әрекетін қосыңыз.

Детекторды іске қосыңыз.

Содан кейін бесінші сәтсіз әрекетті қосып, детекторды қайта іске қосыңыз.

Нәтиженің неліктен өзгергенін түсіндіріңіз.
