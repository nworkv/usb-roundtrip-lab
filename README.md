# usb-roundtrip-lab

Сравнение байтов EP0 IN: Raspberry Pi / Linux Raw Gadget → Windows USBPcap.
Собственного агента Windows нет. Захват вручную, сравнение офлайн на Linux.

## Статус и границы

Первая экспериментальная версия. Проверка сборки и синтетические unit-тесты
не заменяют проверку на Raspberry и Windows: аппаратный тест не выполнен.
Поддерживаются full-speed, EP0 maxpacket 64, GET_DESCRIPTOR и небольшой набор
стандартных запросов для примера с vendor-интерфейсом без endpoint'ов.
Нет bulk/interrupt/iso, HID-протокола, автоматического определения BSOD,
генератора произвольных полнофункциональных устройств или проверки драйвера.
Успешное сравнение означает совпадение данных наблюдаемых передач, НЕ успешный
запуск Windows-драйвера. Пример может остаться без драйвера — это допустимо.
VID/PID 1234:5678 — только локальный пример, не зарегистрированное назначение.
Не распространяйте устройства с чужими идентификаторами.

Raw Gadget — отладочный интерфейс. Используйте отдельный тестовый компьютер.
Не подключайте два host-порта; убедитесь в device-mode поддержке платы и
безопасном питании. Не используйте важные данные и составные storage-устройства.

## 1. Raspberry: подготовка

Нужен device-capable USB-порт и свободный UDC. Типовые платы — Pi Zero/Zero 2 W
(разъём USB, не PWR IN) или Pi 4 с подходящим device-mode подключением.
Для другой модели сначала проверьте её схему и документацию. Подключённые
ConfigFS/g_ether/g_serial gadget могут занимать UDC. Не отключайте gadget,
через который идёт единственный SSH-доступ: сначала настройте Wi-Fi/Ethernet.

```sh
sudo apt update
sudo apt install -y git build-essential linux-libc-dev python3
# Для конвертации pcapng на Linux, если нужна:
sudo apt install -y wireshark-common

git clone https://github.com/nworkv/usb-roundtrip-lab.git
cd usb-roundtrip-lab
make
make test
```

Репозиторий приватный: clone требует вашей GitHub-аутентификации.

Для dwc2-совместимой Raspberry добавьте в активную конфигурацию загрузки
(обычно /boot/firmware/config.txt, на старых образах /boot/config.txt):

```ini
[all]
dtoverlay=dwc2,dr_mode=peripheral
```

Не дублируйте существующие противоречащие overlay. Перезагрузитесь, затем:

```sh
sudo modprobe dwc2
sudo modprobe raw_gadget
ls -l /dev/raw-gadget
ls /sys/class/udc
```

Если raw_gadget не найден, ядру нужен CONFIG_USB_RAW_GADGET=m/y.
Это нельзя исправить установкой одной Python-библиотеки: используйте ядро
с поддержкой либо собирайте модуль для точной версии ядра.
Если UDC пуст, сначала решите проблему платы/порта/overlay.

## 2. Windows: запись

Wireshark сам по себе не гарантирует наличие USBPcap. В списке интерфейсов
должны быть USBPcap1, USBPcap2 и т.д. При необходимости добавьте USBPcap
через установщик Wireshark и перезагрузите Windows.

1. Узнайте, к какому USB root hub относится выбранный физический порт.
2. Запустите захват соответствующего USBPcap-интерфейса ДО старта эмулятора.
3. Используйте полный snap length, не capture-фильтр по VID/PID.
4. Подключите Raspberry data-кабелем через device-capable порт.
5. Запустите эмулятор из следующего раздела, подождите перечисления.
6. Остановите эмулятор, затем захват; сохраните один запуск в capture.pcapng.
7. В Wireshark выпишите Bus и Device address нужного устройства, включая
   неуспешно определившееся устройство. Значения нужны сравнителю.

Нужен USBPcap >=1.5 (SETUP stage 0 и COMPLETE stage 3).
Захватывайте один запуск и одну сессию адресации. При смене адреса устройства
анализируйте захваты/сессии отдельно; сравнитель не угадывает соответствие.

## 3. Raspberry: запуск

Для dwc2 имена driver/device обычно совпадают с именем в /sys/class/udc.
Для иных UDC driver может отличаться: смотрите raw-gadget документацию.
Скрипт ниже намеренно требует ровно один UDC:

```sh
cd usb-roundtrip-lab
mkdir -p runs
set -- /sys/class/udc/*
[ "$#" -eq 1 ] && [ -e "$1" ] || { echo 'Select a UDC manually'; exit 1; }
UDC=$(basename "$1")
sudo python3 gadget.py cases/vendor-ep0.json \
  --driver "$UDC" --device "$UDC" --log runs/sent.jsonl
```

Остановка: Ctrl+C. Закрытие Raw Gadget fd освобождает экземпляр gadget.
Лог создаётся эксклюзивно: для повтора выберите новое имя или переместите старый.
Если ioctl заблокировался в драйвере, может потребоваться отключение USB;
жёсткого watchdog в этой версии нет.

## 4. Сравнение

Скопируйте capture.pcapng с Windows на Linux (scp, флешка или сеть).
Конвертируйте встроенным в Wireshark editcap, не экспортируйте текст таблицы:

```sh
editcap -F pcap capture.pcapng runs/capture.pcap
python3 compare.py --log runs/sent.jsonl --pcap runs/capture.pcap \
  --bus 1 --device 2 --out runs/report.json
```

Замените 1/2 реальными Bus/Device из захвата. editcap можно запустить и на
Windows: & "C:\Program Files\Wireshark\editcap.exe" -F pcap capture.pcapng capture.pcap
Код выхода: 0 — все сравнимые передачи MATCH; 2 — есть иной результат.
Ошибки формата завершаются исключением, а не успешным пустым отчётом.

Отчёт: MATCH, CONTENT_MISMATCH, LENGTH_MISMATCH, WINDOWS_TRANSFER_ERROR,
LINUX_INCOMPLETE_OR_ERROR, LINUX_SHORT_COMPLETION,
WINDOWS_COMPLETION_NOT_OBSERVED, AMBIGUOUS_COUNT, NO_COMPARABLE_TRANSFERS.
first_difference — нулевое смещение первого отличия; для префикса — конец
более короткого массива.

## Как работает корреляция

C-мост использует UAPI-заголовок установленного Linux (ioctl не захардкожены).
Python пишет SETUP и submit ДО блокирующего ioctl, затем complete с его
результатом. Это различает намерение отправить от завершения передачи.
Файлы журналов fsync-ятся для сохранения последних событий.
Сравнитель связывает USBPcap SETUP/COMPLETE по IRP ID, а с Linux — по точным
8 байтам SETUP и порядку одинаковых запросов. При несовпадении числа повторов
возвращается AMBIGUOUS_COUNT, а не выдуманное побайтовое соответствие.
Одинаковое число повторов всё ещё требует полного захвата одной сессии:
без сквозного ID абсолютное доказательство соответствия невозможно.

Полный дескриптор обрезается до wLength для конкретного ответа.
JSON-ключ: type:index:language, числа в десятичном виде или с префиксом 0x.
Неизвестные запросы получают STALL. String-дескрипторы не заданы в примере;
индексы строк device descriptor равны нулю.
SET_ADDRESS может обслуживаться UDC и отсутствовать в журнале userspace.
Не все начальные транзакции доступны USBPcap; отсутствие записи не доказывает
потерю данных. На физическом уровне токены/ACK/CRC не сравниваются.

## Источники интерфейсов

- https://docs.kernel.org/usb/raw-gadget.html
- https://desowin.org/usbpcap/captureformat.html
- https://desowin.org/usbpcap/capture_limitations.html

## Дальнейшее расширение

Добавлять endpoint'ы следует вместе с EPS_INFO, выбором совместимых endpoint'ов,
EP_ENABLE и реализацией протокола. Просто вписать HID/bulk-дескрипторы в JSON
недостаточно. Для определения падений Windows понадобятся отдельные дампы
и/или внешнее наблюдение: USB-захват сам этого не доказывает.
