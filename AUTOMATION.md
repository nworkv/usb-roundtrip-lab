# Автоматический запуск с Raspberry

Первая версия: EP0 IN, без постоянного Windows-агента. Аппаратный прогон ещё
не выполнен. Для USB-части сначала настрой Raspberry по README.md.
Разовая настройка Windows обязательна; затем обычный запуск — только на Raspberry.

## Windows: один раз

Установи USBPcap >=1.5. В PowerShell от администратора:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
Get-NetFirewallRule -Name OpenSSH-Server-In-TCP
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
```

Ограничь входящий SSH доверенной сетью/IP Raspberry, не открывай в Интернет.
Настрой вход по SSH-ключу. Обычный пользователь: .ssh/authorized_keys в профиле.
Administrators по умолчанию: C:\ProgramData\ssh\administrators_authorized_keys
с ограниченными ACL (см. документацию Microsoft). Не отключай UAC ради теста.
Пользователь SSH должен иметь доступ к USBPcap/dumpcap именно из SSH-сеанса.

## Raspberry: один раз

```sh
sudo apt install -y openssh-client coreutils
ssh-keygen -t ed25519 -f ~/.ssh/usb_lab
cat ~/.ssh/usb_lab.pub
```

Установи публичный ключ в Windows. Приватный ключ не публикуй и не клади в Git.
Ключ с passphrase предварительно разблокируй в ssh-agent.
В ~/.ssh/config добавь (IP и пользователь — свои):

```sshconfig
Host usb-windows
    HostName 192.168.1.100
    User YOUR_WINDOWS_USER
    IdentityFile ~/.ssh/usb_lab
    IdentitiesOnly yes
```

Проверь fingerprint Windows при первом подключении, не отключай проверку ключа:

```sh
ssh usb-windows whoami
ssh -o BatchMode=yes usb-windows whoami
cd usb-roundtrip-lab
cp lab.example.json lab.json
make
make test
```

В lab.json:
- ssh_host — SSH alias.
- interface — пусто, если USBPcap-интерфейс один. Если несколько, укажи точное
  имя из dumpcap -D; обратные слеши в JSON удваиваются.
- seconds — длительность теста, 2..300.
- udc/driver — пусто для единственного UDC с совпадающим именем driver (dwc2).
  Для другой конфигурации укажи явно.

Wi-Fi/Ethernet управления не должны зависеть от тестируемого USB gadget.
Не отключай существующий gadget, через который идёт единственный SSH-доступ.
Используй отдельную тестовую Windows без важных данных.

## Каждый тест

Подключи device-mode USB-порт Raspberry к Windows. Из каталога проекта:

```sh
python3 autorun.py
# Другой case:
python3 autorun.py --case cases/vendor-ep0.json --config lab.json
```

Не запускай весь runner через sudo: SSH должен использовать конфиг твоего
пользователя. sudo будет использован только для gadget. Для запуска без запросов
предварительно выполни sudo -v и разблокируй SSH-ключ.

Runner сам собирает C-мост, запускает dumpcap по SSH, ждёт готовности capture,
запускает gadget с таймаутом, получает capture и сравнивает байты.
Windows-команда выполняется только на время теста. Wireshark GUI не нужен.
Capture передаётся по SSH в base64; временные файлы Windows удаляются.
Bus/Device определяется по уникальному совпадению ответа с device descriptor.
Артефакты: runs/<время>-<id>/ — sent.jsonl, capture.pcap, report.json и логи.
Коды выхода: 0 — MATCH и ожидаемое завершение gadget; 2 — различия/неопределённость;
3 — ошибка инфраструктуры. Синтаксис и офлайн-тесты не заменяют аппаратный прогон.

## Ограничения

Один запуск одновременно, один root hub, не более 16 MB capture.
При нескольких USBPcap-интерфейсах порт/root hub выбирается в конфиге один раз.
В захват может попасть трафик других устройств: не подключай чувствительные
устройства к тому же root hub. При достижении лимита capture закончится раньше.
Если два устройства имеют одинаковый descriptor, меняется адрес либо descriptor
не читается, runner сохраняет артефакты и не пытается угадать Bus/Device.
Нет bulk/HID-протокола, определения BSOD, аппаратного reset и перезапуска Windows.
Обрыв SSH означает ошибку наблюдения, не доказанный BSOD. Capture с упавшей
Windows может быть недоступен. У dumpcap свой таймаут; мгновенное завершение при
обрыве SSH не гарантируется. Gadget ограничен GNU timeout; зависший в ядре ioctl
может потребовать отключить USB/перезагрузить Raspberry.
Конфигурация UDC и существующие gadget автоматически не меняются.

## Документация

- https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
- https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
- https://www.wireshark.org/docs/man-pages/dumpcap.html
