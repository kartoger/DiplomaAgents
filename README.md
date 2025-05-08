## 1.FileMonitoring

## Логи
```
[2025-05-08T13:12:15Z] [78:91:04:FA:22:11] [file::create] [john] [/home/john/Documents/report.txt]
[2025-05-08T13:12:17Z] [78:91:04:FA:22:11] [file::modify] [john] [/home/john/Documents/report.txt]
[2025-05-08T13:13:02Z] [78:91:04:FA:22:11] [file::delete] [john] [/home/john/Documents/report.txt]
[2025-05-08T13:14:20Z] [78:91:04:FA:22:11] [file::modify] [john] [/home/john/.config/dconf/user]
[2025-05-08T13:15:45Z] [78:91:04:FA:22:11] [file::modify] [root] [/etc/passwd]
[2025-05-08T13:15:48Z] [78:91:04:FA:22:11] [file::modify] [root] [/etc/shadow]
[2025-05-08T13:16:01Z] [78:91:04:FA:22:11] [file::delete] [kartoger] [/etc/cron.daily/oldjob]
[2025-05-08T13:17:33Z] [78:91:04:FA:22:11] [file::create] [kartoger] [/etc/systemd/system/malicious.service]
[2025-05-08T13:18:20Z] [78:91:04:FA:22:11] [file::modify] [kartoger] [/etc/ssh/sshd_config]
[2025-05-08T13:19:42Z] [78:91:04:FA:22:11] [file::create] [john] [/home/john/.bashrc]
```

## Структура
```
Формат лога: [timestamp] [MAC] [event_type] [user] [path]
Тип события: file::create, file::modify, file::delete
[timestamp] - Временная метка события в формате ISO-8601. Например: [2025-05-08T13:13:02Z]
[mac] - MAC-адрес устройства, на котором произошло событие. например: [78:91:04:FA:22:11]
[event] - Тип события (например, file::delete). Сначала пишется название службы, затем два двоеточия и тип события. Возможные значения:
file::create создание нового файла.
file::Delete удаление файла.
file::Modify изменение файла.
[user] - Имя пользователя, связанное с событием (например, kartoger).
[details] - Дополнительные сведения о событии, такие как путь к файлу или IP-адрес (например, /home/john/Documents/report.txt).
```
## 2.For_SSH_GDM

## Логи
```
[2025-05-08T11:03:21Z] [78:91:04:FA:22:11] [gdm-password::Success] [kartoger] [local GUI login]
[2025-05-08T11:05:42Z] [78:91:04:FA:22:11] [gdm-password::Failed] [kartoger] [local GUI login]
[2025-05-08T11:10:01Z] [78:91:04:FA:22:11] [sshd::Success::Password] [john] [192.168.0.10:58212]
[2025-05-08T11:11:13Z] [78:91:04:FA:22:11] [sshd::Failed] [InvalidUser:admin] [192.168.0.11:47650]
[2025-05-08T11:12:49Z] [78:91:04:FA:22:11] [sshd::Success::PublicKey] [devops] [192.168.0.12:51432]
```
## Cтруктура
```
[timestamp] - 2025-05-08T11:10:01Z Временная метка события в формате ISO 8601 (UTC)
[mac] - 78:91:04:FA:22:11 MAC-адрес устройства, полученный из файла (/sys/class/net/enp3s0/address).
[event] - gdm-password::Success - означает успешную авторизацию пользователя через графический дисплей-менеджер GDM (GNOME Display Manager) с использованием метода gdm-password.
[sshd::Failed] - Тип события, определяемый на основе текста сообщения MESSAGE в journalctl. Состоит из источника (gdm-password, sshd и т.д.) и статуса (Success, Failed, Password, PublicKey).
[user] - kartoger - имя пользователя
[InvalidUser:admin] - Имя пользователя, извлекаемое из сообщения. В случае неправильного имени (например, при ssh попытке под несуществующим юзером) добавляется префикс InvalidUser:.
[details] - local GUI login - Локальный вход пользователя в систему через графический интерфейс (GUI) — то есть, пользователь физически подошёл к компьютеру и вошёл в него через экран входа (например, GDM, LightDM, SDDM и т.п.), а не по сети (не через SSH, RDP и т.д.).
[192.168.0.12:51432] - Дополнительная информация: IP и порт при входе по SSH или описание вроде local GUI login для GDM-сессий.
```

## 3.For SCAN_Users

## Логи
```
[2025-05-08T13:37:12Z] [78:91:04:FA:22:11] [system::Acitve_Terminals] [john] [Terminal: tty1, LoginTime: 2025-05-08T13:12:40Z]
[2025-05-08T13:37:12Z] [78:91:04:FA:22:11] [system::Acitve_Terminals] [kartoger] [Terminal: pts/0 IP: 192.168.1.15, LoginTime: 2025-05-08T13:13:55Z]
[2025-05-08T13:37:12Z] [78:91:04:FA:22:11] [system::Acitve_Terminals] [admin] [Terminal: pts/2 IP: 10.0.0.5, LoginTime: 2025-05-08T13:20:10Z]
```
## Структура
```
[timestamp] - (2025-05-08T13:37:12Z)	Время, когда была вызвана функция логирования. Формируется через getTimestamp1().
[mac] - (78:91:04:FA:22:11)	MAC-адрес устройства. Получается через getMacAddress2() из /sys/class/net/enp3s0/address.
[event] - (system::Acitve_Terminals)	Тип события. Указывается явно в коде как system::Acitve_Terminals (возможно, стоит исправить опечатку на Active_Terminals).
[user] - (john) - Имя пользователя, взятое из поля ut_user структуры utmp.
[details] - (Terminal: pts/0 IP: 192.168.1.12, LoginTime: 2025-05-08T13:35:01Z)	Дополнительные сведения: имя терминала (ut_line), IP (если есть, из ut_host) и время входа (ut_tv.tv_sec) в формате ISO 8601.
```
## 4.For_USB

## Логи 
```
2025-05-08T14:20:01Z | MAC: | IP: | event: device | type: Add_USB | user: | details: /dev/sdb (VID:PID=0781:5583)
2025-05-08T14:20:02Z | MAC: | IP: | event: device | type: Mounted | user: | details: Source:/dev/sdb1 Target:/media/user/SANDISK
2025-05-08T14:20:03Z | MAC: | IP: | event: device | type: ExecutableFound | user: | details: /media/user/SANDISK/setup.sh
2025-05-08T14:20:03Z | MAC: | IP: | event: device | type: ExecutableFound | user: | details: /media/user/SANDISK/bin/install
2025-05-08T14:23:45Z | MAC: | IP: | event: device | type: Unmounted | user: | details: From:/media/user/SANDISK
2025-05-08T14:23:46Z | MAC: | IP: | event: device | type: Remove_USB | user: | details: /dev/sdb (VID:PID=0781:5583)
```
## Структура
```
 [timestamp] - Время события в формате ISO 8601 (UTC). Например:[2025-05-08T13:01:12Z]                                                 
 [event]  - Категория события: `device` Пример: [device::Add_USB]
  device::Add_USB - означает, что было подключено USB-устройство
  device::Mounted - это событие, которое фиксирует момент, когда устройство (например, флешка) было смонтировано в файловую систему.
  device::ExecutableFound -  это событие, которое фиксирует факт обнаружения исполняемого файла на только что смонтированном устройстве (например, USB-флешке).
  device::Unmounted - это событие, которое регистрирует момент отключения (размонтирования) устройства от файловой системы, например, когда извлекают USB-флешку.
  device::Remove_USB -    это событие, которое регистирует момент удаления или отключения USB-устройства из системы, например, когда физически извлекается флешка, внешнее хранилище или любое другое USB-устройство.                                        
 [type]   -    Тип события: `Add_USB`, `Remove_USB`, `Mounted`, `Unmounted`, `ExecutableFound`                                    
 [details]  - Подробности события: путь к устройству, точка монтирования, VID/PID и т.п.      

```
## 5.For_ALL
## Логи
```
[2025-05-08T14:03:21Z] [34:17:eb:ba:01:af] [system::Start] [user123] [System monitoring started]
[2025-05-08T14:04:10Z] [34:17:eb:ba:01:af] [device::USB_Inserted] [user123] [Device: /dev/sdb1 (VID:PID=0781:5581)]
[2025-05-08T14:04:22Z] [34:17:eb:ba:01:af] [device::Mounted] [user123] [Source:/dev/sdb1 Target:/media/user123/USB_DRIVE]
[2025-05-08T14:07:45Z] [34:17:eb:ba:01:af] [device::ExecutableFound] [user123] [/media/user123/USB_DRIVE/runme.sh]
[2025-05-08T14:08:00Z] [34:17:eb:ba:01:af] [device::Unmounted] [user123] [From:/media/user123/USB_DRIVE]
```
## Структура
```

| Поле         | Описание                                                                     |
| ------------ | ---------------------------------------------------------------------------- |
| `timestamp`  | Метка времени в формате ISO8601 (UTC), например: `2025-05-08T14:03:21Z`      |
| `mac`        | MAC-адрес интерфейса (здесь: `enp3s0`)                                       |
| `event_name` | Категория события, например: `system`, `device`, `user`                      |
| `event_type` | Тип события, например: `Mounted`, `USB_Inserted`, `ExecutableFound`          |
| `username`   | Имя пользователя, под которым работает процесс (получено через `getlogin()`) |
| `details`    | Детали события: путь к устройству, путь к файлу, VID/PID, и т.п.             |
```
## 6.File Access
## Логи
```
1.Создание файла:
[2025-05-08T12:34:56Z] [08:00:27:ab:cd:ef] [file::create] [user] [/home/user/new_file]
2. Удаление файла:
[2025-05-08T12:35:56Z] [08:00:27:ab:cd:ef] [file::delete] [user] [/etc/hosts]
3.Изменение файла:
[2025-05-08T12:36:56Z] [08:00:27:ab:cd:ef] [file::modify] [user] [/home/user/important_file]
4.Игнорируемое событие (например, временный файл):
[2025-05-08T12:37:56Z] [08:00:27:ab:cd:ef] [file::unknown] [user] [/home/user/.vim/swapfile]
5.Ошибка при добавлении наблюдения за директорией:
[WARN] Ошибка добавления /home/user/.cache: Permission denied
6.Ошибка при обходе директории:
[WARN] Ошибка обхода /home/user/.config: Permission denied
```
## Структура
```
timestamp — метка времени события в формате ISO 8601 (UTC). Например:
2025-05-08T12:34:56Z
mac_address — MAC-адрес сетевого интерфейса, например:
08:00:27:ab:cd:ef
event_type — тип события:
file::create — создание нового файла.
file::delete — удаление файла.
file::modify — изменение файла.
file::unknown — неизвестное событие.
username — имя пользователя, которому принадлежит файл. Получается через getpwuid() для UID владельца файла.
file_path — полный путь к файлу или каталогу, с которым связано событие:
/home/user/new_file
/etc/hosts
/home/user/important_file
```
