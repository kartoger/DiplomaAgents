##Логи
''[2025-05-08T13:12:15Z] [78:91:04:FA:22:11] [file::create] [john] [/home/john/Documents/report.txt]''
''[2025-05-08T13:12:17Z] [78:91:04:FA:22:11] [file::modify] [john] [/home/john/Documents/report.txt]''
''[2025-05-08T13:13:02Z] [78:91:04:FA:22:11] [file::delete] [john] [/home/john/Documents/report.txt]''
''[2025-05-08T13:14:20Z] [78:91:04:FA:22:11] [file::modify] [john] [/home/john/.config/dconf/user]''
''[2025-05-08T13:15:45Z] [78:91:04:FA:22:11] [file::modify] [root] [/etc/passwd]''
''[2025-05-08T13:15:48Z] [78:91:04:FA:22:11] [file::modify] [root] [/etc/shadow]''
''[2025-05-08T13:16:01Z] [78:91:04:FA:22:11] [file::delete] [kartoger] [/etc/cron.daily/oldjob]''
''[2025-05-08T13:17:33Z] [78:91:04:FA:22:11] [file::create] [kartoger] [/etc/systemd/system/malicious.service]''
''[2025-05-08T13:18:20Z] [78:91:04:FA:22:11] [file::modify] [kartoger] [/etc/ssh/sshd_config]''
''[2025-05-08T13:19:42Z] [78:91:04:FA:22:11] [file::create] [john] [/home/john/.bashrc]''


##Структура
Формат лога: '[timestamp] [MAC] [event_type] [user] [path]'
Тип события: 'file::create, file::modify, file::delete'
'[timestamp]' - Временная метка события.
'[mac]' - MAC-адрес устройства, на котором произошло событие.
'[event]' - Тип события (например, file::delete). Сначала пишется название службы, затем два двоеточия и тип события. Возможные значения:
file::create
file::Delete
file::Modify
'[user]' - Имя пользователя, связанное с событием (например, kartoger).
'[details]' - Дополнительные сведения о событии, такие как путь к файлу или IP-адрес (например, /home/john/Documents/report.txt).
