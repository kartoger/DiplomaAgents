# Единый формат логов

### Было
```
Apr 24 14:07:49 gdm-password: authentication failure for kartoger
Apr 24 14:08:10 sshd: Failed password for kartoger from 172.20.10.3
Apr 24 14:17:08  [MODIFY]: /home/kartoger/DiplomaAgents/delete/hell.txt [MODIFY] by kartoger
Apr 24 14:17:11  [MODIFY]: /home/kartoger/DiplomaAgents/delete/hell.txt [MODIFY] by kartoger
Apr 24 14:17:11  [MODIFY]: /home/kartoger/DiplomaAgents/delete/hell.txt [MODIFY] by kartoger
Apr 24 14:17:12  [MODIFY]: /home/kartoger/DiplomaAgents/delete/hell.txt [MODIFY] by kartoger
Apr 24 14:17:19  [DELETE]: /home/kartoger/DiplomaAgents/delete/hell.txt [DELETE] by kartoger
```

### Пример лога
```
[2025-04-24T14:17:19Z] [AA:BB:CC:DD:EE:FF] [file::delete] [kartoger] [/home/kartoger/DiplomaAgents/delete/hell.txt]
[2025-04-24T14:08:10Z] [AA:BB:CC:DD:EE:FF] [logon::failed] [kartoger] [172.20.10.3]
[2025-04-24T03:15:20Z] [AA:BB:CC:DD:EE:FF] [logon::after_hours] [john] [tty1]
[2025-04-24T14:20:02Z] [AA:BB:CC:DD:EE:FF] [net::suspicious_connection] [root] [212.34.12.55:4444]
```

### Структура
`[timestamp] [mac] [event] [user] [details]`
- `[timestamp]` - Временная метка события в формате ISO 8601 (например, 2025-04-24T14:17:19Z).
- `[mac]` - MAC-адрес устройства, на котором произошло событие.
- `[event]` - Тип события (например, file::delete). Сначала пишется название службы, затем два двоеточия и тип события.
Возможные значения:
  - gdm-password::Success
  - gdm-password::Failed
  - sshd::Success::Password
  - sshd::Success::PublicKey
  - sshd::Failed
  - file::Delete
  - file::Modify
- `[user]` - Имя пользователя, связанное с событием (например, kartoger).
- `[details]` - Дополнительные сведения о событии, такие как путь к файлу или IP-адрес (например, /home/kartoger/DiplomaAgents/delete/hell.txt).
