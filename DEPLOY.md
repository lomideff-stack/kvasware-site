# 🚀 Инструкция по деплою на Railway

## ✅ Что уже настроено

Все необходимые файлы созданы и настроены:

- ✅ `Procfile` - команда запуска через gunicorn
- ✅ `requirements.txt` - Flask 3.0.3 + gunicorn 23.0.0
- ✅ `runtime.txt` - Python 3.11
- ✅ `nixpacks.toml` - конфигурация сборки
- ✅ `app.py` - порт настроен через `os.environ.get("PORT")`
- ✅ `.gitignore` - исключает базу данных из git

## 📋 Шаги для деплоя

### 1. Закоммитить изменения

```bash
cd kvasware-site-python
git add .
git commit -m "Configure for Railway deployment"
git push
```

### 2. В Railway Dashboard

1. Зайдите в ваш проект на Railway
2. Нажмите **"New Deployment"** или подождите авто-деплоя
3. Railway автоматически:
   - Обнаружит Python проект
   - Установит зависимости из `requirements.txt`
   - Запустит через команду из `Procfile`

### 3. Проверка логов

В Railway → ваш сервис → **Deployments** → выберите последний деплой

Должны увидеть:
```
✓ Building...
✓ Installing dependencies from requirements.txt
✓ Starting service...
✓ [INFO] Starting gunicorn 23.0.0
✓ [INFO] Listening at: http://0.0.0.0:XXXX
```

## 🔧 Если возникла ошибка

### Ошибка: "No module named gunicorn"
**Решение:** Проверьте, что `gunicorn==23.0.0` есть в `requirements.txt`

### Ошибка: "cannot find 'app'"
**Решение:** Убедитесь, что в `app.py` есть строка `app = Flask(__name__)`

### Ошибка: "Address already in use"
**Решение:** Проверьте, что используется `$PORT` из окружения:
```python
PORT = int(os.environ.get("PORT", 5000))
app.run(host='0.0.0.0', port=PORT)
```

### Ошибка: "Build failed"
**Решение:** Проверьте логи сборки в Railway. Возможно:
- Неправильная версия Python в `runtime.txt`
- Ошибка в `requirements.txt`
- Синтаксическая ошибка в `app.py`

## 🌐 После успешного деплоя

1. Railway предоставит URL вида: `https://your-app.railway.app`
2. Откройте URL в браузере
3. Должна открыться главная страница KvasWare
4. Войдите в админку:
   - Username: `admin`
   - Password: `admin`
   - **Сразу смените пароль!**

## 📊 Мониторинг

В Railway Dashboard можете:
- Смотреть логи в реальном времени
- Проверять использование ресурсов (CPU, RAM)
- Настроить переменные окружения
- Перезапустить сервис

## 🔐 Безопасность

После деплоя обязательно:
1. Смените пароль админа
2. Добавьте переменную окружения `SECRET_KEY` в Railway:
   ```
   SECRET_KEY=your-super-secret-key-here-change-this
   ```

## 💾 База данных

SQLite база создаётся автоматически в папке `data/`.
Railway сохраняет её между деплоями.

**Важно:** Для продакшена рекомендуется использовать PostgreSQL вместо SQLite.

## 🆘 Поддержка

Если проблемы остались:
1. Проверьте логи деплоя в Railway
2. Убедитесь, что все файлы закоммичены в git
3. Проверьте, что деплоите из правильной ветки
