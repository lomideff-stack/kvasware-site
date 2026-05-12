# KvasWare Site (Python/Flask)

Flask-based website for KvasWare cheat management system.

## Features
- User authentication (login/register)
- Subscription management
- Admin panel
- API endpoints for loader
- DLL download system

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python app.py
```

Server will start at `http://localhost:5000`

## Deploy to Railway

1. Push to GitHub
2. Connect Railway to your repo
3. Railway will auto-detect Python and use:
   - `Procfile` for start command
   - `requirements.txt` for dependencies
   - `nixpacks.toml` for build configuration

### Environment Variables (Optional)
- `SECRET_KEY` - Flask secret key (auto-generated if not set)
- `PORT` - Port number (auto-set by Railway)

## Project Structure

```
kvasware-site-python/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── Procfile           # Railway start command
├── nixpacks.toml      # Build configuration
├── runtime.txt        # Python version
├── data/              # SQLite database (auto-created)
└── client_download/   # DLL files for download
```

## API Endpoints

- `POST /api/auth` - User authentication
- `POST /api/check` - Token validation
- `GET /client_download/<filename>` - Download DLL

## Admin Access

Default admin credentials:
- Username: `admin`
- Password: `admin`

**Change these immediately after first login!**
