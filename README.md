# Travel-Assistance-TAS-

## Backend Setup (Windows PowerShell)

Set required environment variables (run once):

```powershell
setx MONGODB_URI "mongodb://localhost:27017"
setx DB_NAME "monsoon"
setx JWT_SECRET "change-this-secret"
setx google_cloud "YOUR_GOOGLE_ROUTES_API_KEY"
setx perplexity_api "YOUR_PERPLEXITY_API_KEY"
```

Install dependencies and run the API:

```powershell
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Notes:
- After using `setx`, restart your terminal so variables are available.
- Ensure MongoDB is running locally or update `MONGODB_URI` to your Atlas URI.

Backend
cd backend
fastapi dev main.py

Frontend
cd frontend
npm start