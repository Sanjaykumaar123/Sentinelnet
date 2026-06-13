# Setup Instructions

## Step 1: Initialize Database
The system uses SQLite by default (for easy local setup). The database file `sentinelnet.db` will be created automatically when you start the backend.

## Step 2: Create a User
1. Start the complete system using `run_dev.bat`.
2. Go to the API Documentation: [http://localhost:8000/docs](http://localhost:8000/docs).
3. Find the `POST /api/v1/auth/register` endpoint.
4. Click "Try it out" and enter:
   ```json
   {
     "email": "commander@sentinel.net",
     "password": "securepassword",
     "full_name": "Commander Shepard",
     "is_active": true,
     "is_superuser": true,
     "role": "admin"
   }
   ```
5. Click **Execute**.

## Step 3: Login to Frontend
1. Open the frontend: [http://localhost:3000](http://localhost:3000).
2. Click "Secure Login".
3. Enter the credentials you just created:
   - Email: `commander@sentinel.net`
   - Password: `securepassword`

## Database Configuration (PostgreSQL)
To switch to a production PostgreSQL database:
1. Copy `.env.example` to `.env` in the `backend` folder.
2. Update the `DATABASE_URL` with your connection string:
   `postgresql://user:password@localhost:5432/sentinelnet`
3. Restart the backend.

## 🧠 Running in Full AI/ML Transformer Mode (Local)
By default, the production deployment on serverless hosts (like Vercel) runs in **Enhanced Heuristics Mode** to comply with Vercel's 500MB function size limit (PyTorch + Hugging Face libraries exceed 4.7 GB).

To enable the full **RoBERTa-base AI Transformer Threat Model** locally:
1. Activate your virtual environment:
   ```bash
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
2. Install the additional ML packages:
   ```bash
   pip install -r requirements-ml.txt
   ```
3. Restart the backend. The startup logs will confirm: `✓ AI detection model loaded: roberta-base-openai-detector` and the dashboard will display **⚡ TRANSFORMER AI ACTIVE**.

