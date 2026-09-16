# Deployment Guide

This project is configured to be deployed on **Render** (Backend) and **Vercel** (Frontend).

## Backend (Render)
1. Link your GitHub repository to a new **Web Service** in Render.
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Environment Variables required:
   - `DATABASE_URL`
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_JWT_SECRET`
   - `GEMINI_API_KEY`

## Frontend (Vercel)
1. Link your GitHub repository to Vercel.
2. Root Directory: `frontend`
3. Build Command: `npm run build`
4. Install Command: `npm install`
5. Environment Variables:
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
   - `VITE_API_URL` (points to your Render URL)
