# Website AI - Project Architecture

## Overview
Website AI is a full-stack educational platform built with modern technologies. It provides an interactive AI-powered learning environment where students can upload documents, chat with an AI tutor, take generated quizzes, and track their progress over time.

## Tech Stack
### Frontend
- **Framework**: React 18, Vite
- **Styling**: Tailwind CSS
- **State Management**: React Query (Tanstack Query), Zustand
- **Authentication**: Supabase Auth (JWT, OAuth)
- **Deployment**: Vercel

### Backend
- **Framework**: FastAPI (Python 3.11)
- **Database**: PostgreSQL with pgvector
- **ORM**: SQLAlchemy 2.0 (Async) + Alembic
- **AI / LLMs**: Google Gemini Pro 1.5, DeepSeek
- **Vector Search**: pgvector HNSW index
- **Deployment**: Render

## Infrastructure & Data Flow
1. **Frontend Request**: The React app makes an API call to FastAPI, including the Supabase JWT in the `Authorization` header.
2. **Backend Auth**: FastAPI validates the JWT against Supabase's JWKS.
3. **Business Logic**: Depending on the route (e.g., AI chat, Document upload), FastAPI interacts with the LLM via LangChain/Google SDK, or queries PostgreSQL.
4. **Vector DB (RAG)**: For document Q&A, documents are parsed, chunked, and stored as embeddings in PostgreSQL (using `pgvector`). Similarity search is performed to retrieve context for the LLM.

## Repository Structure
- `frontend/`: React codebase.
- `backend/`: FastAPI codebase.
  - `app/`: Main application code (routers, schemas, models, services).
  - `tests/`: Pytest suite (unit, integration, e2e).
  - `scripts/`: Admin and utility scripts.
  - `alembic/`: Database migrations.
- `docs/`: Technical documentation.
