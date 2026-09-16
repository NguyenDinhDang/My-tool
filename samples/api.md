# Website AI - API Documentation

## Overview
The backend provides a RESTful API with FastAPI. Swagger UI documentation is available locally at `/docs` when the backend server is running.

## Base URL
- **Local**: `http://localhost:8000/api/v1`
- **Production**: Hosted on Render

## Key Endpoints

### Authentication (`/auth`)
Authentication is handled by Supabase, so most local auth endpoints are removed.
- `GET /auth/me`: Validate the Supabase JWT and return the synchronized user profile from our PostgreSQL database.

### Users (`/users`)
- `GET /users/me`: Get current user details.
- `PUT /users/me`: Update user profile.
- `POST /users/sync`: Triggered during/after Supabase login to ensure the Supabase user exists in the local DB.

### Documents & RAG (`/documents`)
- `POST /documents/`: Upload a new PDF/Word document for ingestion and embedding.
- `GET /documents/`: List all uploaded documents for the user.
- `GET /documents/{id}`: Get document metadata.
- `DELETE /documents/{id}`: Delete a document and its embeddings.

### Workspaces (`/workspaces`)
- `POST /workspaces/`: Create a new workspace.
- `GET /workspaces/`: List workspaces.
- `POST /workspaces/{id}/chat`: Send a message to the AI tutor within the context of a workspace and its linked documents.

### AI & Quizzes (`/ai`)
- `POST /ai/chat`: Standalone AI chat.
- `POST /ai/quiz`: Generate a quiz based on a given topic or document context.
- `POST /ai/summarize`: Summarize text or documents.

### Progress Tracking (`/progress`)
- `GET /progress/`: Get user statistics (total documents, quizzes, accuracy, study minutes).
- `DELETE /progress/`: Reset user progress.

### Admin (`/admin`)
- `GET /admin/analytics/overview/stream`: SSE stream for live admin dashboard metrics.
- `GET /admin/users`: List all users (admin only).
