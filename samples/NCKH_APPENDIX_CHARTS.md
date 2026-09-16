# Phụ Lục Biểu Đồ NCKH

Tài liệu này bổ sung các biểu đồ trực quan để dùng kèm báo cáo kỹ thuật chính. Nội dung được trích theo source code hiện tại của dự án.

## 1. Bản Đồ API Tổng Hợp

```mermaid
mindmap
  root((API))
    Auth
      GET /api/v1/auth/me
    Users
      GET /api/v1/users/profile
      POST /api/v1/users/sync
      POST /api/v1/users/avatar
      PUT /api/v1/users/profile
      GET /api/v1/users/gpa
      POST /api/v1/users/gpa
    Workspaces
      GET /api/v1/workspaces/
      POST /api/v1/workspaces/
      DELETE /api/v1/workspaces/{workspace_id}
    Documents
      POST /api/v1/documents/
      GET /api/v1/documents/
      GET /api/v1/documents/{doc_id}
      GET /api/v1/documents/{doc_id}/status
      DELETE /api/v1/documents/{doc_id}
    AI
      POST /api/v1/ai/summarize
      POST /api/v1/ai/summarize-multiple
      POST /api/v1/ai/generate-quiz
      POST /api/v1/ai/generate-mindmap
      POST /api/v1/ai/chat
      POST /api/v1/ai/explain
      POST /api/v1/ai/grade
      GET /api/v1/ai/chat/history
    Progress
      GET /api/v1/progress/
      POST /api/v1/progress/time
      DELETE /api/v1/progress/
    Roadmap
      POST /api/v1/roadmap/generate
      GET /api/v1/roadmap/list
      GET /api/v1/roadmap/timeline/list
      PUT /api/v1/roadmap/stage/{stage_id}/progress
    Analysis
      GET /api/v1/analysis/
    Admin
      GET /api/v1/admin/analytics/overview
      GET /api/v1/admin/analytics/overview/stream
      GET /api/v1/admin/analytics/tokens
      GET /api/v1/admin/analytics/providers
      GET /api/v1/admin/analytics/errors
      GET /api/v1/admin/analytics/users
      GET /api/v1/admin/analytics/ingestion
```

## 2. Kiến Trúc Triển Khai

```mermaid
flowchart LR
    Dev["Developer / Local env"] --> Compose["Docker Compose"]
    Compose --> API["api"]
    Compose --> DB["db: PostgreSQL"]
    Compose --> Redis["redis"]
    Compose --> Worker["worker: ARQ"]
    API --> Uploads["./uploads volume"]
    Worker --> Uploads
```

## 3. Luồng Upload Và Ingestion

```mermaid
sequenceDiagram
    participant U as Người dùng
    participant FE as Frontend
    participant API as FastAPI
    participant S as Document Service
    participant W as ARQ Worker
    participant V as PGVector
    participant DB as PostgreSQL

    U->>FE: Chọn file và workspace
    FE->>API: POST /api/v1/documents/
    API->>S: Validate file, tạo metadata
    S->>DB: Lưu documents status=UPLOADING
    S->>W: Enqueue ingest_document
    W->>W: Extract -> Chunk -> Embed
    W->>V: aadd_documents(chunks)
    W->>DB: Cập nhật progress/status
    DB-->>API: Document updated
    API-->>FE: DocumentResponse
```

## 4. Pipeline AI RAG

```mermaid
flowchart TD
    Q["User question"] --> D["Document / workspace context"]
    D --> F["filtered_content"]
    D --> R["Vector retrieval"]
    F --> P["Prompt builder"]
    R --> P
    P --> M{"LLM provider"}
    M --> G["Gemini"]
    M --> K["DeepSeek"]
    G --> V["Pydantic validate"]
    K --> V
    V --> O["Structured response"]
```

## 5. Dashboard Analytics

```mermaid
flowchart TB
    Admin["Admin"] --> API["/api/v1/admin/analytics/*"]
    API --> TS["Token usage over time"]
    API --> PU["Provider usage"]
    API --> IM["Ingestion metrics"]
    API --> AU["Active users"]
    API --> EM["Error metrics"]
    API --> BS["Budget summary"]
    API --> TC["Top consumers"]
    TS --> Chart1["Line chart"]
    PU --> Chart2["Pie / donut chart"]
    IM --> Chart3["Bar / stacked chart"]
    AU --> Chart4["Area chart"]
    EM --> Chart5["Table / heatmap"]
    BS --> Chart6["KPI cards"]
    TC --> Chart7["Ranking table"]
```

## 6. Gợi Ý Dùng Trong NCKH

- Chèn biểu đồ API tổng hợp vào phần tổng quan hệ thống.
- Chèn biểu đồ upload-ingestion vào phần thiết kế backend.
- Chèn biểu đồ RAG vào phần pipeline AI.
- Chèn biểu đồ analytics vào phần giá trị vận hành và đánh giá hệ thống.

