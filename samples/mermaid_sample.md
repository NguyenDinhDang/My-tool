# Huong Dan Su Dung Mermaid Diagrams

## Gioi thieu

Mermaid la ngon ngu de ve diagram bang code. Khi chuyen sang Word, cac diagram nay se duoc render thanh hinh anh neu may co `mmdc` hoac co ket noi internet.

---

## 1. Flowchart

```mermaid
flowchart TD
    A[Start] --> B{Kiem tra}
    B -->|Yes| C[Process A]
    B -->|No| D[Process B]
    C --> E[End]
    D --> E
```

## 2. Sequence Diagram

```mermaid
sequenceDiagram
    participant User
    participant Server
    participant Database
    User->>Server: Login Request
    Server->>Database: Query User
    Database-->>Server: User Data
    Server-->>User: Login Success
```

## 3. Gantt Chart

```mermaid
gantt
    title Project Timeline
    section Development
    Setup :a1, 2024-01-01, 7d
    Design :a2, after a1, 10d
    Implementation :a3, after a2, 20d
    Testing :a4, after a3, 5d
```

## 4. Pie Chart

```mermaid
pie title My Skills Distribution
    "Python" : 40
    "JavaScript" : 30
    "SQL" : 20
    "Other" : 10
```

## 5. Class Diagram

```mermaid
classDiagram
    class Animal {
        +String name
        +Int age
        +speak()
    }
    class Dog {
        +bark()
    }
    class Cat {
        +meow()
    }
    Animal <|-- Dog
    Animal <|-- Cat
```

## 6. State Diagram

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Processing: Start
    Processing --> Success: Complete
    Processing --> Error: Fail
    Success --> [*]
    Error --> Idle: Retry
```

## Luu y

- Can ket noi internet de render diagram bang Mermaid Ink neu chua cai Mermaid CLI.
- Neu khong render duoc, cong cu se nhung source Mermaid vao Word.
- Ho tro flowchart, sequence, gantt, pie, class, state va cac loai Mermaid pho bien khac.

## Cach Su Dung

Viet ma Mermaid trong khoi code:

````markdown
```mermaid
flowchart TD
    A --> B
```
````

Chay convert:

```bash
python agi.py md2word samples/mermaid_sample.md
```
