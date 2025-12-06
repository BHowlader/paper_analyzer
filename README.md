# Research Paper Analysis API
A powerful API to extract insights, methodology, and key findings from research papers using AI.

## Features
- 📄 **PDF Upload**: Extract text from research papers.
- 🧠 **AI Analysis**: Uses OpenAI (GPT-4) to extract structured data.
- 📊 **Structured Output**: Returns JSON with Title, Abstract, Methodology, Results, Conclusions, Key Findings, and Citations.
- 📈 **Usage Tracking**: Logs all analysis requests to a SQLite database.
- 🎨 **Modern UI**: Includes a beautiful frontend for easy interaction.

## Setup

1.  **Clone the repository**
2.  **Create a virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
4.  **Configure Environment**:
    - Copy `.env.example` to `.env`
    - Add your `OPENAI_API_KEY`
    ```bash
    cp .env.example .env
    # Edit .env
    ```
5.  **Run the Server**:
    ```bash
    uvicorn app.main:app --reload
    ```
6.  **Access the App**:
    - Open [http://localhost:8000](http://localhost:8000)

## API Documentation
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## Tech Stack
- **Backend**: FastAPI, Python
- **AI**: OpenAI API
- **PDF Parsing**: PyPDF2
- **Database**: SQLite (SQLAlchemy)
- **Frontend**: HTML, TailwindCSS
# Trigger deployment
# Using PostgreSQL
