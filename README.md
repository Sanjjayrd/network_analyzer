# Cyberdome Vulnerability Intelligence Platform (CVIP) - React Redesign

This project is a massive architectural redesign of the CVIP application. It has been transformed from a monolithic Streamlit script into a modern, highly interactive **React Web Application**, drawing aesthetic inspiration from formal government portals (specifically referencing the JEE Main color palette: Saffron, White, Dark Blue, Green). 

## 🏗️ Architecture & Tech Stack

The application is now cleanly separated into a Frontend UI and a Backend REST API.

### 1. Frontend (React Web UI)
*   **Tech Stack:** React 18, Vite, React Router, Axios, and Lucide React (for icons).
*   **Styling:** Custom CSS leveraging modern web principles (glass-morphism, smooth hover animations, flexbox layouts) while adhering to a strict, classy government theme.
*   **Key Components & Flow:**
    *   **Login Portal (`/login`):** A secure, interactive entry point with animated cards.
    *   **Dashboard (`/dashboard`):** A comprehensive layout featuring a fixed top navigation band (with Kerala Police & Cyberdome logos), an animated News Ticker, and a dynamic Sidebar for all 13 legacy CVIP features.
    *   **Interactive Modules:**
        *   **Scan Targets:** Form inputs for IP addresses and intensity selection, complete with a simulated scanning progress bar.
        *   **Scan Results:** An animated data table that fetches and renders real JSON data from the backend.
        *   **Vulnerabilities:** A dynamic search engine for CVE IDs (e.g., CVE-2021-41773) that displays interactive remediation playbooks.
        *   **AI Remediation:** A fully functional Chat Assistant interface to communicate with the backend AI service.

### 2. Backend (API Server)
*   **Tech Stack:** Python, FastAPI, and Uvicorn.
*   **Role:** Replaces the legacy Streamlit logic. It serves as a high-performance REST API that the React frontend consumes.
*   **Active Endpoints:**
    *   `GET /api/dashboard`: Returns summary stats, recent scans, and security notifications.
    *   `GET /api/scans`: Returns the list of discovered hosts, open ports, and vulnerabilities.
    *   `GET /api/cve/{cve_id}`: Returns detailed descriptions and mitigation playbooks for a specific CVE.
    *   `POST /api/ai/chat`: Simulates LLM Assistant interactions for remediation advice.

## 🚀 How to Run the Application

A batch file has been provided to start both environments automatically.

1. Ensure the Python libraries (`fastapi`, `uvicorn`) and Node.js are installed.
2. Ensure you have run `npm install` inside the `web-ui` folder.
3. Double-click the **`start_cvip.bat`** file.

This will automatically:
- Launch the FastAPI server in the background.
- Launch the Vite React development server.
- Open your default web browser directly to the `http://localhost:5173/login` page.

## 🔌 Connecting Future Tools
Because the system is now decoupled, expanding its capabilities is straightforward:
1.  **Real Network Scans:** Modify the `/api/scans` route in `backend/main.py` to trigger an actual Nmap/Masscan subprocess, parsing the XML output into the JSON format expected by the frontend.
2.  **LLM Integration:** Connect the `/api/ai/chat` endpoint to the official OpenAI API or a local Ollama instance using their respective Python SDKs.
3.  **Database:** Swap out the mock Python dictionaries in the backend with SQLAlchemy to store historical scan data in SQLite or PostgreSQL.
