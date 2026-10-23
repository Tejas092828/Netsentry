# NETSENTRY — Network Traffic Intelligence & Intrusion Response

**Course:** Computer Networks Laboratory (CSE20110)  
**Academic Year:** 2026–2027  
**Institution:** MIT World Peace University, Pune  
**Repository:** CN-Lab-2026-27

## 1. Team Details

- **Team 5:** 
- **Panel:** E
- **Batch:** E2
- **Faculty:** Dr. Swati

| Team Member | PRN | Contribution |
|---|---|---|
| Tejas Jadhav | 1272250848 | Update with actual source changes, testing or documentation. |
| Ruturaj Parit | 1272250843 | Update with actual source changes, testing or UI work. |
| Rajas Patil | 1272250847 | Update with actual testing, report or presentation work. |


## 2. Project Overview

NETSENTRY is an educational network-monitoring prototype that generates synthetic network-event records, evaluates configurable rule-based detection logic, organizes detections into incidents, and presents the results through a web dashboard.

The project demonstrates how a client communicates with a backend service using HTTP requests and JSON responses. It is intended for controlled simulation and learning, not as a production intrusion detection system.

## 3. Problem Statement

Network monitoring can generate large numbers of events, making suspicious patterns difficult to identify manually. NETSENTRY demonstrates a basic workflow for generating event data, identifying selected patterns using rules, presenting evidence, and recording simulated response actions.

## 4. Objectives

1. Simulate network activity such as port scans, SYN bursts, DNS spikes, repeated authentication failures, outbound-volume anomalies, and traffic spikes.
2. Apply rule-based checks to identify selected suspicious patterns.
3. Present detections, severity, supporting evidence, incidents, and metrics.
4. Demonstrate communication between a web client and a REST API.
5. Record response dry-run actions without changing firewall configuration.

## 5. Computer Networks Concepts

- Client-server architecture
- HTTP request and response
- REST API communication
- JSON data exchange
- TCP and UDP traffic concepts
- DNS activity and port scanning
- Network-event monitoring and rule-based detection
- Incident handling and audit logging

Network activity is simulated; the application does not capture live packets unless such functionality is separately implemented.

## 6. Technology Stack

| Component | Technology |
|---|---|
| Frontend | React and Vite |
| Backend | Python and FastAPI |
| ASGI server | Uvicorn |
| Communication | HTTP and JSON |
| Backend API port | 8000 |
| Frontend development port | 5173 |
| Data storage | In-memory application state |

Record the actual installed Python, Node.js, npm, and package versions used for the submission.

## 7. Project Structure

- `backend/app/main.py` — backend API entry point.
- `backend/app/engine.py` — simulation and detection logic.
- `backend/requirements.txt` — Python dependencies.
- `frontend/src/App.jsx` — frontend application.
- `frontend/package.json` — frontend dependencies and scripts.
- `samples/` — sample test cases and expected results.
- `screenshots/` — actual screenshots captured during testing.
- `docs/` — final report and presentation.

## 8. Prerequisites

Install the following software:

- Python version compatible with the backend dependencies.
- Node.js and npm versions compatible with the frontend dependencies.
- Git.

## 9. Installation and Execution

### Step 1: Clone the repository

```bash
git clone https://github.com/<YOUR_USERNAME>/CN-Lab-2026-27.git
cd CN-Lab-2026-27/NETSENTRY
```

### Step 2: Start the backend

Open a terminal in the project directory:

```bash
cd backend
python -m venv .venv
```

Activate the environment on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies and start the API:

```bash
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify the health endpoint:

```text
http://127.0.0.1:8000/api/health
```

Keep this terminal running.

### Step 3: Start the frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, normally:

```text
http://localhost:5173
```

Keep both the backend and frontend running. If the frontend cannot reach the API, check that the backend is running and that its CORS configuration permits the frontend origin.

## 10. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Check API health |
| GET | `/api/events` | Retrieve event records |
| GET | `/api/incidents` | Retrieve incidents |
| GET | `/api/metrics` | Retrieve monitoring metrics |
| POST | `/api/simulations/run` | Run a simulation |
| POST | `/api/response/dry-run` | Demonstrate a response action without applying firewall changes |

Consult the source code for the exact request schema and response format.

## 11. Testing

The following scenarios form the test plan:

| Test | Input/Action | Expected Behaviour |
|---|---|---|
| API health | Request `/api/health` | API returns a health response |
| Port scan | Run a port-scan simulation | Port-diversity rule is evaluated |
| SYN burst | Run a SYN-burst simulation | Configured threshold is evaluated |
| DNS spike | Run a DNS-spike simulation | DNS activity is checked against its rule |
| Authentication failures | Run the relevant simulation | Matching events and evidence are recorded |
| Incident display | Trigger a detection | Incident information appears when generated |
| Response dry-run | Submit a dry-run action | Audit entry is recorded without firewall changes |
| Input validation | Submit an event count outside the allowed range | Invalid input is rejected |

**Test results:** Record the actual observed output and mark each test Pass, Fail, or Not Tested. Include screenshots in `screenshots/`. Do not report an expected result as a successful observed result without running the test.

## 12. Limitations

- Events are synthetic rather than captured from live network interfaces.
- Application state is held in memory and may reset when the backend restarts.
- Detection uses simple rules and may produce false positives or miss suspicious activity.
- The prototype is not a replacement for a production security monitoring system.

## 13. Future Improvements

- Add authorized live packet capture.
- Introduce configurable detection windows and thresholds.
- Add persistent storage and user authentication.
- Evaluate detection quality against labelled datasets.
- Add additional protocols, dashboards, and exportable incident reports.

## 14. Demonstration

**YouTube demonstration:** https://youtu.be/xYXLgqoOIAw

The demonstration should show application startup, a simulation run, the resulting events and detections, incident evidence, and the response dry-run audit record.

## 15. References and Attribution

- FastAPI documentation: https://fastapi.tiangolo.com/
- React documentation: https://react.dev/
- Vite documentation: https://vite.dev/
- Python documentation: https://docs.python.org/3/

Include attribution and links for any reused code, diagrams, datasets, or other resources.

## 16. Submission Documents

- `docs/NETSENTRY_Final_Report.pdf`
- `docs/NETSENTRY_Presentation.pptx`
- Editable source code and dependency files
- Actual screenshots and test evidence
