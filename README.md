# 🛡️ Cowrie Honeypot Security Dashboard

An interactive cybersecurity monitoring dashboard developed using **Cowrie, Python, Streamlit, Pandas, and Plotly** to analyze SSH honeypot activity and visualize security events.

## Project Overview

This project demonstrates the deployment of a Cowrie SSH honeypot in a Kali Linux environment and the development of a web-based security monitoring dashboard.

Cowrie simulates an SSH service and records interactions such as login attempts, session activity, and commands entered by connected clients.

The dashboard processes Cowrie's JSON event logs and presents the information through interactive charts and monitoring panels.

## Features

- SSH honeypot deployment using Cowrie
- Monitoring of login attempts and SSH sessions
- Source IP address analysis
- Attacker command analysis
- Interactive charts using Plotly
- Log processing using Pandas
- Streamlit-based web interface
- Access from a browser on a trusted local network
- Custom dashboard styling

## Technology Stack

| Technology | Purpose |
|---|---|
| Kali Linux | Lab environment |
| Cowrie | SSH honeypot |
| Python | Log processing |
| Streamlit | Web dashboard |
| Pandas | Data analysis |
| Plotly | Interactive visualizations |
| Git and GitHub | Version control |

## Project Structure

```text
cowrie-honeypot-dashboard/
├── dashboard.py
├── requirements.txt
├── README.md
├── .gitignore
└── screenshots/
    └── dashboard.png
```

## Installation

### 1. Install and configure Cowrie

Follow the official Cowrie documentation:

https://docs.cowrie.org/

Ensure Cowrie is running and generating JSON logs.

### 2. Clone this repository

```bash
git clone https://github.com/YOUR_USERNAME/cowrie-honeypot-dashboard.git
cd cowrie-honeypot-dashboard
```

### 3. Create a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install dashboard dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure the log path

Update the Cowrie JSON log path in `dashboard.py` if your installation uses a different location.

Example:

```text
/home/cowrie/cowrie/var/log/cowrie/cowrie.json
```

### 6. Start the dashboard

```bash
streamlit run dashboard.py
```

Open:

http://localhost:8501

For access from another device on a trusted private network, configure Streamlit to listen on the appropriate network interface. Do not expose the dashboard publicly without authentication and other security controls.

## Dashboard Preview

![Cowrie Dashboard](screenshots/dashboard.png)

## Project Objectives

- Understand SSH honeypot technology
- Study suspicious login attempts and attacker behavior
- Learn cybersecurity log analysis
- Build interactive security visualizations
- Gain hands-on experience with Kali Linux and Python

## Future Improvements

- Automatic live refresh
- Advanced attack analytics
- Geographic IP visualization
- Security alert notifications
- Historical attack trends
- Secure dashboard authentication

## Disclaimer

This project is intended for educational purposes and authorized cybersecurity research in a controlled environment.

Never publish captured passwords, sensitive honeypot logs, or confidential network information.

## Author

Developed as a hands-on cybersecurity and security monitoring project.
