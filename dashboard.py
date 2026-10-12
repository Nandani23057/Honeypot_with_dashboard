
import json
from pathlib import Path
from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st

# -----------------------------------------
# Configuration
# -----------------------------------------
LOG_FILE = Path(
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
)

COLORS = {
    "cream": "#FDFBD4",
    "beige": "#D9D7B6",
    "gray": "#878672",
    "olive": "#505037",
}

st.set_page_config(
    page_title="Cowrie Honeypot Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# -----------------------------------------
# Dashboard styling
# -----------------------------------------
st.markdown(
    """
    <style>
    .stApp {
        background-color: #FDFBD4;
        color: #505037;
    }

    h1, h2, h3, p, label {
        color: #505037 !important;
    }

    [data-testid="stMetric"] {
        background-color: #D9D7B6;
        border: 1px solid #878672;
        border-radius: 12px;
        padding: 18px;
    }

    [data-testid="stMetricValue"] {
        color: #505037;
    }

    [data-testid="stSidebar"] {
        background-color: #D9D7B6;
    }

    .stButton button {
        background-color: #505037;
        color: #FDFBD4;
        border-radius: 8px;
        border: none;
    }

    .stButton button:hover {
        background-color: #878672;
        color: #FDFBD4;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------
# Read Cowrie JSON events
# -----------------------------------------
def load_events():
    events = []

    if not LOG_FILE.exists():
        return events

    with LOG_FILE.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        for line in file:
            try:
                event = json.loads(line)

                if isinstance(event, dict):
                    events.append(event)

            except json.JSONDecodeError:
                continue

    return events


def prepare_dataframe(events):
    if not events:
        return pd.DataFrame()

    df = pd.DataFrame(events)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce",
            utc=True,
        )

    return df


def style_chart(fig):
    fig.update_layout(
        paper_bgcolor=COLORS["cream"],
        plot_bgcolor=COLORS["cream"],
        font_color=COLORS["olive"],
        margin=dict(l=20, r=20, t=35, b=20),
    )

    fig.update_xaxes(gridcolor=COLORS["beige"])
    fig.update_yaxes(gridcolor=COLORS["beige"])

    return fig


# -----------------------------------------
# Sidebar
# -----------------------------------------
st.sidebar.title("🛡️ Cowrie SOC")
st.sidebar.write("SSH Honeypot Monitoring")
st.sidebar.divider()

refresh = st.sidebar.button("🔄 Refresh Events")

if refresh:
    st.rerun()

st.sidebar.info(
    "Dashboard data is read from local Cowrie JSON logs."
)

# -----------------------------------------
# Main dashboard
# -----------------------------------------
st.title("🛡️ Cowrie Honeypot Dashboard")
st.caption("SSH Attack Monitoring & Security Analytics")

events = load_events()
df = prepare_dataframe(events)

if df.empty:
    st.warning(
        "No Cowrie events found. Check your JSON log path "
        "and make sure Cowrie is generating events."
    )
    st.stop()

event_counts = Counter(
    str(e.get("eventid", "")) for e in events
)

sessions = {
    e.get("session")
    for e in events
    if e.get("session")
}

login_attempts = sum(
    count
    for event_id, count in event_counts.items()
    if event_id.startswith("cowrie.login.")
)

commands = event_counts.get("cowrie.command.input", 0)

source_ips = [
    e["src_ip"]
    for e in events
    if e.get("src_ip")
]

unique_ips = len(set(source_ips))

# -----------------------------------------
# Metrics
# -----------------------------------------
m1, m2, m3, m4 = st.columns(4)

m1.metric("Total Sessions", len(sessions))
m2.metric("Login Events", login_attempts)
m3.metric("Commands Captured", commands)
m4.metric("Unique Source IPs", unique_ips)

st.divider()

# -----------------------------------------
# Analytics
# -----------------------------------------
left, right = st.columns(2)

with left:
    st.subheader("Top Source IPs")

    if source_ips:
        ip_counts = Counter(source_ips).most_common(10)

        ip_df = pd.DataFrame(
            ip_counts,
            columns=["Source IP", "Events"],
        )

        fig = px.bar(
            ip_df,
            x="Events",
            y="Source IP",
            orientation="h",
            color_discrete_sequence=[COLORS["olive"]],
        )

        fig.update_layout(
            yaxis={"categoryorder": "total ascending"}
        )

        st.plotly_chart(
            style_chart(fig),
            use_container_width=True,
        )
    else:
        st.info("No source IP data available.")

with right:
    st.subheader("Event Types")

    counts = Counter(
        e.get("eventid", "unknown") for e in events
    )

    event_df = pd.DataFrame(
        counts.most_common(8),
        columns=["Event Type", "Count"],
    )

    fig = px.bar(
        event_df,
        x="Count",
        y="Event Type",
        orientation="h",
        color_discrete_sequence=[COLORS["gray"]],
    )

    fig.update_layout(
        yaxis={"categoryorder": "total ascending"}
    )

    st.plotly_chart(
        style_chart(fig),
        use_container_width=True,
    )

# -----------------------------------------
# Login usernames
# -----------------------------------------
st.subheader("Most Attempted Usernames")

usernames = [
    e.get("username")
    for e in events
    if str(e.get("eventid", "")).startswith("cowrie.login.")
    and e.get("username")
]

if usernames:
    username_df = pd.DataFrame(
        Counter(usernames).most_common(10),
        columns=["Username", "Attempts"],
    )

    st.dataframe(
        username_df,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No login usernames recorded.")

# -----------------------------------------
# Captured commands
# -----------------------------------------
st.subheader("Captured SSH Commands")

command_events = [
    {
        "Timestamp": e.get("timestamp", ""),
        "Source IP": e.get("src_ip", ""),
        "Command": e.get("input", ""),
    }
    for e in events
    if e.get("eventid") == "cowrie.command.input"
]

if command_events:
    st.dataframe(
        pd.DataFrame(command_events).tail(30).iloc[::-1],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No commands captured yet.")

# -----------------------------------------
# Recent activity
# -----------------------------------------
st.subheader("Recent Security Events")

recent_events = [
    {
        "Timestamp": e.get("timestamp", ""),
        "Event": e.get("eventid", ""),
        "Source IP": e.get("src_ip", ""),
        "Session": e.get("session", ""),
    }
    for e in events[-50:]
]

st.dataframe(
    pd.DataFrame(recent_events).iloc[::-1],
    use_container_width=True,
    hide_index=True,
)

st.caption(
    "Educational cybersecurity project | "
    "Cowrie SSH Honeypot | Streamlit"
)
