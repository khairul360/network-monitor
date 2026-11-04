import sqlite3, time
import pandas as pd
import streamlit as st

st.set_page_config(page_title="DNS Monitor", layout="wide")
st.title("🛡️ Home DNS Monitor")

def load(query):
    con = sqlite3.connect("alerts.db")
    try:
        return pd.read_sql(query, con)
    except Exception:
        return pd.DataFrame()
    finally:
        con.close()

alerts = load("SELECT * FROM alerts ORDER BY ts DESC")
queries = load("SELECT * FROM queries")

st.sidebar.header("Filters")
auto = st.sidebar.checkbox("Auto-refresh (5s)", value=False)
sev_options = ["high", "medium", "low"]
sev = st.sidebar.multiselect("Severity", sev_options, default=sev_options)

if not alerts.empty:
    alerts = alerts[alerts["severity"].isin(sev)]

c1, c2, c3 = st.columns(3)
c1.metric("DNS queries seen", len(queries))
c2.metric("Alerts", len(alerts))
c3.metric("High severity", int((alerts["severity"] == "high").sum()) if not alerts.empty else 0)

left, right = st.columns(2)

with left:
    st.subheader("Alerts by rule")
    if alerts.empty:
        st.info("No alerts yet.")
    else:
        st.bar_chart(alerts["description"].value_counts())

    st.subheader("Alerts over time")
    if not alerts.empty:
        t = pd.to_datetime(alerts["ts"])
        st.line_chart(alerts.set_index(t).resample("1min").size())

with right:
    st.subheader("Top queried domains")
    if queries.empty:
        st.info("No queries logged yet.")
    else:
        st.bar_chart(queries["domain"].value_counts().head(10))

st.subheader("Alert log")
st.dataframe(alerts, use_container_width=True, hide_index=True)

if auto:
    time.sleep(5)
    st.rerun()
