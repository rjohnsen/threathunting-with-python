"""
Introduction sample for manual Threat Hunting using Python

This Python script is written as a demo on how to manually parse
a big log file using simple tools such as Python, Dask, and Streamlit.
It also server as a POC on how to use alternative tools other than
Jupyter Notebooks.

This script handles parsing of Zeek log of roughly ~3GB size.

Author: Roger Johnsen
Date: 31.10.2021

Resources:

Log dump:
https://www.secrepo.com/maccdc2012/conn.log.gz

Bro logs cheat sheet:
https://github.com/corelight/bro-cheatsheets/blob/master/Corelight-Bro-Cheatsheets-2.6.pdf

Column mapping:
https://docs.zeek.org/en/master/log-formats.html
"""

from multiprocessing.pool import ThreadPool
import dask
import dask.dataframe as dd
import streamlit as st

dask.config.set(pool=ThreadPool(50))

def run():
    """
    Run and display log data
    """
    logset = open_log("./conn.log")

    st.write("# Zeek log")
    st.write("## Head (3) of log")
    st.write(logset.head(3))

    st.write("## Metrics")

    # Display traffic distribution pr. day
    st.write("### Traffic distribution pr. day")
    day_traffic = logset.groupby(by=logset['ts'].dt.day)["proto"].count().compute()
    st.write("#### Diagram")
    st.bar_chart(day_traffic)

    st.write("#### Statistics")
    st.write(day_traffic)

    # Display protocols
    render_unique("Protocols", logset, "proto")

    # Display services
    render_unique("Services", logset, "service")

    # Display Connection States
    render_unique("Connection States", logset, "conn_state")


def render_unique(title, frame, column_name):
    """
    Helper function to render log data
    """
    dataset = get_unique(frame, column_name)
    st.write(f"### {title}")

    st.write("#### Diagram")
    st.bar_chart(dataset)

    st.write("#### Statistics")
    st.dataframe(dataset)

def get_unique(frame, column_name):
    """
    Helper function to get unique count for column
    """
    return frame[column_name].value_counts().compute()

def open_log(log_path: str):
    """
    Open log and import it to data frame
    """

    # Column mapping
    columns = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "missed_bytes",
        "history",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
        "unknown1",
        "unknown2",
        "unknown3"
    ]

    # Indicate which column(s) that we have no interest in analysing
    drop_columns = [
        "uid",
        "missed_bytes",
        "unknown1",
        "unknown2",
        "unknown3",
        "history"
    ]

    data_frame = dd.read_csv(log_path, delimiter="\t", names=columns).drop(drop_columns, axis=1)
    data_frame['ts']=dd.to_datetime(data_frame.ts, unit='s')

    return data_frame.persist()

if __name__ == "__main__":
    with st.spinner('Processing the log'):
        run()

    st.balloons()
