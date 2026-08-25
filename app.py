import streamlit as st
import streamlit.components.v1 as components
import os

st.set_page_config(
    page_title="BankSec Core | Banking Security Engine",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS overrides to hide Streamlit chrome and allow full screen custom web UI
st.markdown("""
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .block-container {
        padding-top: 0rem !important;
        padding-bottom: 0rem !important;
        padding-left: 0rem !important;
        padding-right: 0rem !important;
        max-width: 100% !important;
    }
    iframe {
        width: 100% !important;
        border: none !important;
    }
</style>
""", unsafe_allow_html=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def read_file(path):
    with open(os.path.join(BASE_DIR, path), 'r', encoding='utf-8') as f:
        return f.read()

index_html = read_file("index.html")
styles_css = read_file("styles.css")
framework_js = read_file("data/banking-framework.js")
app_js = read_file("app.js")

body_content = index_html.split("<body>")[1].split("</body>")[0]

full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BankSec Core</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
  {styles_css}
  </style>
</head>
<body>
  {body_content}
  <script>
  {framework_js}
  </script>
  <script>
  {app_js}
  </script>
</body>
</html>
"""

components.html(full_html, height=1400, scrolling=True)
