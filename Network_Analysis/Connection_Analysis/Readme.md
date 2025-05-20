# 📊 IP Connection Log Analysis

This project analyzes IP connection logs to distinguish between **legitimate** and **malicious** traffic. The analysis includes visualizations for comparing traffic types, services accessed, and time-based trends — both static and interactive charts are generated using Matplotlib and Plotly.

## 🗂️ Project Structure


## 📌 Features

- **Bar chart** of total legitimate vs. malicious connections.
- **Service access chart** comparing services targeted by each IP type.
- **Time series chart** showing hourly activity trends (interactive with Plotly).
- Automatic saving of static `.png` files and interactive `.html` file.

## 📈 Visualizations

### 1. Legit vs Malicious Connections
A bar chart showing the total number of connections per IP type.

### 2. Services Accessed
A grouped bar chart showing which services (like HTTP, FTP, SSH) are most accessed by each IP type.

### 3. Hourly Connection Activity (Interactive)
A time series chart showing connection frequency over time, resampled hourly — rendered interactively using Plotly.

![Example](./1_legit_vs_malicious.png)

## 🔧 Requirements

Install the necessary Python libraries:

```bash
pip install pandas matplotlib plotly

▶️ How to Run
Place your connection_logs.csv file in the project directory.

Run the main script:

bash
python connection_analysis.py
S
tatic plots (.png) will be saved in the same directory.

The interactive chart (3_hourly_activity.html) will automatically open in your browser and can be shared.

📑 Sample CSV Structure
Your connection_logs.csv should have at least the following columns:

timestamp	label	service_accessed
2025-05-20 10:00:00	legit	HTTP
2025-05-20 10:15:00	malicious	SSH

👨‍💻 Author
Melvin Kwame Awuku
💻 Ethical Hacker | IT Support Analyst | Cybersecurity Enthusiast
