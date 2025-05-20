import pandas as pd
import plotly.express as px
import plotly.io as pio

# Avoid localhost error
pio.renderers.default = 'iframe'  # Use 'iframe_connected' if preferred

# Load data
df = pd.read_csv(r'C:\Users\Lenovo\Desktop\Folders\My_Basic_To_Advanced_Python_Projects\Refreshed_Python_Projects\connection_logs.csv')

# Ensure timestamp is datetime
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Split datasets (optional)
malicious_df = df[df['label'] == 'malicious']
legit_df = df[df['label'] == 'legit']

# ---- Plot 1: Legit vs Malicious Counts ----
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import matplotlib.ticker as ticker

plt.figure(figsize=(8, 5))
df['label'].value_counts().plot(kind='bar', color=['red', 'green'])
plt.title('Legit vs Malicious IP Connections')
plt.xlabel('Type of IP')
plt.ylabel('Number of Connections')
plt.xticks(rotation=0)
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.tight_layout()
plt.savefig("1_legit_vs_malicious.png")
plt.show()

# ---- Plot 2: Services Accessed by Each Type ----
service_counts = df.groupby(['label', 'service_accessed']).size().unstack().fillna(0)

service_counts.T.plot(kind='bar', figsize=(10, 6), color=['green', 'red'])
plt.title('Services Accessed by Legit vs Malicious IPs')
plt.xlabel('Service Accessed')
plt.ylabel('Number of Connections')
plt.xticks(rotation=45)
plt.legend(title='IP Type')
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.tight_layout()
plt.savefig("2_services_accessed.png")
plt.show()

# ---- Plot 3: Time Series of Connections (Interactive) ----
# Resample hourly and count labels
df_hourly = df.set_index('timestamp').resample('h')['label'].value_counts().unstack().fillna(0).reset_index()

# Create interactive line chart
fig = px.line(
    df_hourly,
    x='timestamp',
    y=['legit', 'malicious'],
    title='Hourly Connection Activity',
    labels={'value': 'Number of Connections', 'timestamp': 'Time'},
)

# Customize layout
fig.update_layout(
    xaxis=dict(
        tickformat='%b %d\n%H:%M',
        title='Time'
    ),
    yaxis_title='Number of Connections',
    legend_title='IP Type',
    hovermode='x unified',
    template='plotly_white',
    autosize=True,
)

# Show the interactive plot (opens in iframe)
fig.show()

# Optional: Save as HTML for manual viewing
fig.write_html(r'C:\Users\Lenovo\Desktop\Folders\My_Basic_To_Advanced_Python_Projects\Refreshed_Python_Projects\3_hourly_activity.html', auto_open=True)
