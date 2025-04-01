import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Generate timestamps for a 7-day period (every 30 minutes)
time_steps = pd.date_range(start="2024-01-01", periods=7*48, freq="30T")

# Simulate biomarker levels using sine waves + noise
np.random.seed(42)
sodium_levels = 140 + 2 * np.sin(np.linspace(0, 14*np.pi, len(time_steps))) + np.random.normal(0, 0.5, len(time_steps))
glucose_levels = 90 + 10 * np.sin(np.linspace(0, 14*np.pi, len(time_steps))) + np.random.normal(0, 5, len(time_steps))
potassium_levels = 4 + 0.2 * np.sin(np.linspace(0, 14*np.pi, len(time_steps))) + np.random.normal(0, 0.1, len(time_steps))

# Create DataFrame
df = pd.DataFrame({"Timestamp": time_steps, "Sodium": sodium_levels, "Glucose": glucose_levels, "Potassium": potassium_levels})

# Save to CSV
df.to_csv("synthetic_isf_data.csv", index=False)

# Plot example biomarker
plt.figure(figsize=(10,5))
plt.plot(df["Timestamp"], df["Sodium"], label="Sodium Level")
plt.plot(df["Timestamp"], df["Glucose"], label="Glucose Level", alpha=0.7)
plt.legend()
plt.xticks(rotation=45)
plt.title("Synthetic ISF Biomarker Data")
plt.show()