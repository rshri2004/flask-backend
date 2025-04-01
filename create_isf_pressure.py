import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Generate timestamps for a 24-hour period (every second)
time_steps = pd.date_range(start="2024-01-01", periods=24*60*60, freq="S")

# Base sinusoidal interstitial fluid pressure variation over 24 hours
np.random.seed(42)
isf_pressure = -3 + np.sin(np.linspace(0, 2*np.pi, len(time_steps))) + np.random.normal(0, 0.2, len(time_steps))

# Add contextual event: gradually increased pressure from 18th to 20th hour
event_start = 18 * 60 * 60  # Start at the 18th hour
event_end = 20 * 60 * 60    # End at the 20th hour
isf_pressure[event_start:event_end] += np.linspace(0, 8, event_end - event_start)

# Add contextual event: increased pressure from 20th to 24th hour
event2_start = 20 * 60 * 60  # Start at the 20th hour
event2_end = 24 * 60 * 60    # End at the 24th hour
isf_pressure[event2_start:event2_end] = np.random.uniform(4, 6, event2_end - event2_start)

# Create DataFrame
df = pd.DataFrame({"Timestamp": time_steps, "ISF_Pressure": isf_pressure})

# Save to CSV
df.to_csv("synthetic_isf_pressure.csv", index=False)

# Plot example
plt.figure(figsize=(12,5))
plt.plot(df["Timestamp"], df["ISF_Pressure"], label="ISF Pressure Over 24 Hours")
plt.axvspan(time_steps[event_start], time_steps[event_end-1], color='red', alpha=0.3, label="Pressure Increase Event")
plt.xticks(rotation=45)
plt.legend()
plt.title("Synthetic Interstitial Fluid Pressure Over 24 Hours")
plt.show()