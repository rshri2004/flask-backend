import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Generate timestamps for a 24-hour period (every second)
time_steps = pd.date_range(start="2024-01-01", periods=24*60*60, freq="S")

# Base sinusoidal sodium variation over 24 hours
np.random.seed(42)
sodium_levels = 140 + 2 * np.sin(np.linspace(0, 2*np.pi, len(time_steps))) + np.random.normal(0, 0.5, len(time_steps))

# Add contextual events (meal sodium impact, dehydration)
meal_times = np.random.choice(len(time_steps), size=5, replace=False)  # 5 random meal times
sodium_levels[meal_times] += np.random.uniform(2, 5, len(meal_times))  # Meal sodium spike

dehydration_start = np.random.randint(0, len(time_steps) - 3600)  # 1-hour dehydration period
sodium_levels[dehydration_start:dehydration_start+3600] += np.linspace(0, 5, 3600)  # Gradual increase

# Create DataFrame
df = pd.DataFrame({"Timestamp": time_steps, "Sodium_Level": sodium_levels})

# Save to CSV
df.to_csv("synthetic_sodium_data.csv", index=False)

# Plot example
plt.figure(figsize=(12,5))
plt.plot(df["Timestamp"][:86400], df["Sodium_Level"][:86400], label="Sodium Level (First Hour)")
plt.xticks(rotation=45)
plt.legend()
plt.title("Synthetic Sodium Levels Over 24 Hours")
plt.show()