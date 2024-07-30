import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


df = pd.read_csv("ip.csv", names=["id", "address", "identifier", "service", "tarpit", "time", "timespan"])
df["timespan"] = pd.to_timedelta(df["timespan"]).dt.total_seconds()

tarpit = []
method = ["banner", "kex"]
for m in method:
    tarpit.append(df["timespan"].where(df["tarpit"] == m).dropna().reset_index(drop=True))


fig = plt.figure(figsize=(24, 10))
axs = fig.subplots(1, 2)

ax = axs[0]
ax.set_yscale("log")
ax.set_ylabel("Time in s", fontsize=18)
ax.set_xlabel("Type of tarpit", fontsize=18)
ax.set_title("Connection time for clients", fontsize=24)

for t in [60, 600, 3600, 7200]:
    ax.hlines(t, 0, len(method)+1, color="black", linewidth=0.2)
    ax.text(0.3, t, "{} min".format(int(t/60)), horizontalalignment="center")

ax.boxplot(tarpit, showmeans=True, meanline=True, widths=0.5, medianprops=dict(color="black"), meanprops=dict(color="black"))
ax.set_xticks(range(1, len(method)+1), ["{} n={}".format(m, len(t)) for t, m in zip(tarpit, method)], fontsize=12)

for i, t in enumerate(tarpit):
    ax.text(i+1, t.mean(), "mean: {} min".format(round(t.mean()/60, 2)), horizontalalignment="center")
    ax.text(i+1, t.median(), "med: {} min".format(round(t.median()/60, 2)), horizontalalignment="center")
    ax.text(i+1, t.max(), "max: {} h".format(round(t.max()/3600, 2)), horizontalalignment="left")

ax = axs[1]
ax.set_yscale("log")
ax.set_ylabel("Number of connections", fontsize=18)
ax.set_xlabel("Time in s", fontsize=18)
ax.set_title("Histogram connection time", fontsize=24)

ax.hist(tarpit, bins=25, color=["#"+6*"{}".format(hex(int(i))[2:]) for i in np.linspace(10, 1, len(method))], label=method)
ax.legend()

plt.show()
