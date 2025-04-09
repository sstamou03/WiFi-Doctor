#  Wi-Fi Doctor
# Wi-Fi Doctor – Part 1.1: Wi-Fi Network Density Analyzer

To evaluate Wi-Fi network density, we collected **two packet capture files** using Wireshark in monitor mode:

- `TUC.pcapng` – Captured in an **enterprise/campus** environment 
- `MyHome.pcapng` – Captured in a **residential/home** network environment

In the `WifiNetDensity.py` we have:

- `analyze_ap_signal_strength(pcap_file)` function that:
  - Parses the given `.pcapng` file using **PyShark**
  - Filters **beacon frames** (type/subtype 0x08) to extract essential fields 
  - Performs all necessary calculations to derive Wi-Fi channel characteristics
  - Computes a **Density Score** using a weighted formula based on penalties for:
    - Overlapping APs
    - RSSI
    - PHY type performance
  - Prints a detailed per-channel summary of each channel, along with its score.

This function is central to analyzing the **performance of wireless channels** in both **2.4 GHz** and **5 GHz** bands

- The `visualizer(data1, data2, label1="TUC", label2="MyHome")` function is used to generate the necessary plots for analysis such as:

  - **Density score per channel** for each `.pcapng` file
  - **Average signal strength (RSSI)** per channel for each file
  - **Number of overlapping APs** (BSSIDs) per channel
  - **Mean density score** for each .`pcapng` file



# Wi-Fi Doctor – Part 1.2: Wi-Fi Network Performance

We used the `HowIWiFi_PCAP.pcap` file to estimate the theoretical downlink throughput and identify performance bottlenecks by analyzing key metrics from the capture.

We also use the `ht_mcs_full_correct.json` file, which contains the  table from project reference [4].  
In `utils.py`, we read this file and convert it into a dictionary where:

- **Keys**: `(MCS index, bandwidth, spatial streams, short GI)`
- **Values**: `(data rate, required RSSI)`



In the `WifiNetPerfomance.py` we have:

- `pcap_parser(pcap_file)` function that:
  - Parses 802.11 **data frames** between a specific AP and device using **PyShark**
  - Extracts fields that we need.
  - Returns a list of parsed frames to use it in the project.


 - `performance_monitor(parsed_frames)` function that:
   - Calculates the **frame loss ratio** based on retry flags
   - Computes the **mean data rate** across all frames
   - Estimates the **throughput** using the formula:  
     **Throughput = Data Rate × (1 - Frame Loss Rate)**
   - Calculates the **Rate Gap** for each frame following Equation (1) from reference [3]


- `performance_analyzer(parsed_frames)` function that:
     - Analyzes the frame loss ratio and classifies the connection quality based on its severity
     - Calculates detailed frame-level statistics, such as:
       - Retry distribution (retransmissions)
       - Short Guard Interval (GI) usage
       - RSSI distribution across quality ranges
     - Adds comments to each frame, diving into:
       - RSSI quality and its expected impact on throughput
       - Retry frame causes
       - Short GI influence on data rate
       - Rate Gap interpretation (difference between theoretical PHY rate and achieved throughput)
       - MCS optimization opportunities based on signal strength
       - Identification of potential performance bottlenecks (e.g. interference, weak RSSI, congestion)
     - Prompts the user for detailed performance analysis per frame


- `visualizer(parsed_frames)` function that:
  - Plots a **time series of throughput** and prints key statistics (min / mean / median / 75th / 95th percentile / max)
  - Plots a **time series of RateGap**, and another one for the **normalized RateGap**
  - Plots **data rate per RSSI value**
  - Plots **mean throughput per PHY type**
  - Plots the **number of retry frames**
  - Plots the **distribution of Short GI** (True/False)
  - Plots the **number of frames per spatial stream count**
  - Plots the **distribution of frames across RSSI ranges**
  - Plots the **average throughput per bandwidth**
  - Plots the **mean throughput per Short GI setting**
  - Plots the **mean throughput per MCS index**
  - Prints the calculated **frame loss percentage**
  - Prints the **average normalized RateGap** across frames



For **privacy and security reasons**, the `.pcapng` files used in this project (e.g. `TUC.pcapng`, `MyHome.pcapng`) **are not included** in this repository.

To use the project, you will need to provide your own capture files.

You can easily generate them using tools like **Wireshark** or **tshark**.
