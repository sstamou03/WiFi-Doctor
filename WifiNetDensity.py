import sys
import matplotlib.pyplot as plt
import pyshark
import numpy as np
import pandas as pd
from collections import defaultdict

'''======================================================PCAP PARSER - ANALYZER========================================================================'''


def hex_ssid_to_string(hex_ssid):
    hex_str = hex_ssid.replace(":", "")
    return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')


def analyze_ap_signal_strength(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='wlan.fc.type_subtype == 0x08')

    # to defaultdict ap_data einai gia kathe ena AP.
    # To defaultdict leitourgei etsi: An pame na valoume ena key pou DEN einai mesa, tote automata tha dimiourgisoume
    # mia nea kataxwrish, pou periexei ena SET bssids, ena LIST rssi_values, ena SET phy_types (krataei ola ta diaforetika phy pou exoun perasei apo to kanali),
    # kai duo metavlites avg_rssi kai overlap_count
    channel_data = defaultdict(lambda: {
                    'bssids': set(),
                    'rssi_values' : [],
                    'phy_types' : set(),
                    'avg_rssi' : None,
                    'overlap_count' : None
    })

    summarized_channel_data = {} #edw tha mpoun ola mazi gia kathe kanali sto telos, gia na kanoume avoid to defaultdict gia ton visualizer

    # to dictionary gia to penalty pou tha prosthetei sto congestion score to prwtokollo pou xrhsimopoioume
    phy_weights = {
        '4': 10,  # 802.11b — worst
        '5': 8,  # 802.11a — better, alla arketa outdated
        '6': 7,  # 802.11g — idio PHY me 802.11a (ofdm) , alla 2.4 GHz
        '7': 4,  # 802.11n — good, diathetei MIMO
        '8': 2,  # 802.11ac — sxetika moderno kai grigoro
        '9': 1  # 802.11ax — best
        #ta upoloipa twra den tha ta kanoume alla an diathetei kapoios kaluterh karta feel free to change it
    }

    overlap_norm = 10
    rssi_norm = 100
    phy_norm = 10

    for packet in cap:
        try:
            hex_ssids = getattr(packet['wlan.mgt'], 'wlan_ssid', 'Hidden SSID')
            ssid = hex_ssid_to_string(hex_ssids)
            bssid = getattr(packet['wlan'], 'bssid', None)
            rssi = getattr(packet['wlan_radio'], 'signal_dbm', None)
            channel = getattr(packet['wlan_radio'], 'channel', None)
            phy = getattr(packet['wlan_radio'], 'phy', None)

            if bssid and rssi and channel:
                rssi = int(rssi)  # Convert RSSI to integer
                channel = int(channel)

                channel_data[channel]['bssids'].add(bssid)
                channel_data[channel]['rssi_values'].append(rssi)  # append giati to rssi_values einai lista
                channel_data[channel]['phy_types'].add(phy)

        except AttributeError:
            continue

    cap.close()

    for channel in channel_data.keys():
        rssi_values = channel_data[channel]['rssi_values']
        channel_data[channel]['avg_rssi'] = (sum(rssi_values) / len(rssi_values)) if rssi_values else None
        channel_data[channel]['overlap_count'] = len(channel_data[channel]['bssids']) if channel else None

    # Calculate and display average signal strength per AP per SSID
    for channel, data in channel_data.items():
        overlap_count = channel_data[channel]['overlap_count']
        phy = data['phy_types']
        avg_rssi = data['avg_rssi']


        # ta varh, den exei kathe tomeas idia shmasia
        if channel <= 13: #2.4GHz
            w_overlap = 1
            w_rssi = 1
        else: #5GHz
            w_overlap = 0.30
            if avg_rssi > -55: #cases gia to w_ssid
                w_rssi = 0.5
            elif -67 < avg_rssi <= -55:
                w_rssi = 1
            elif -75 < avg_rssi <= -67:
                w_rssi = 1.5
            else:
                w_rssi = 2.0

        phy_score = max(phy_weights[str(p)] for p in phy if str(p) in phy_weights)
        density_score = w_overlap * (overlap_count / overlap_norm) + (phy_score / phy_norm) + w_rssi * (abs(avg_rssi / rssi_norm))

        # summary tou AP sto dictionary
        summarized_channel_data[channel] = {
            'avg_rssi': round(avg_rssi, 2) if avg_rssi is not None else None,
            'overlapping_APs': overlap_count,
            'phy_types': phy,
            'density_score': density_score,
        }

    sorted_summary = dict(sorted(
        summarized_channel_data.items(),
        key=lambda item: item[1]['density_score']
    ))
    for channel, data in sorted_summary.items():
        print(
            f"Channel {channel:<3} | "
            f"Overlapping APs (BSSIDs) : {data['overlapping_APs']:<4} | "
            f"Avg RSSI: {data['avg_rssi']:>6.2f} dBm | "
            f"Phy Types: {', '.join(str(p) for p in data['phy_types']):<5} | "
            f"Density Score: {data['density_score']:>5.2f}"
        )

    return sorted_summary


'''======================================================Visualizer========================================================================'''


def visualize_density_scores(data1, data2, label1="File 1", label2="File 2"):

# ========== PLOT 1 - DENSITY SCORES PER CHANNEL ====================
    fig, axs = plt.subplots(1, 2, figsize=(14, 5), sharey=True)
    for ax, data, label in zip(axs, [data1, data2], [label1, label2]):
        # Extract channels and scores
        channels = list(data.keys())
        scores = [data[ch]['density_score'] for ch in channels]

        # Just enumerate the bars to space them evenly
        x_positions = list(range(len(channels)))

        # Plot bars
        bars = ax.bar(x_positions, scores, color='royalblue', edgecolor='black')

        # Annotate each bar with score
        for i, (bar, score) in enumerate(zip(bars, scores)):
            ax.text(bar.get_x() + bar.get_width() / 2, score + 0.05, f"{score:.2f}",
                    ha='center', va='bottom', fontsize=8)

        # Set labels and titles
        ax.set_title(f"Density Scores — {label}", fontsize=13)
        ax.set_xlabel("Channels", fontsize=11)
        ax.set_ylabel("Density Score", fontsize=11)
        ax.grid(axis='y', linestyle='--', alpha=0.3)

        # Set custom tick labels to show actual channel numbers
        ax.set_xticks(x_positions)
        ax.set_xticklabels([str(ch) for ch in channels], rotation=0)

    plt.tight_layout()
    plt.show()

# ===================== PLOT 2 =================================
    def group_and_average(data):
        band_scores = {'2.4GHz': [], '5GHz': []}
        for ch, stats in data.items():
            if ch <= 13:
                band_scores['2.4GHz'].append(stats['density_score'])
            else:
                band_scores['5GHz'].append(stats['density_score'])

        means = {
            band: (sum(scores) / len(scores)) if scores else 0
            for band, scores in band_scores.items()
        }
        return means


    means1 = group_and_average(data1)
    means2 = group_and_average(data2)

    fig, axs = plt.subplots(1, 2, figsize=(10, 5), sharey=True)

    for ax, means, label in zip(axs, [means1, means2], [label1, label2]):
        bands = list(means.keys())
        values = list(means.values())
        bars = ax.bar(bands, values, color=['cornflowerblue', 'lightsalmon'], edgecolor='black')

        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, val + 0.05, f"{val:.2f}",
                    ha='center', va='bottom', fontsize=9)

        ax.set_title(f"Mean Density Score per Frequency Band — {label}")
        ax.set_ylabel("Density Score")
        ax.set_ylim(0, max(values) + 1)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        ax.set_yticks([])
        ax.set_yticklabels([])

    plt.tight_layout()
    plt.show()

# ========== PLOT 3 =======================
def plot_avg_rssi_per_channel_comparison(data1, data2, label1="Network 1", label2="Network 2"):
    def process_data(summary_data):
        sorted_data = sorted(
            summary_data.items(),
            key=lambda item: item[1]['avg_rssi'] if item[1]['avg_rssi'] is not None else float('-inf'),
            reverse=True
        )
        channels = [item[0] for item in sorted_data]
        foo_rssi = [item[1]['avg_rssi'] for item in sorted_data]
        avg_rssi = [x + 100 if x is not None else None for x in foo_rssi]
        bar_heights = [abs(rssi) if rssi is not None else 0 for rssi in avg_rssi]
        return channels, bar_heights, avg_rssi

    channels1, bar_heights1, avg_rssi1 = process_data(data1)
    channels2, bar_heights2, avg_rssi2 = process_data(data2)

    x_positions1 = np.arange(len(channels1)) * 1.5
    x_positions2 = np.arange(len(channels2)) * 1.5

    fig, axs = plt.subplots(1, 2, figsize=(14, 6), sharey=True)

    # Plot 1
    bars1 = axs[0].bar(x_positions1, bar_heights1, color='mediumseagreen', edgecolor='black')
    for x, bar, rssi in zip(x_positions1, bars1, avg_rssi1):
        if rssi is not None:
            axs[0].text(x, bar.get_height() + 1, f"{(rssi - 100):.1f}", ha='center', va='bottom', fontsize=8)

    axs[0].set_title(f"Average RSSI per Channel — {label1}", fontsize=12)
    axs[0].set_xlabel("Channel")
    axs[0].set_ylabel("Signal Strength (dBm)")
    axs[0].set_xticks(x_positions1)
    axs[0].set_xticklabels(channels1, rotation=45)
    axs[0].grid(axis='y', linestyle='--', alpha=0.3)

    # Plot 2
    bars2 = axs[1].bar(x_positions2, bar_heights2, color='cornflowerblue', edgecolor='black')
    for x, bar, rssi in zip(x_positions2, bars2, avg_rssi2):
        if rssi is not None:
            axs[1].text(x, bar.get_height() + 1, f"{(rssi - 100):.1f}", ha='center', va='bottom', fontsize=8)

    axs[1].set_title(f"Average RSSI per Channel — {label2}", fontsize=12)
    axs[1].set_xlabel("Channel")
    axs[1].set_xticks(x_positions2)
    axs[1].set_xticklabels(channels2, rotation=45)
    axs[1].grid(axis='y', linestyle='--', alpha=0.3)

    max_height = max(bar_heights1 + bar_heights2) + 10
    axs[0].set_ylim(0, max_height)
    axs[1].set_ylim(0, max_height)

    plt.tight_layout()
    plt.show()

def plot_overlapping_aps_comparison(data1, data2, label1="Dataset 1", label2="Dataset 2"):
    # Sort both datasets by number of overlapping APs (ascending)
    sorted_data1 = sorted(data1.items(), key=lambda item: item[1]['overlapping_APs'])
    sorted_data2 = sorted(data2.items(), key=lambda item: item[1]['overlapping_APs'])

    channels1 = [item[0] for item in sorted_data1]
    overlap_counts1 = [item[1]['overlapping_APs'] for item in sorted_data1]

    channels2 = [item[0] for item in sorted_data2]
    overlap_counts2 = [item[1]['overlapping_APs'] for item in sorted_data2]

    # Determine max Y for consistent scaling
    max_y = max(max(overlap_counts1, default=0), max(overlap_counts2, default=0)) + 3

    fig, axes = plt.subplots(1, 2, figsize=(16, 6), sharey=True)

    for ax, channels, overlaps, label in zip(axes,
                                              [channels1, channels2],
                                              [overlap_counts1, overlap_counts2],
                                              [label1, label2]):
        x_positions = np.arange(len(channels)) * 1.5
        bars = ax.bar(x_positions, overlaps, color='cornflowerblue', edgecolor='black')

        for x, bar, count in zip(x_positions, bars, overlaps):
            ax.text(x, bar.get_height() + 0.2, str(count),
                    ha='center', va='bottom', fontsize=8)

        ax.set_title(f"Overlapping APs — {label}", fontsize=13)
        ax.set_xlabel("Wi-Fi Channel", fontsize=11)
        ax.set_xticks(x_positions)
        ax.set_xticklabels(channels, rotation=45)
        ax.grid(axis='y', linestyle='--', alpha=0.3)

    axes[0].set_ylabel("Number of Overlapping APs (BSSIDs)", fontsize=11)
    axes[0].set_ylim(0, max_y)

    plt.tight_layout()
    plt.show()

def plot_mean_density_scores(data1, data2, label1="PCAP 1", label2="PCAP 2"):
    mean1 = sum(ch['density_score'] for ch in data1.values()) / len(data1)
    mean2 = sum(ch['density_score'] for ch in data2.values()) / len(data2)

    labels = [label1, label2]
    means = [mean1, mean2]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, means, color=['mediumslateblue', 'salmon'], edgecolor='black')

    for bar, val in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.05,
                f"{val:.2f}",
                ha='center', va='bottom', fontsize=10)

    ax.set_title("Mean Density Score per Network", fontsize=14)
    ax.set_ylabel("Mean Density Score", fontsize=12)
    ax.set_ylim(0, max(means) + 1)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()



def print_combined_phy_protocols(data1, data2, label1="TUC", label2="MyHome"):
    phy_labels = {
        4: '802.11b',
        5: '802.11a (OFDM)',
        6: '802.11g',
        7: '802.11n',
        8: '802.11ac',
        9: '802.11ax'
    }

    all_channels = sorted(set(int(c) for c in data1.keys()) | set(int(c) for c in data2.keys()))

    print(f"{'Channel':<10}{label1:<25}{label2:<25}")
    print("-" * 60)

    for ch in all_channels:
        def get_protocols(data):
            info = data.get(ch) or data.get(str(ch), {})
            raw = info.get("phy_types", set())
            result = set()
            for p in raw:
                try:
                    p_int = int(p)
                    if p_int in phy_labels:
                        result.add(phy_labels[p_int])
                except:
                    continue
            return ", ".join(sorted(result)) if result else "—"

        p1 = get_protocols(data1)
        p2 = get_protocols(data2)
        print(f"{ch:<10}{p1:<25}{p2:<25}")

def visualizer(data1, data2, label1="TUC", label2="MyHome"):
    print_combined_phy_protocols(data1, data2, label1="TUC", label2="MyHome")
    visualize_density_scores(data1, data2, label1="TUC", label2="MyHome")
    plot_avg_rssi_per_channel_comparison(data1, data2, label1="TUC", label2="MyHome")
    plot_overlapping_aps_comparison(data1, data2, label1="TUC", label2="MyHome")
    plot_mean_density_scores(data1, data2, label1="TUC", label2="MyHome")


'''==========================================================================================================================================='''


def main():
    pcap_file1 = "TUC.pcapng"
    pcap_file2 = "MyHome.pcapng"

    print("*" * 150)
    print(f"Reading {pcap_file1}")
    data1 = analyze_ap_signal_strength(pcap_file1)
    print("*" * 150)

    print(f"Reading {pcap_file2}")
    data2 = analyze_ap_signal_strength(pcap_file2)
    print("*" * 150)

    print(f"{'\n---- 802.11 Protocols used in each channel ----':<30}")

    visualizer(data1, data2, label1="TUC", label2="MyHome")


if __name__ == "__main__":
    main()