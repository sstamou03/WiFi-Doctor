from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyshark
import time

from pandas.tests.dtypes.test_inference import expected

from utils import load_json, flatmap_json

mcs_json = load_json()
mcs_table_2ss = flatmap_json(mcs_json)

#phy_suffix and bandwidth_number will be used later to find the bandwidth from the wireshark packets
phy_suffix = {
    '6' : '11g',
    '7' : '11n',
    '8' : '11ac'
}

bandwidth_number = {
    '0' : 20,
    '1' : 40,
    '2' : 80,
    '3' : 160
}

'''======================================================PCAP PARSER========================================================================'''

def spatial_streams(mcs_index):
    try:
        return (int(mcs_index) // 8) + 1
    except:
        return None


def pcap_parser(pcap_file):
    cap = pyshark.FileCapture(pcap_file , display_filter='wlan.fc.type == 2 && wlan.ta == 2c:f8:9b:dd:06:a0 && wlan.ra == 00:20:a6:fc:b0:36')
    parsed_frames = []


    for pkt in cap:
        try:
            frame = {}

            # WLAN layer
            wlan = pkt.wlan
            frame['bssid'] = getattr(wlan, 'bssid', None)
            frame['tx_mac'] = getattr(wlan, 'ta', None)
            frame['rx_mac'] = getattr(wlan, 'ra', None)
            frame['tsf'] = getattr(wlan, 'timestamp', None)

            # Retry field
            retry_raw = getattr(wlan, 'fc_retry', 'False')
            frame['retry'] = 1 if retry_raw.lower() == 'true' else 0

            # Radiotap (Short GI)
            raw_shortGI = getattr(pkt['radiotap'], 'flags_shortgi', None) if 'radiotap' in pkt else None
            if raw_shortGI == 'True':
                frame['short_gi'] = True
            elif raw_shortGI == 'False':
                frame['short_gi'] = False
            else:
                frame['short_gi'] = None

            #mcs
            raw_mcs = getattr(pkt['radiotap'], 'mcs.index', None)
            frame['mcs'] = int(raw_mcs) if raw_mcs is not None else None
            #spatial streams
            frame['spatial_streams'] = spatial_streams(frame['mcs'])

            # WLAN Radio
            if 'wlan_radio' in pkt:
                # phy
                radio = pkt['wlan_radio']
                frame['phy'] = getattr(radio, 'phy', None)

                # bandwidth
                protocol = phy_suffix[frame['phy']]
                raw_bandwidth = getattr(radio, f'{protocol}.bandwidth', None)
                frame['bandwidth'] = bandwidth_number[raw_bandwidth] if raw_bandwidth is not None else None

                # datarate, channel, frequency, rssi, snr, rategap, throughput, highest data rate & required rssi for MCS
                raw_datarate = getattr(radio, 'data_rate', None)
                frame['data_rate'] = round(float(raw_datarate), 1) if raw_datarate is not None else None
                frame['channel'] = getattr(radio, 'channel', None)
                frame['frequency'] = getattr(radio, 'frequency', None)
                frame['rssi'] = getattr(radio, 'signal_dbm', None)
                frame['snr'] = getattr(radio, 'snr', None)
                frame['expected_datarate'] = None
                frame['minimum_rssi'] = None
                frame['rategap'] = None
                frame['rategap_norm'] = None
                frame['throughput'] = None
            else:
                for key in ['phy', 'mcs', 'bandwidth', 'data_rate', 'channel', 'frequency', 'rssi', 'snr', 'rategap', 'throughput']:
                    frame[key] = None

        # older protocols dont provide bandwidth on wireshark, so for them we provide it ourselves (explanation in report)
            if frame['bandwidth'] is None:
                if frame['phy'] == '7':  # 802.11n
                    frame['bandwidth'] = 20
                elif frame['phy'] == '6':  # 802.11g
                    frame['bandwidth'] = 20
                elif frame['phy']  == '2': #802.11a
                    frame['bandwidth'] = 20
                elif frame['phy'] == '1': #802.11b
                    frame['bandwidth'] = 20
                elif frame['phy'] == '0': #802.11
                    frame['bandwidth'] = 0
                else:
                    frame['bandwidth'] = 'Unknown'

        # to save the analyzation comments for each frame, maybe we print them later?
            frame['Comments'] = []

            parsed_frames.append(frame)

        except Exception as e:
            print(f"Error: {e}")
            continue

    cap.close()

    return parsed_frames

'''=================================================================================================================================================='''

'''====================================================== Performance Monitor ========================================================================'''

def performance_monitor(parsed_frames):

    #print("\n ================ STATISTICS ===============")
    mean_throughput=0
    frameloss = frameloss_calculation(parsed_frames)
    datarate = mean_datarate(parsed_frames)

    if datarate:
        mean_throughput = datarate * (1 - frameloss)

    #print(f"Mean Throughput: {mean_throughput:.2f} Mbps")

    return mean_throughput, frameloss


def throughput_calculation(parsed_frames):

    frame_loss = frameloss_calculation(parsed_frames)

    for frame in parsed_frames:
        if frame['data_rate']:
            data_rate = float(frame['data_rate'])
            frame_throughput = data_rate * (1 - frame_loss)
            frame['throughput'] = frame_throughput


def frameloss_calculation (parsed_frames):

    total = len(parsed_frames)
    counter = sum(1 for frame in parsed_frames if frame['retry'] == 1)

    if total == 0:
        return 0

    return counter / total

def rateGap_calculation(parsed_frames):

    for frame in parsed_frames:
        key = (frame['mcs'], frame['bandwidth'], frame['spatial_streams'], frame['short_gi'])

        datarate_rssi_tuple = mcs_table_2ss.get(key)
        expected_rate = datarate_rssi_tuple[0] if datarate_rssi_tuple is not None else None
        minimum_rssi = datarate_rssi_tuple[1] if datarate_rssi_tuple is not None else None
        frame['expected_datarate'] = expected_rate if expected_rate else None
        frame['minimum_rssi'] = minimum_rssi if minimum_rssi else None

        if expected_rate is not None and frame['data_rate'] is not None:
            rategap = expected_rate - frame['throughput']
            frame['rategap'] = rategap

            rategap_norm = rategap / expected_rate
            frame['rategap_norm'] = rategap_norm

def mean_datarate(parsed_frames):
    '''utility function to calculate mean data rate'''

    counter_dr = [float(frame['data_rate']) for frame in parsed_frames if frame['data_rate']]
    if len(counter_dr):
        return sum(counter_dr) / len(counter_dr)




'''===================================================================================================================================================='''

'''=======================================================Perfomance Analyzer==========================================================================='''

def performance_analyzer(parsed_frames):
    frameloss = frameloss_calculation(parsed_frames)

    if frameloss < 0.05:
        print(f"Frame loss: {frameloss:.2f}, indicates excellent connection.")
    elif 0.05 <= frameloss < 0.15:
        print(f"Frame loss: {frameloss:.2f}, within tolerance. Indicates slight instability, possibly due to interference.")
    elif 0.15 <= frameloss < 0.30:
        print(f"Frame loss: {frameloss:.2f}, indicates moderate losses, possibly due to interference and/or bad signal strength.")
    elif 0.30 <= frameloss < 0.5:
        print(f"Frame loss: {frameloss:.2f}, indicates important losses, possibly due to interference, bad signal strength, contention, distance from access point.")
    else:
        print(f"Frame loss: {frameloss:.2f}, losses are severe, possibly due to interference, extremely poor signal strength, contention, long distance from access point.")



        # ===== ANALYZING =====
    for frame in parsed_frames:
        rssi = int(frame['rssi']) if frame['rssi'] else None
        data_rate = float(frame['data_rate']) if frame['data_rate'] else None
        expected_datarate = float(frame['expected_datarate']) if frame['expected_datarate'] else None
        retry = frame['retry']
        mcs = int(frame['mcs']) if frame['mcs'] else None
        rssi = int(frame['rssi']) if frame['rssi'] else None
        minimum_rssi = int(frame['minimum_rssi']) if frame['minimum_rssi'] else None
        rategap = frame['rategap']
        rategap_norm = frame['rategap_norm']
        throughput = frame['throughput']
        streams = int(frame['spatial_streams']) if frame['spatial_streams'] else None
        shortGI = frame['short_gi'] if frame['short_gi'] else None




        # spatial streams
        if streams and streams>1:
            frame['Comments'].append(f"MIMO supported, {streams} spatial streams.")
        elif streams == 1:
            frame['Comments'].append(f"1 spatial stream.")

        #retry frame or not
        if retry == 1:
            frame['Comments'].append(f"This is a retry frame. This is normal, even for a solid connection, due to the nature of WiFi. Possible causes are low RSSI, too agressive MCS (if so, consider downgrading), and collisions.")

        #short guard interval
        if shortGI :
            frame['Comments'].append("Short GI is 400ns, to shorten the interval between frames, so delays are probably small. This means that the data rate is ~11% more than it would be with Guard Interval set to 800ns. ")
        elif not shortGI:
            frame['Comments'].append("Short GI is 800ns, perhaps there are delays in the network. This means that the data rate is ~11% less than it would be with Guard Interval set to 400ns. ")

        # RSSI
        if rssi:
            if rssi > -35:
                frame['Comments'].append(f"RSSI {rssi} dBm, excellent signal. Throughput will not be limited.")
            elif -50 < rssi <= -35:
                frame['Comments'].append(f"RSSI {rssi} dBm, very good signal. Throughput should be near the max, along with minimal retries/losses.")
            elif -67 < rssi <= -50:
                frame['Comments'].append(f"RSSI {rssi} dBm, moderate signal. Throughput will likely be affected, and some retries/losses will observed.")
            elif -75 < rssi <= -67:
                frame['Comments'].append(f"RSSI {rssi} dBm, poor signal. Expect high retry rates, consider lowering MCS.")
            else:
                frame['Comments'].append(f"RSSI {rssi} dBm, very poor signal. Throughput will be severely degraded, and high retries/losses will be observed.")

        #MCS -- only for 802.11n , not 802.11ac, since the file doesn't contain any 802.11ac frames
        if rssi and minimum_rssi and mcs and streams:
            if rssi > minimum_rssi -2 :
                # these are only for 802.11n, not for 802.11ac
                if (streams == 1 and mcs<7) or (streams == 2 and mcs<15) or (streams == 3 and mcs<23) :
                    frame['Comments'].append(f"RSSI is {rssi}, minimum RSSI for current MCS index {mcs} is {minimum_rssi}. MCS {mcs+1} can be supported.")
                elif (streams == 1 and mcs==7) or (streams == 2 and mcs==15) or (streams == 3 and mcs==23):
                    frame['Comments'].append(f"We're at the maximum MCS index ({mcs}) for {streams} spatial streams on 802.11n. No further MCS upgrades available.")

        #RateGap
        if rategap and data_rate and expected_datarate:
            frame['Comments'].append(f"Theoretical PHY rate : {data_rate} Mbps, actual rate : {throughput:.2f} Mbps. RateGap is {rategap:.2f} Mbps, or {(float(rategap_norm)*100):.2f}% of the theoretical rate.")
            if rategap_norm == 0: # No gap between theoretical and actual data rate, ideal scenario, which is probably never going to happen
                frame['Comments'].append("Since RateGap is 0, this means that the theoretical PHY rate matches EXACTLY the actual PHY rate.")
            elif rategap_norm == 1: # Actual data rate is 0
                frame['Comments'].append("The connection must have collapsed entirely, since RateGap is exactly the theoretical PHY rate.")
            elif 0 < rategap_norm < 0.15:
                frame['Comments'].append("RateGap is minor, within tolerance. Overall performance is still solid and unaffected. ")
            elif 0.15 <= rategap_norm < 0.30:
                frame['Comments'].append("RateGap indicates minor underperformance, possibly points to slightly weak RSSI for the currect MCS, interference from other networks, or contention due to multiple clients on the same channel.")
            elif 0.30 <= rategap_norm < 0.60:
                frame['Comments'].append("RateGap indicates high underperformance. Throughput is way below expected, RSSI is probably well below the MCS threshold, possible channel congestion as well. Retries and losses are well expected.")
            elif 0.60 <= rategap_norm < 1:
                frame['Comments'].append("RateGap indicates severe performance issues. Heavy interference from other networks, severe contention, possibly poor RSSI for current MCS, as well as hardware problems.")



    print("\n")
    while True:
        choice = input("Proceed to see analytics, along with possible causes for problems for each frame? (y/n) : ").lower()
        if choice not in ['y','yes','yea', 'sure', 'bring it awwwn pefkianaki', 'rip steve jobs', 'i hate tim cook', 'i love Apple', 'i love the first 5g iphone']:
            print("Take your time.")
            time.sleep(2)
        else:
            break

    print("=============== FRAME ANALYSIS =================")
    for frame in parsed_frames:
        print(f" --- FRAME : 802.{phy_suffix[frame['phy']]}, Bandwidth {frame['bandwidth']}, MCS {frame['mcs']}, Retry = {frame['retry']} ---")
        for comment in frame['Comments']:
            print(comment)
        print()




'''=======================================================Visualizer==========================================================================='''

def plot_throughput(parsed_frames):
    values = 0
    df = pd.DataFrame(parsed_frames)
    if 'throughput' in df.columns:
        df['throughput'] = pd.to_numeric(df['throughput'], errors='coerce')
        df = df.dropna(subset=['throughput'])
    #print(df['throughput'].value_counts().sort_index())

        values = df['throughput'].values

    #statistics
        min_val = np.min(values)
        mean_val = np.mean(values)
        median_val = np.percentile(values, 50)
        p75 = np.percentile(values, 75)
        p95 = np.percentile(values, 95)
        max_val = np.max(values)

        x = list(range(len(df['throughput'])))

        plt.figure(figsize=(20, 15))
        plt.plot(df.index, df['throughput'], color='navy', marker='o', markersize=3, linestyle='-', linewidth=1)

    #point statistics in the figure
        plt.axhline(min_val, color='red', linestyle=':', linewidth=1, alpha=0.5, label=f"Min: {min_val:.1f} Mbps")
        plt.axhline(mean_val, color='blue', linestyle='--', linewidth=1, alpha=0.5, label=f"Mean: {mean_val:.1f} Mbps")
        plt.axhline(median_val, color='green', linestyle='-.', linewidth=1, alpha=0.5, label=f"Median: {median_val:.1f} Mbps")
        plt.axhline(p75, color='yellow', linestyle=':', linewidth=1, alpha=0.5, label=f"75th P: {p95:.1f} Mbps")
        plt.axhline(p95, color='orange', linestyle=':', linewidth=1, alpha=0.5, label=f"95th P: {p95:.1f} Mbps")
        plt.axhline(max_val, color='black', linestyle=':', linewidth=1, alpha=0.5, label=f"Max: {max_val:.1f} Mbps")

        plt.title("Time Series Plot of Throughput", fontsize=14)
        plt.xlabel("Frame Index", fontsize=12)
        plt.ylabel("Throughput (Mbps)", fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.xticks(ticks=x[::100])  # Αραιά x-axis label
        plt.tight_layout()
        plt.legend(loc='lower right', fontsize=9, frameon=True)

        plt.show()

    #printers
        print("\nThroughput Statistics:")
        print(f"Min:     {min_val:.2f} Mbps")
        print(f"Mean:    {mean_val:.2f} Mbps")
        print(f"Median:  {median_val:.2f} Mbps")
        print(f"75th P:  {p75:.2f} Mbps")
        print(f"95th P:  {p95:.2f} Mbps")
        print(f"Max:     {max_val:.2f} Mbps")

def plot_rategap(parsed_frames):
    df = pd.DataFrame(parsed_frames)

    if 'rategap' in df.columns:
        df['rategap'] = pd.to_numeric(df['rategap'], errors='coerce')
        df = df.dropna(subset=['rategap'])

        x = list(range(len(df['rategap'])))
        values = df['rategap'].values

        plt.figure(figsize=(20, 15))
        plt.plot(x, values, color='darkred', marker='o', markersize=3, linestyle='-', linewidth=1)

        plt.title("Time Series Plot of RateGap", fontsize=16)
        plt.xlabel("Frame Index", fontsize=14)
        plt.ylabel("RateGap (Mbps)", fontsize=14)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.xticks(ticks=x[::100])
        plt.tight_layout()
        plt.legend(["RateGap"], loc='lower right', fontsize=10, frameon=True)
        plt.show()

def plot_rategap_normalized(parsed_frames):
    df = pd.DataFrame(parsed_frames)

    if 'rategap_norm' in df.columns:
        df['rategap_norm'] = pd.to_numeric(df['rategap_norm'], errors='coerce')
        df = df.dropna(subset=['rategap_norm'])

        x = list(range(len(df['rategap_norm'])))
        values = df['rategap_norm'].values

        plt.figure(figsize=(20, 15))
        plt.plot(x, values, color='darkred', marker='o', markersize=3, linestyle='-', linewidth=1)

        plt.title("Time Series Plot of Normalized RateGap", fontsize=16)
        plt.xlabel("Frame Index", fontsize=14)
        plt.ylabel("RateGap (Normalized [0,1])", fontsize=14)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.xticks(ticks=x[::100])
        plt.tight_layout()
        plt.legend(["RateGap"], loc='lower right', fontsize=10, frameon=True)
        plt.show()

def plot_dr_rssi(parsed_frames):

    df = pd.DataFrame(parsed_frames)
    if 'rssi' in df.columns:
        df['rssi'] = pd.to_numeric(df['rssi'], errors='coerce')
        df['rate'] = pd.to_numeric(df['data_rate'], errors='coerce')
        df = df.dropna(subset=['rssi', 'rate'])


        unique_rssi = sorted(df['rssi'].unique())

        fig, axes = plt.subplots(1, len(unique_rssi), figsize=(5 * len(unique_rssi), 4))

        if len(unique_rssi) == 1:
            axes = [axes]

        for i, rssi_val in enumerate(unique_rssi):
            rssi_df = df[df['rssi'] == rssi_val]
            rate_counts = rssi_df['rate'].value_counts().sort_index()

            rate_counts.plot(kind='bar', ax=axes[i], color='navy', edgecolor='black')
            axes[i].set_title(f"RSSI = {rssi_val} dBm", fontsize=12)
            axes[i].set_xlabel("Data Rate (Mbps)")
            axes[i].set_ylabel("Frame Count")
            axes[i].grid(axis='y', linestyle='--', alpha=0.3)

        plt.tight_layout()
        plt.show()


def plot_throughput_phy(parsed_frames):
    #ψcreat data frame and make the map for phy
    df = pd.DataFrame(parsed_frames)
    if 'throughput' in df.columns:
        df['throughput'] = pd.to_numeric(df['throughput'], errors='coerce')
        df['phy']=pd.to_numeric(df['phy'], errors='coerce')

        phy_suffix = {
            6: '802.11g',
            7: '802.11n',
            8: '802.11ac'
        }

        df['phy_label'] = df['phy'].map(phy_suffix)
        df = df.dropna(subset=['phy_label'])
        df = df.dropna(subset=['throughput'])

        group = df.groupby('phy_label')['throughput'].mean()

        plt.figure(figsize=(10, 5))
        fig = group.plot(kind='bar', color= 'navy', edgecolor='black')

        for i, val in enumerate(group):
            fig.text(i, val+2, f"{val:.2f} Mbps", ha='center', va='bottom')

        plt.title("Average Throughput per Phy type", fontsize=14)
        plt.xlabel("Phy Type", fontsize=12)
        plt.ylabel("Throughput (Mbps)", fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.show()

def plot_rssi(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    if 'rssi' in df.columns:
        df['rssi'] = pd.to_numeric(df['rssi'], errors='coerce')


    pass



def plot_retry_breakdown(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    if 'retry' in df.columns:
        df['retry'] = pd.to_numeric(df['retry'], errors='coerce')

        total_with_retry_info = df['retry'].notna().sum()
        retry0 = (df['retry'] == 0).sum()
        retry1 = (df['retry'] == 1).sum()

        categories = ['Total Frames', 'No Retry (0)', 'Retry (1)']
        counts = [total_with_retry_info, retry0, retry1]
        colors = ['gray', 'green', 'red']

        plt.figure(figsize=(10, 5))
        bars = plt.bar(categories, counts, color=colors, edgecolor='black')

        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, yval + 1, f'{yval}', ha='center', va='bottom', fontsize=10)

        plt.title("Retry Frame Breakdown", fontsize=14)
        plt.ylabel("Number of Frames", fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.show()

def plot_spatialstreams_breakdown(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    df['spatial_streams'] = pd.to_numeric(df['spatial_streams'], errors='coerce')

    frames_with_ss_info = df['spatial_streams'].notna().sum()

    ss_counts = df['spatial_streams'].value_counts().sort_index()

    # Prepare categories and values
    categories = ['Total Frames'] + [f"{int(ss)} SS" for ss in ss_counts.index]
    counts = [frames_with_ss_info] + ss_counts.tolist()
    colors = ['steelblue', 'gray'] + ['green' if ss == 1 else 'orange' if ss == 2 else 'red' for ss in ss_counts.index]

    plt.figure(figsize=(10, 5))
    bars = plt.bar(categories, counts, color=colors, edgecolor='black')

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 1, f'{yval}', ha='center', va='bottom', fontsize=10)

    plt.title("Spatial Streams (SS) Breakdown", fontsize=14)
    plt.ylabel("Number of Frames", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()


def plot_shortgi_breakdown(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    df['short_gi'] = pd.to_numeric(df['short_gi'], errors='coerce')

    frames_with_sgi_info = df['short_gi'].notna().sum()
    shortgi_false = (df['short_gi'] == False).sum()
    shortgi_true = (df['short_gi'] == True).sum()

    categories = ['Total Frames', 'GI = 800ns (False)', 'GI = 400ns (True)']
    counts = [frames_with_sgi_info, shortgi_false, shortgi_true]
    colors = ['gray', 'orange', 'purple']

    plt.figure(figsize=(10, 5))
    bars = plt.bar(categories, counts, color=colors, edgecolor='black')

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 1, f'{yval}', ha='center', va='bottom', fontsize=10)

    plt.title("Short Guard Interval Breakdown", fontsize=14)
    plt.ylabel("Number of Frames", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()

def plot_rssi_breakdown(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    df['rssi'] = pd.to_numeric(df['rssi'], errors='coerce')

    frames_with_rssi_info = df['rssi'].notna().sum()

    # Initialize counters
    rssi_gt_35 = (df['rssi'] > -35).sum()
    rssi_35_50 = ((df['rssi'] <= -35) & (df['rssi'] > -50)).sum()
    rssi_50_67 = ((df['rssi'] <= -50) & (df['rssi'] > -67)).sum()
    rssi_67_75 = ((df['rssi'] <= -67) & (df['rssi'] > -75)).sum()
    rssi_lt_75 = (df['rssi'] <= -75).sum()

    categories = [
        'Total Frames',
        'Excellent (> -35)',
        'Very Good (-50 to -35)',
        'Moderate (-67 to -50)',
        'Poor (-75 to -67)',
        'Very Poor (< -75)'
    ]
    counts = [
        frames_with_rssi_info,
        rssi_gt_35,
        rssi_35_50,
        rssi_50_67,
        rssi_67_75,
        rssi_lt_75
    ]
    colors = ['gray', 'green', 'lime', 'orange', 'red', 'darkred']

    plt.figure(figsize=(12, 5))
    bars = plt.bar(categories, counts, color=colors, edgecolor='black')

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 1, f'{yval}', ha='center', va='bottom', fontsize=10)

    plt.title("RSSI Breakdown", fontsize=14)
    plt.ylabel("Number of Frames", fontsize=12)
    plt.xticks(rotation=20)
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()

def plot_throughput_per_bandwidth(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    df['throughput'] = pd.to_numeric(df['throughput'], errors='coerce')
    df['bandwidth'] = pd.to_numeric(df['bandwidth'], errors='coerce')
    df = df.dropna(subset=['throughput', 'bandwidth'])

    grouped = df.groupby('bandwidth')['throughput'].mean().sort_index()

    plt.figure(figsize=(8, 5))
    ax = grouped.plot(kind='bar', color='navy', edgecolor='black')

    for i, val in enumerate(grouped):
        ax.text(i, val + 2, f"{val:.1f} Mbps", ha='center', fontsize=9)

    plt.title("Average Throughput per Bandwidth", fontsize=14)
    plt.xlabel("Bandwidth (MHz)", fontsize=12)
    plt.ylabel("Throughput (Mbps)", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()

def plot_throughput_per_shortgi(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    df['throughput'] = pd.to_numeric(df['throughput'], errors='coerce')
    df['short_gi'] = df['short_gi'].astype(str)

    df = df.dropna(subset=['throughput', 'short_gi'])


    grouped = df.groupby('short_gi')['throughput'].mean()

    # Plot
    plt.figure(figsize=(6, 5))
    ax = grouped.plot(kind='bar', color='lightpink', edgecolor='black')

    for i, val in enumerate(grouped):
        ax.text(i, val + 2, f"{val:.1f} Mbps", ha='center', fontsize=9)

    plt.title("Mean Throughput vs Short GI", fontsize=14)
    plt.xlabel("Short GI (Guard Interval)", fontsize=12)
    plt.ylabel("Mean Throughput (Mbps)", fontsize=12)
    plt.xticks(rotation=0)
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()

def plot_avg_throughput_per_mcs(parsed_frames):
    df = pd.DataFrame(parsed_frames)
    df['mcs'] = pd.to_numeric(df['mcs'], errors='coerce')
    df['throughput'] = pd.to_numeric(df['throughput'], errors='coerce')
    df = df.dropna(subset=['mcs', 'throughput'])

    # Group by MCS and calculate average throughput
    grouped = df.groupby('mcs')['throughput'].mean().sort_index()

    # Use new colormap API (Matplotlib >=3.7)
    cmap = plt.get_cmap('Set3', len(grouped))
    colors = [cmap(i) for i in range(len(grouped))]

    # Plotting
    plt.figure(figsize=(12, 5))
    bars = plt.bar(grouped.index.astype(str), grouped.values, color=colors, edgecolor='black')

    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 1, f"{yval:.1f}", ha='center', fontsize=8)

    plt.title("Average Throughput per MCS Index", fontsize=14)
    plt.xlabel("MCS Index", fontsize=12)
    plt.ylabel("Throughput (Mbps)", fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.3)
    plt.tight_layout()
    plt.show()

    def plot_retry_vs_shortgi(parsed_frames):
        df = pd.DataFrame(parsed_frames)
        df['retry'] = pd.to_numeric(df['retry'], errors='coerce')
        df['short_gi'] = df['short_gi'].astype(str)

        # Filter retry frames only
        retry_df = df[df['retry'] == 1]
        retry_sgi_counts = retry_df['short_gi'].value_counts().sort_index()

        categories = ['GI = 400ns (True)', 'GI = 800ns (False)', 'Unknown']
        counts = [
            retry_sgi_counts.get('True', 0),
            retry_sgi_counts.get('False', 0),
            retry_sgi_counts.get('None', 0)
        ]
        colors = ['purple', 'orange', 'gray']

        plt.figure(figsize=(8, 5))
        bars = plt.bar(categories, counts, color=colors, edgecolor='black')

        for bar in bars:
            yval = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, yval + 1, f"{yval}", ha='center', va='bottom', fontsize=10)

        plt.title("Retry Frame Breakdown by Short GI Usage", fontsize=14)
        plt.ylabel("Number of Retry Frames", fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.3)
        plt.tight_layout()
        plt.show()




def visualizer(frames):

    print("Visualizer".center(100, "-"))

    plt.close('all')

    _,frameloss = performance_monitor(frames)
    print(f"\nFrame Loss: {frameloss * 100:.2f}%")

    rategap_list =[]
    avg=0
    for frame in frames:
        rategap = frame.get('rategap_norm')
        if rategap is not None:
            rategap_list.append(float(rategap))
    if len(rategap_list):
        avg=sum(rategap_list)/len(rategap_list)

    print(f"Rate gap: {avg * 100:.2f}%")

    plot_throughput(frames)
    plot_rategap(frames)
    plot_rategap_normalized(frames)
    plot_dr_rssi(frames)
    plot_throughput_phy(frames)
    plot_retry_breakdown(frames)
    plot_shortgi_breakdown(frames)
    plot_spatialstreams_breakdown(frames)
    plot_rssi_breakdown(frames)
    plot_throughput_per_bandwidth(frames)
    plot_throughput_per_shortgi(frames)
    plot_avg_throughput_per_mcs(frames)



'''===================================================================================================================================================='''



def main():

    print("... Reading .pcap file ...\n")
    frames = pcap_parser("HowIWiFi_PCAP.pcap")
    throughput_calculation(frames)
    rateGap_calculation(frames)
    performance_monitor(frames)
    performance_analyzer(frames)
    visualizer(frames)


if __name__ == '__main__':
    main()