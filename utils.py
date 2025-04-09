import json

def load_json(path="ht_mcs_full_correct.json"):
    with open(path, "r") as f:
        return json.load(f)

def flatmap_json(mcs_json):
    flat_table = {}

    for mcs_index, bw_data in mcs_json.items():
        for bw, gi_data in bw_data.items():
            for gi, streams in gi_data.items():
                for stream, values in streams.items():
                    key = (int(mcs_index), int(bw), int(stream), gi == "true")
                    flat_table[key] = (values["rate"], values["rssi"])

    return flat_table