from ehp_signal_matrix_struct import *
import json
import dpkt

def get_link_form_info(profiles_form_of_way):
    result = {}
    for profile_form_of_way in profiles_form_of_way:
        link_id = profile_form_of_way.profile_head()[0]
        form_of_way = profile_form_of_way.link_form_way()[0]
        result[link_id] = form_of_way
    return result

def load_file(file_path):
    profiles_form_of_way = []
    with open(file_path, "rb") as fp:
        try:
            pcp_data = dpkt.pcap.Reader(fp)
            for timestamp, buffer in pcp_data:
                eth_udp = dpkt.ethernet.Ethernet(buffer)
                if (
                        "udp" in dir(eth_udp.data)
                        and eth_udp.data.p == dpkt.ip.IP_PROTO_UDP
                ):
                    ehp_obj = EhpHead(eth_udp.data.data.data)
                    data_id = eval(ehp_obj.ehp_head()[-2])
                    if data_id == 0x03000011:
                        profiles_form_of_way.append(ProfileFormOfWay(eth_udp.data.data.data))
            print(file_path, ": loaded")
        except ValueError as e:
            print(e, ": ", file_path)
    return profiles_form_of_way

def generate_data(data, file_path):
    with open(file_path, mode="w", encoding='utf-8') as f:
        f.write(json.dumps(data))

def get_data(pcap_path):
    return get_link_form_info(load_file(pcap_path))

if __name__ == '__main__':
    import os
    import sys
    import time
    from multiprocessing import Pool
    
    t0 = time.time()
    ''' create json from single file '''
    # pcap_path = sys.argv[1]
    # output_file_path = os.path.splitext(pcap_path)[0] + ".json"
    # data = get_data(pcap_path)
    # generate_data(data, output_file_path)

    ''' create json from multiple files '''
    pool = Pool(8)
    pcap_foler = sys.argv[1]
    all_data = []
    for root, dirs, files in os.walk(pcap_foler):
        for file in files:
            result = pool.apply_async(get_data, args=(os.path.join(root, file),))
            all_data.append(result)
    pool.close()
    pool.join()
    data = {}
    for i in all_data:
        for k,v in i.get().items():
            data[k] = v
    output_file_path = os.path.splitext(pcap_foler)[0] + ".json"
    generate_data(data, output_file_path)

    t1 = time.time()
    print(f'Finished, timespan: {t1 - t0}s', f'link_number: {len(data)}')