import os
from collections import defaultdict
import dpkt
from ehp_signal_matrix_struct import *
from cities.city_code import get_city_code_provider
from cities.city_code2 import get_city_code_provider as get_city_code_provider2
from cities.gps import GpsTransfer
from Logger import log


def load_file(file_path):
    """
    Read pcap file and decode udp package as signals.
    pcap_file: Pcap file full path.
    :return Dict of all signal and map between link id and city code
    """
    if os.path.exists(file_path):
        with open(file_path, "rb") as fp:
            pcp_data = dpkt.pcap.Reader(fp)
            log().info("load " + file_path)
            for timestamp, buffer in pcp_data:
                eth_udp = dpkt.ethernet.Ethernet(buffer)

                if (
                        "udp" in dir(eth_udp.data)
                        and eth_udp.data.p == dpkt.ip.IP_PROTO_UDP
                ):
                    ehp_obj = EhpHead(eth_udp.data.data.data)
                    data_id = eval(ehp_obj.ehp_head()[-2])

                    if data_id == 0x03000022:
                        data_pcap = ProfileTollgate(eth_udp.data.data.data)
                        link_id = data_pcap.profile_head()[0]
                        is_tollgate = data_pcap.toll_gate()
                        if is_tollgate:
                            print(link_id)
                    else:
                        continue


if __name__ == "__main__":
    import os
    from collections import defaultdict
    from multiprocessing import Pool

    def load_files(file_dir, process_num=8):
        pool = Pool(process_num)
        process_results = []
        for root, dirs, files in os.walk(file_dir):
            for file in files:
                if not file.endswith('.pcap'):
                    continue
                process_results.append(pool.apply_async(load_file, args=(os.path.join(root, file),)))
        pool.close()
        pool.join()

    '''start'''
    pcap_path = input('请输入文件路径： ')

    '''load pcap file'''
    if os.path.isfile(pcap_path):
        load_file(pcap_path)
    else:
       load_files(pcap_path)
