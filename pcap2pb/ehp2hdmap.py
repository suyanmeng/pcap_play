import os
import socket
import dpkt
import time
import threading
import json
from ehp_signal_matrix_struct import *

# 组播地址和端口
MULTICAST_ADDR = '239.255.43.44'
PORT = 12345

interval = 50
real_interval = 50
update_interval = False
current_sum_interval = 0
last_ts = 0

def interval_watch(interval_path):
    global interval
    global real_interval
    global update_interval
    while 1:
        with open(interval_path, 'r') as f:
            # 读取JSON数据
            data = json.load(f)
        if int(data["interval"]) != interval:
            interval = int(data["interval"])
            real_interval = real_interval if interval>1000 else interval
            update_interval = True
        time.sleep(1)

def time_prepare():
    global interval
    global current_sum_interval
    global update_interval
    if interval <=1000:
        return True
    if update_interval:
        update_interval = False
        current_sum_interval = 0
    current_sum_interval+=1000
    if current_sum_interval > interval:
        current_sum_interval = 0
        return True
    return False

def init_interval_file(interval_path, init_interval):
    data = {"interval":str(init_interval)}
    json_str = json.dumps(data)

    with open(interval_path, 'w') as f:
        f.write(json_str)

def load_file(file_path,interval_path,interval_input):
    global interval
    global last_ts
    interval = interval_input
    # 创建 UDP 套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    # 设置组播选项
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    if os.path.exists(file_path):
        with open(file_path, "rb") as fp:
            pcp_data = dpkt.pcap.Reader(fp)
            init_interval_file(interval_path,interval_input)
            watch_thread = threading.Thread(target=interval_watch,args=(interval_path,))
            watch_thread.daemon = True
            watch_thread.start()

            for ts, buf in pcp_data:
                if(last_ts == 0):
                    last_ts = ts
                else:
                    dist = abs(ts-last_ts)
                    print("dist ==",dist,"\n")
                    time.sleep(dist)
                    last_ts = ts
                eth_udp = dpkt.ethernet.Ethernet(buf)
                sock.sendto(bytes(eth_udp.data.data.data), (MULTICAST_ADDR, PORT))
                while(time_prepare() != True):
                    time.sleep(real_interval*0.0001)
           
        sock.close()        
