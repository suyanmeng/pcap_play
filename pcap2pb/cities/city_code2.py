import json
import os
from collections import defaultdict
from cities.gps import GpsTransfer


# 对GPS进行纠偏得到WGS84，然后获取WGS84坐标对应的segment和city code
class CityCodeProvider:
    def __init__(self, seg_2_city_file) -> None:
        self.seg_2_city = defaultdict(list)
        with open(seg_2_city_file, 'r') as fp:
            self.seg_2_city = json.load(fp)
        
    def find_segment_by_gps(self, lon, lat):
        wgs_lon, wgs_lat = GpsTransfer.gcj02_to_wgs84(lon, lat)
        return GpsTransfer.gps_to_segment(14, wgs_lon, wgs_lat)
    
    def find_city_code_by_segment(self, segment):
        segment = str(segment)
        if segment not in self.seg_2_city:
            return None
        return set(self.seg_2_city[segment])
    
    def find_city_code_by_gps(self, lon, lat) -> set:
        segment = self.find_segment_by_gps(lon, lat)
        city_codes = self.find_city_code_by_segment(segment)
        if city_codes is not None:
            return city_codes
        else:
            return set()

def get_city_code_provider():
    cur_dir = os.path.dirname(__file__)
    return CityCodeProvider(os.path.join(cur_dir, "seg_2_city.json"))

if __name__ == "__main__":
    city_code_provider = get_city_code_provider()
    print(city_code_provider.find_city_code_by_gps(121.59050854593515,30.196337839588523))
    print(city_code_provider.find_city_code_by_gps(120.39256347343326,30.217161756008863))