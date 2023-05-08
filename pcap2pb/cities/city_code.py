import json
import os
from rtree import index
from collections import defaultdict


# 对segment所在经纬度进行偏转得到GCJ02坐标范围，然后根据GPS落在哪个GCJ02范围来确定segment和city code
class CityCodeProvider:
    def __init__(self, seg_2_gps_file, seg_2_city_file) -> None:
        self.idx = index.Index()
        self._load_segments(seg_2_gps_file)
        self.seg_2_city = defaultdict(list)
        with open(seg_2_city_file, 'r') as fp:
            self.seg_2_city = json.load(fp)
        
    def _load_segments(self, seg_2_gps_file):
        seg_2_gps = dict()
        with open(seg_2_gps_file, 'r') as fp:
            seg_2_gps = json.load(fp)
        for segment, gps_range in seg_2_gps.items():
            self.idx.insert(eval(segment), tuple(gps_range))
    
    def find_segment_by_gps(self, lon, lat):
        return set(self.idx.intersection((lon, lat, lon, lat)))
    
    def find_city_code_by_segment(self, segment):
        segment = str(segment)
        if segment not in self.seg_2_city:
            return None
        return set(self.seg_2_city[segment])
    
    def find_city_code_by_gps(self, lon, lat) -> set:
        segments = self.find_segment_by_gps(lon, lat)
        result = set()
        for segment in segments:
            city_codes = self.find_city_code_by_segment(segment)
            if city_codes is None:
                continue
            for city_code in city_codes:
                result.add(city_code)
        return result

def get_city_code_provider():
    cur_dir = os.path.dirname(__file__)
    return CityCodeProvider(os.path.join(cur_dir, "seg_2_gcj02.json"), os.path.join(cur_dir, "seg_2_city.json"))

if __name__ == "__main__":
    city_code_provider = get_city_code_provider()
    print(city_code_provider.find_city_code_by_gps(121.59050854593515,30.196337839588523))
    print(city_code_provider.find_city_code_by_gps(120.39256347343326,30.217161756008863))