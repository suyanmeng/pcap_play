import math

class GpsTransfer:
    pi = 3.1415926535897932384626
    a = 6378245.0    # 地球长半径
    ee = 0.00669342162296594323    # 第一偏心率平方

    def _transform_lon(x, y):
        ret = 300 + x + 2*y + 0.1*x**2 + 0.1*x*y + 0.1*math.sqrt(math.fabs(x))
        ret += (20*math.sin(6*x*GpsTransfer.pi) + 20*math.sin(2*x*GpsTransfer.pi))*2/3
        ret += (20*math.sin(x*GpsTransfer.pi) + 40*math.sin(x/3*GpsTransfer.pi))*2/3
        ret += (150*math.sin(x/12*GpsTransfer.pi) + 300*math.sin(x/30*GpsTransfer.pi))*2/3
        return ret

    def _transform_lat(x, y):
        ret = -100 + 2*x + 3*y + 0.2*y**2 + 0.1*x*y + 0.2*math.sqrt(math.fabs(x))
        ret += (20*math.sin(6*x*GpsTransfer.pi) + 20*math.sin(2*x*GpsTransfer.pi))*2/3
        ret += (20*math.sin(y*GpsTransfer.pi) + 40*math.sin(y/3*GpsTransfer.pi))*2/3
        ret += (160*math.sin(y/12*GpsTransfer.pi) + 320*math.sin(y*GpsTransfer.pi/30))*2/3
        return ret

    def wgs84_to_gcj02(lon, lat):
        dLon = GpsTransfer._transform_lon(lon - 105, lat - 35)
        dLat = GpsTransfer._transform_lat(lon - 105, lat - 35)
        radLat = lat / 180 * GpsTransfer.pi
        magic = math.sin(radLat)
        magic = 1 - GpsTransfer.ee*magic**2
        sqrtMagic = math.sqrt(magic)
        dLat = dLat*180 / ((GpsTransfer.a * (1 - GpsTransfer.ee)) / (magic * sqrtMagic) * GpsTransfer.pi)
        dLon = dLon*180 / (GpsTransfer.a / sqrtMagic * math.cos(radLat) * GpsTransfer.pi)
        mgLat = lat + dLat
        mgLon = lon + dLon
        return (mgLon, mgLat)

    def gcj02_to_wgs84(lon, lat):
        initDelta = 0.01
        threshold = 0.000001
        dLat = initDelta
        dLon = initDelta
        mLat = lat - dLat
        mLon = lon - dLon
        pLat = lat + dLat
        pLon = lon + dLon
        wgsLat = 0
        wgsLon = 0
        i = 0
        while(True):
            wgsLat = (mLat + pLat) / 2
            wgsLon = (mLon + pLon) / 2
            tmp_lon, tmp_lat = GpsTransfer.wgs84_to_gcj02(wgsLon, wgsLat)
            dLat = tmp_lat - lat
            dLon = tmp_lon - lon
            if math.fabs(dLat) < threshold and math.fabs(dLon) < threshold:
                break
            if dLat > 0:
                pLat = wgsLat
            else:
                mLat = wgsLat
            if dLon > 0:
                pLon = wgsLon
            else:
                mLon = wgsLon
            i += 1
            if i > 1000:
                break
        return (wgsLon, wgsLat)

    def gps_to_segment(level, lon, lat):
        if level > 15 or level < 0:
            return None
        twoP30 = 1024 * 1024 * 1024
        nds_lon = int(round((lon * twoP30) / 90)) + 4294967296
        nds_lat = int(round((lat * twoP30) / 90)) + 4294967296
        nds_lon_bin = bin(nds_lon).lstrip('0b')[-32:].zfill(32)
        nds_lat_bin = bin(nds_lat).lstrip('0b')[-32:].zfill(32)
        tile_bin = ''
        for i in list(range(level)):
            tile_bin = ''.join(
                (nds_lat_bin[level - i], nds_lon_bin[level - i], tile_bin))
        tile_bin = ''.join((nds_lon_bin[0], tile_bin))
        return int(tile_bin, 2)


if __name__ == "__main__":
    ''' test '''
    gps_gcj = input('请输入GPS坐标(GCJ-02)： ')
    lon_gcj, lat_gcj = gps_gcj.strip('()').split(',')
    lon_gcj = eval(lon_gcj)
    lat_gcj = eval(lat_gcj)
    print(GpsTransfer.gcj02_to_wgs84(lon_gcj, lat_gcj))