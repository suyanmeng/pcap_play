from enum import IntFlag
import struct

"""
Decode c/c++ type to python :
c++ type: uint8 --> python type 'integer' decode is:'B',length:1 byte;
c++ type: sint8 --> python type 'integer' decode is:'b',length:1 byte;
c++ type: Bool --> python type 'bool' decode is:'?',length:1 byte;
c++ type: uint16 --> python type 'integer' decode is:'H',length:2 bytes;
c++ type: sint16 --> python type 'integer' decode is:'h,length:2 bytes;
c++ type: uint32 --> python type 'integer' decode is:'I',length:4 bytes;
c++ type: sint32 --> python type 'integer decode is:'i',length:4 bytes;
c++ type: uint64 --> python type 'long' decode is:'Q',length:8 bytes;
c++ type: sint64 --> python type 'long long' decode is:'q',length:8 bytes;
c++ type: float32 --> python type 'float' decode is:'f',length:4 bytes;
"""


class EHPSignal(IntFlag):
    LOC = 0x03000001
    PATH_CONTROL = 0x03000002
    GLOBAL_DATA = 0x03000003
    PROFILE_CONTROL = 0x03000004
    PROFILE_NODE = 0x03000005
    LANE_MODEL = 0x03000006
    LANE_CONNECTIVITY = 0x03000007
    LINEAR_OBJECTS = 0x03000008
    LANES_GEOMETRY = 0x03000009
    CURVATURE = 0x0300000A
    SLOPE = 0x0300000B
    EFFECTIVE_SPEED_LIMIT = 0x0300000C
    ROAD_GEOMETRY = 0x0300000D
    NUMBER_OF_LANES_DRIVING_DIRECTION = 0x0300000E
    LINK_IDENTIFIER = 0x0300000F
    FUNCTIONAL_ROAD_CLASS = 0x03000010
    FORM_OF_WAY = 0x03000011
    TUNNEL = 0x03000012
    LANE_WIDTH = 0x03000013
    SWITCH_INFO = 0x03000014
    ROUTE_LIST = 0x03000017
    GEOFENCE = 0x0300001A  # it's not used in SW1
    MERGE_POINT = 0x0300001B
    TRAFFIC_SIGN = 0x0300001D  # it's not used in SW1
    GANTRY = 0x0300001E  # it's not used in SW1
    POLE = 0x0300001F  # it's not used in SW1
    GROUND_ARROW = 0x03000020  # it's not used in SW1
    GROUND_TEXT = 0x03000021  # it's not used in SW1
    TOLLGATE = 0x03000022  # it's not used in SW1
    DYNAMIC_INFO_EVENT = 0x03000015
    DYNAMIC_INFO_EMERGENCY = 0x03000019
    DYNAMIC_INFO_METEOROLOGY = 0x03000018


def decode_udp_bytes_content(eth_udp_bin_data, start_, end_, decode_str):
    """
    Decode EHP info from pcap package
    eth_udp_bin_data:UDP data in pcap
    start_:The start position of binary content of UDP data
    end_:The end position of binary content of UDP data
    decode_str:The decoding string change c++ type to python style,PS:'<IIB'
    """
    ehp_decode_info = struct.unpack(decode_str, eth_udp_bin_data[start_:end_])
    return ehp_decode_info


class EhpHead(object):
    # Ehp package head
    def __init__(self, udp_data) -> None:
        self.eth_udp = udp_data

    def ehp_head(self):
        """
        EHP output package head is 12 bytes:
        length:2 bytes
        counter:2 bytes
        Data ID: 4 bytes,value is payload length.
        CRC: 4 bytes
        """
        (
            ehp_package_length,
            ehp_package_counter,
            ehp_package_data_id,
            ehp_package_crc,
        ) = decode_udp_bytes_content(self.eth_udp, 0, 12, "<HHII")
        return (
            ehp_package_length,
            ehp_package_counter,
            hex(ehp_package_data_id),
            ehp_package_crc,
        )


class Payload(EhpHead):

    # Timestamp info of payload

    def pay_load_ts_info(self):
        """
        Timestamp length is 20 bytes :
        timestamp:20 bytes
        """
        (
            ehp_pl_ts_reserve,
            ehp_pl_ts_utc_valid,
            ehp_pl_ts_utc_week,
            ehp_pl_ts_utc_us,
            ehp_pl_ts_utc_systime,
        ) = decode_udp_bytes_content(self.eth_udp, 12, 32, "<BBHQQ")
        return (
            ehp_pl_ts_reserve,
            ehp_pl_ts_utc_valid,
            ehp_pl_ts_utc_week,
            ehp_pl_ts_utc_us,
            ehp_pl_ts_utc_systime,
        )

    # Payload head

    def pay_load_head_info(self):
        """
        Message count,index,bundle:
        partCount: 2 bytes
        partIndex: 2 bytes
        bundleId: 4 bytes
        """
        (
            ehp_pl_head_partcount,
            ehp_pl_head_partIndex,
            ehp_pl_head_bundleId,
        ) = decode_udp_bytes_content(self.eth_udp, 32, 40, "<HHI")
        return ehp_pl_head_partcount, ehp_pl_head_partIndex, ehp_pl_head_bundleId


class AdasisV3(Payload):

    # Adasis v3 head

    def pay_load_adasis_head(self, eth_udp_bin_data):
        """
        ADAS V3 head length is 4 bytes:
        reserved: 1 byte
        cycliccounter: 1 byte
        messageType: 1 byte
        messageCount: 1 byte
        """
        (
            ehp_adasis_head_reserve,
            ehp_adasis_head_cyc_counter,
            ehp_adasis_head_msg_type,
            ehp_adasis_head_msg_count,
        ) = decode_udp_bytes_content(eth_udp_bin_data, 40, 44, "<BBBB")
        return (
            ehp_adasis_head_reserve,
            ehp_adasis_head_cyc_counter,
            ehp_adasis_head_msg_type,
            ehp_adasis_head_msg_count,
        )


class NOASwitchInfo(AdasisV3):
    def navigation_info(self):
        navigation_status, matching_status, remain_distance = decode_udp_bytes_content(
            self.eth_udp, 44, 50, "<BBI"
        )
        return navigation_status, matching_status, remain_distance

    def switch_info(self):
        (
            switch_lane_direction,
            switch_lane_reason,
            switch_lane_distance,
            switch_lane_end_distance,
            line_count,
        ) = decode_udp_bytes_content(self.eth_udp, 50, 58, "<BBHHH")
        return (
            switch_lane_direction,
            switch_lane_reason,
            switch_lane_distance,
            switch_lane_end_distance,
            line_count,
        )

    def linear_object_id(self):
        *_, line_count = self.switch_info()
        line_list = list()
        if line_count:
            for line_ in range(0, line_count):
                line_list.append(
                    decode_udp_bytes_content(
                        self.eth_udp, 58 + line_ * 4, 58 + (line_ + 1) * 4, "<I"
                    )[0]
                )
        return line_list


class NOARouteList(AdasisV3):
    def nav_hd_info(self):
        hdmap_version, link_count = decode_udp_bytes_content(
            self.eth_udp, 44, 50, "<IH"
        )
        return hdmap_version, link_count

    def nav_link_list(self):
        _, link_total = self.nav_hd_info()
        links_list = list()

        for elem in range(0, link_total):
            link_ = decode_udp_bytes_content(
                self.eth_udp, 50 + elem * 4, 50 + (elem + 1) * 4, "<I"
            )[0]
            links_list.append(link_)
        return links_list


class Location(AdasisV3):
    # If DataId is 0x03000001,msg is location info.

    def location_relative_pos(self):
        """
        Relative postion info in locaiton length is 33 bytes:
        RoadID:8 bytes
        LaneID:8 bytes
        LaneSeq:1 bytes
        DisLeft:4 bytes
        DisRight:4 bytes
        HeadLeft:4 bytes float type
        HeadRight:4 bytes float type
        """
        (
            ehp_loc_relapos_roadid,
            ehp_loc_relapos_laneid,
            ehp_loc_relapos_laneseq,
            ehp_loc_relapos_disleft,
            ehp_loc_relapos_disright,
            ehp_loc_relapos_headleft,
            ehp_loc_relapos_headright,
        ) = decode_udp_bytes_content(self.eth_udp, 44, 77, "<QQBLLff")
        return (
            ehp_loc_relapos_roadid,
            ehp_loc_relapos_laneid,
            ehp_loc_relapos_laneseq,
            ehp_loc_relapos_disleft,
            ehp_loc_relapos_disright,
            ehp_loc_relapos_headleft,
            ehp_loc_relapos_headright,
        )

    def location_absolute_pos(self):
        """
        Absolute postion info in location length is 45 bytes :

        """
        (
            ehp_loc_absopos_lon,
            ehp_loc_absopos_lat,
            ehp_loc_absopos_heading,
            ehp_loc_absopos_lon_std,
            ehp_loc_absopos_lat_std,
            ehp_loc_absopos_confidence,
            ehp_loc_absopos_xacc,
            ehp_loc_absopos_yacc,
            ehp_loc_absopos_zacc,
            ehp_loc_absopos_angular_velocity_x,
            ehp_loc_absopos_angular_velocity_y,
            ehp_loc_absopos_angular_velocity_z,
        ) = decode_udp_bytes_content(self.eth_udp, 77, 122, "<llfffBffffff")
        return (
            ehp_loc_absopos_lon,
            ehp_loc_absopos_lat,
            ehp_loc_absopos_heading,
            ehp_loc_absopos_lon_std,
            ehp_loc_absopos_lat_std,
            ehp_loc_absopos_confidence,
            ehp_loc_absopos_xacc,
            ehp_loc_absopos_yacc,
            ehp_loc_absopos_zacc,
            ehp_loc_absopos_angular_velocity_x,
            ehp_loc_absopos_angular_velocity_y,
            ehp_loc_absopos_angular_velocity_z,
        )

    def location_geofence_info(self):
        """
        Geometry defence info in location length is 2 bytes:
        geofennce_judge_status: 1 byte
        geofence_judge_type: 1 byte
        """

        (
            ehp_loc_geofennce_judge_status,
            ehp_loc_geofence_judge_type,
        ) = decode_udp_bytes_content(self.eth_udp, 122, 124, "<BB")
        return ehp_loc_geofennce_judge_status, ehp_loc_geofence_judge_type

    def location_position_info(self):
        """
        Position info in location length is:49 bytes
        timestamp:8 bytes
        positionage :8 bytes
        pathid: 4 bytes
        offset:4 bytes
        accuracy:4 bytes
        deviation:4 bytes
        speed:4 bytes float type
        Relative_H:4 bytes float type
        probability:4 bytes float type
        currentLane:1 bytes
        preferPath:4 bytes
        """

        (
            ehp_loc_position_timestamp,
            ehp_loc_position_positionage,
            ehp_loc_position_pathid,
            ehp_loc_position_offset,
            ehp_loc_position_accuracy,
            ehp_loc_position_deviation,
            ehp_loc_position_speed,
            ehp_loc_position_relative_h,
            ehp_loc_position_probability,
            ehp_loc_position_currentLane,
            ehp_loc_position_preferpath,
        ) = decode_udp_bytes_content(self.eth_udp, 124, 173, "<QQIIIlfffBI")
        return (
            ehp_loc_position_timestamp,
            ehp_loc_position_positionage,
            ehp_loc_position_pathid,
            ehp_loc_position_offset,
            ehp_loc_position_accuracy,
            ehp_loc_position_deviation,
            ehp_loc_position_speed,
            ehp_loc_position_relative_h,
            ehp_loc_position_probability,
            ehp_loc_position_currentLane,
            ehp_loc_position_preferpath,
        )

    def location_fail_safe(self):
        """
        Fail safe info in location length is 6 bytes：
        failsafe_loc_status:1 byte
        failsafe_gnss_status:1 byte
        failsafe_camera_status:1 byte
        failsafe_hdmap_status:1 byte
        failsafe_vehcle_status:1 byte
        failsafe_imu_status:1 byte
        """
        (
            ehp_loc_failsafe_loc_status,
            ehp_loc_failsafe_gnss_status,
            ehp_loc_failsafe_camera_status,
            ehp_loc_failsafe_hdmap_status,
            ehp_loc_failsafe_vehcle_status,
            ehp_loc_failsafe_imu_status,
        ) = decode_udp_bytes_content(self.eth_udp, 173, 179, "<BBBBBB")
        return (
            ehp_loc_failsafe_loc_status,
            ehp_loc_failsafe_gnss_status,
            ehp_loc_failsafe_camera_status,
            ehp_loc_failsafe_hdmap_status,
            ehp_loc_failsafe_vehcle_status,
            ehp_loc_failsafe_imu_status,
        )


class GlobalData(AdasisV3):
    """
    ADASIS V3 type:
    NODE = 0,
    PROBABILITY = 1,
    HEADING_CHANGE = 2,
    LANE_MODEL = 3,
    LANE_CONNECTIVITY = 4,
    LINEAR_OBJECTS = 5,
    LANES_GEOMETRY = 6,
    LANE_WIDTH = 7,
    ROAD_GEOMETRY = 8,
    NUMBER_OF_LANES_DRIVING_DIRECTION = 9,
    COMPLEX_INTERSECTION = 10,
    LINK_IDENTIFIER = 11,
    FUNCTIONAL_ROAD_CLASS = 12,
    ROUTE_NUMBER_TYPES = 13,
    FORM_OF_WAY = 14,
    ROAD_ACCESSIBILITY = 15,
    ACCESS_RESTRICTION = 16,
    OVERTAKING_RESTRICTION = 17,
    TUNNEL = 18,
    BRIDGE = 19,
    DIVIDEDROAD = 20,
    CURVATURE = 21,
    SLOPE = 22,
    BUILTUP_AREA = 23,
    IN_TOWN = 24,
    SURFACE = 25,
    TRAFFIC_SIGN = 26,
    TRAFFIC_LIGHT = 27,
    SPECIAL_SITUATION = 28,
    EFFECTIVE_SPEED_LIMIT = 29,
    EXTENDED_SPEED_LIMIT = 30,
    AVERAGE_SPEED = 31,
    FLOW_SPEED = 32,
    ROAD_CONDITION = 33,
    WEATHER = 34,
    LOCATION_OBJECT = 35,
    PART_OF_CALCULATED_ROUTE = 36,
    COUNTRY_CODE = 37,
    REGION_CODE = 38,
    DRIV_SIDE = 39,
    UNIT_SYSTEM = 40,
    VERSION_PROTOCOL = 41,
    VERSION_HARDWARE = 42,
    VERSION_MAP = 43,
    MAP_AGE = 44,
    MAP_PRO = 45,
    MAP_STATUS = 46,
    SYSTEM_STATUS = 47,
    TIME_ZONE_OFFSET = 48,
    ABSOLUTE_VEHICLE_POSITION = 49,
    OBSTACLE = 50,
    TURNR_ESTRICTION = 51,
    //extra type:
    MERGE_PATH = 52,
    NOA = 53,
    DYNAMIC_TRAFFIC = 54,
    DYNAMIC_METEOROLOGY = 55,
    DYNAMIC_EMERGENCY = 56,
    GEO_FENCE = 57,
    GANTRY=58,
    POLE=59,
    GROUND_ARROW=60,
    GROUND_TEXT=61,
    TOLLGATE=62,
    """

    def global_drive_side(self):
        data_type, is_avialable, dirve_side = decode_udp_bytes_content(
            self.eth_udp, 44, 47, "<B?B"
        )
        return data_type, is_avialable, dirve_side

    def global_country_code(self):
        data_type, is_avialable, country_code = decode_udp_bytes_content(
            self.eth_udp, 47, 53, "<B?I"
        )
        return data_type, is_avialable, country_code

    def global_unit_system(self):
        data_type, is_avialable, unit_system = decode_udp_bytes_content(
            self.eth_udp, 53, 56, "<B?B"
        )
        return data_type, is_avialable, unit_system

    def global_protocol_version(self):
        data_type, is_avialable, protocol_version = decode_udp_bytes_content(
            self.eth_udp, 56, 62, "<B?I"
        )
        return data_type, is_avialable, protocol_version

    def global_hardware_version(self):
        data_type, is_avialable, hardware_version = decode_udp_bytes_content(
            self.eth_udp, 62, 68, "<B?I"
        )
        return data_type, is_avialable, hardware_version

    def global_map_version(self):
        data_type, is_avialable, map_version = decode_udp_bytes_content(
            self.eth_udp, 68, 74, "<B?I"
        )
        return data_type, is_avialable, map_version

    def global_map_age(self):
        data_type, is_avialable, map_age = decode_udp_bytes_content(
            self.eth_udp, 74, 80, "<B?I"
        )
        return data_type, is_avialable, map_age

    def global_map_provider(self):
        data_type, is_avialable, map_provider = decode_udp_bytes_content(
            self.eth_udp, 80, 86, "<B?I"
        )
        return data_type, is_avialable, map_provider

    def global_guidance(self):
        data_type, is_avialable, guidance = decode_udp_bytes_content(
            self.eth_udp, 86, 89, "<B?B"
        )
        return data_type, is_avialable, guidance

    def global_simulating(self):
        simulating = decode_udp_bytes_content(self.eth_udp, 89, 90, "<?")
        return simulating

    def global_regioncode(self):
        citycode=decode_udp_bytes_content(self.eth_udp, 91, 95, "<I")
        return citycode


class PathControl(AdasisV3):
    def path_control_head(self):
        """
        Path sequence info in PathControl info length is 10 bytes:
        idFirst:4 bytes
        idLast:4 bytes
        pathCount:1 bytes
        isReset:1 bytes
        """
        (
            ehp_path_ctrl_id_first,
            ehp_path_ctrl_id_last,
            ehp_path_ctrl_path_count,
            ehp_path_ctrl_is_reset,
        ) = decode_udp_bytes_content(self.eth_udp, 44, 54, "<IIBB")
        return (
            ehp_path_ctrl_id_first,
            ehp_path_ctrl_id_last,
            ehp_path_ctrl_path_count,
            ehp_path_ctrl_is_reset,
        )

    def path_control_path(self):
        """
        Path info in pathControl content,every path length is 12 bytes:
            Id:4 bytes
            parentId:4 bytes
            offset:4 bytes
        Every pathControl udp package maybe 1 or more path info.The length is all path info.
        """
        length_, _, _, _ = self.ehp_head()
        all_path = ((length_ + 12) - 54) / 12
        path_info = list()
        for elem in range(0, int(all_path)):
            (
                ehp_path_ctrl_id_x,
                ehp_path_ctrl_parent_id_x,
                ehp_path_ctrl_path_offset_x,
            ) = decode_udp_bytes_content(
                self.eth_udp,
                54 + (elem * 12),
                54 + (elem + 1) * 12,
                "<III",  # From 54 bytes to 54+12
            )
            path_info.append(
                (
                    ehp_path_ctrl_id_x,
                    ehp_path_ctrl_parent_id_x,
                    ehp_path_ctrl_path_offset_x,
                )
            )
        return path_info


class ProfileControl(AdasisV3):
    def profile_control_path(self):
        """
        Path info in profileControl length is 8 bytes:
            pathId:4 bytes
            pathOffS:4 bytes
        Every profileControl maybe 1 or more path info.
        """
        length_, _, _, _ = self.ehp_head()
        all_path = ((length_ + 12) - 44) / 8
        path_list = list()
        if all_path != 0:
            for elem in range(0, int(all_path)):
                path_id, path_offset = decode_udp_bytes_content(
                    self.eth_udp, 44 + elem * 8, 44 + ((elem + 1) * 8), "<II"
                )
                path_list.append((path_id, path_offset))
        return path_list


class ProfileHead(AdasisV3):
    def profile_head(self):
        """
        Profile head in profile length is 27 bytes:
        instanceId:4 bytes
        Retransmis:1 byte
        change:1 byte
        confidence:4 bytes float type
        pathId:4 bytes
        laneNumber:1 byte
        offset:4 bytes
        endOffset:4 bytes
        endOffsetF:1 byte
        Interpolat:1 byte
        type:1 byte
        available:1 byte
        """
        (
            instance_id,
            retransmis,
            change,
            confidence,
            path_id,
            lane_number,
            offset,
            end_offset,
            end_offset_final,
            interpolat,
            profile_type,
            available,
        ) = decode_udp_bytes_content(self.eth_udp, 44, 71, "<I?BfIBII?BB?")
        return (
            instance_id,
            retransmis,
            change,
            confidence,
            path_id,
            lane_number,
            offset,
            end_offset,
            end_offset_final,
            interpolat,
            profile_type,
            available,
        )


class ProfileCurvature(ProfileHead):
    def profile_curvature(self):
        """
        Curvature info in profile every length is 8 bytes:
        offset:4 bytes
        curvature:4 bytes
        """
        cur_count = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        cur_list = list()
        if cur_count >= 1:

            for elem in range(0, cur_count):
                offset, curvature = decode_udp_bytes_content(
                    self.eth_udp, 72 + elem * 8, 72 + ((elem + 1) * 8), "<If"
                )
                cur_list.append([offset, curvature])
        return cur_list


class ProfileEffectiveSpeedLimit(ProfileHead):
    def speed_limit(self):
        speed_high, speed_low, speed_unit = decode_udp_bytes_content(
            self.eth_udp, 71, 74, "<BBB"
        )
        return speed_high, speed_low, speed_unit


class ProfileFormOfWay(ProfileHead):
    def link_form_way(self):
        link_form_of_way = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")
        return link_form_of_way


class ProfileFunctionalRoadClass(ProfileHead):
    def link_fun_class(self):
        fun_class = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")
        return fun_class


# Failed,1.24 version exclude
class ProfileGantry(ProfileHead):

    def gantry_info(self):
        """
        Decode gantry info
        :return: Gantry info list
        """
        length_, _, _, _ = self.ehp_head()
        gantry_all = ((length_ + 12) - 71) / 12
        gantry_list = list()

        for index_ in range(0, int(gantry_all)):
            (
                gantry_lat,
                gantry_lon,
                gantry_alt,
            ) = decode_udp_bytes_content(self.eth_udp, 71 + (index_ * 12), 71 + (index_ + 1) * 12, "<iii")
            gantry_list.append((gantry_lat, gantry_lon, gantry_alt))
        return gantry_list


class ProfileGeoFence(ProfileHead):
    def geo_fence_count(self):
        fence_count = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        # print("geoFenceCount:", fence_count)
        return fence_count

    def geo_fence_info(self):

        # length_,_,_,_=self.ehp_head()
        # fence_all=((length_+12)-73)/4
        fence_all = self.geo_fence_count()
        geo_fence_info = list()
        if fence_all > 0:

            # geo_fence_type,geo_fence_seq=decode_udp_bytes_content(self.eth_udp,72,74,'<Bb')
            # geo_fence_info.append(geo_fence_type,geo_fence_seq)
            for elem in range(0, int(fence_all)):
                (
                    geo_fence_type,
                    geo_fence_seq,
                    geo_fence_offset,
                    geo_fence_end_offset,
                ) = decode_udp_bytes_content(
                    self.eth_udp, 72 + (elem * 10), 72 + (elem + 1) * 10, "<BbII"
                )
                geo_fence_info.append(
                    (
                        geo_fence_type,
                        geo_fence_seq,
                        geo_fence_offset,
                        geo_fence_end_offset,
                    )
                )
            return geo_fence_info


# 1.24 version exclude
class ProfileGroundArrow(ProfileHead):
    def ground_arrow_info(self):
        length_, _, _, _ = self.ehp_head()
        ground_arrow_all = ((length_ + 12) - 71) / 12
        ground_arrow_list = list()

        for index_ in range(0, int(ground_arrow_all)):
            (
                gantry_lat,
                gantry_lon,
                gantry_alt,
            ) = decode_udp_bytes_content(self.eth_udp, 71 + (index_ * 12), 71 + (index_ + 1) * 12, "<iii")
            ground_arrow_list.append((gantry_lat, gantry_lon, gantry_alt))
        return ground_arrow_list


# 1.24 version exclude
class ProfileGroundText(ProfileHead):
    def ground_text_info(self):
        length_, _, _, _ = self.ehp_head()
        ground_text_all = ((length_ + 12) - 71) / 12
        ground_text_list = list()

        for index_ in range(0, int(ground_text_all)):
            (
                gantry_lat,
                gantry_lon,
                gantry_alt,
            ) = decode_udp_bytes_content(self.eth_udp, 71 + (index_ * 12), 71 + (index_ + 1) * 12, "<iii")
            ground_text_list.append((gantry_lat, gantry_lon, gantry_alt))
        return ground_text_list


class ProfileLaneConnectivity(ProfileHead):
    def lane_connectivity_count(self):
        lane_count = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        return lane_count

    def lane_connection_info(self):
        lanes_info = list()
        if self.lane_connectivity_count():
            for lane_ in range(0, self.lane_connectivity_count()):
                (
                    init_lane_number,
                    init_path,
                    new_lane_number,
                    new_path,
                    to_link_id,
                ) = decode_udp_bytes_content(
                    self.eth_udp, 72 + lane_ * 14, 72 + ((lane_ + 1) * 14), "<BIBII"
                )
                lanes_info.append(
                    (
                        init_lane_number,
                        init_path,
                        new_lane_number,
                        new_path,
                        to_link_id,
                    )
                )
        return lanes_info


class ProfileLaneModel(ProfileHead):
    def lane_total(self):
        lane_count = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")
        return lane_count

    def lane_infoes(self):
        length_, _, _, _ = self.ehp_head()
        lane_info_length = (length_ + 12) - 71
        lane_all = lane_info_length / 23

        lane_info_list = list()
        for elem in range(0, int(lane_all)):
            (
                lane_number,
                direction,
                transit,
                lane_type,
                lane_app_type,
                centeline,
                left_bound,
                right_bound,
            ) = decode_udp_bytes_content(
                self.eth_udp, 72 + (elem * 23), 72 + (elem + 1) * 23, "<BBBIIIII"
            )
            lane_info_list.append(
                (
                    lane_number,
                    direction,
                    transit,
                    lane_type,
                    lane_app_type,
                    centeline,
                    left_bound,
                    right_bound,
                )
            )
        return lane_info_list


class ProfileLanesGeometry(ProfileHead):
    def get_geometry_info(self):
        geometry_count, id_line, curve_type, point_count = decode_udp_bytes_content(
            self.eth_udp, 71, 78, "<BIBB"
        )
        return geometry_count, id_line, curve_type, point_count

    def get_geometry_contents(self):
        length_, _, _, _ = self.ehp_head()
        geo_info_length = (length_ + 12) - 77
        geo_all = geo_info_length / 12

        geo_list = list()

        for elem in range(0, int(geo_all)):
            lat, lon, alt = decode_udp_bytes_content(
                self.eth_udp, 78 + elem * 12, 78 + (elem + 1) * 12, "<iii"
            )
            geo_list.append((lat, lon, alt))
        return geo_list


class ProfileLaneWidth(ProfileHead):
    def get_lane_width(self):
        min_width, max_width = decode_udp_bytes_content(self.eth_udp, 71, 75, "<HH")
        return min_width, max_width


class ProfileLinearObjects(ProfileHead):
    def linear_object_total(self):
        total_linear_object = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        return total_linear_object

    def linear_object_info(self):
        length_, _, _, _ = self.ehp_head()
        linear_info_length = (length_ + 12) - 71
        linear_all = linear_info_length / 8

        line_info_list = list()
        for elem in range(0, int(linear_all)):
            (
                line_id,
                line_type,
                line_marking,
                line_color,
                line_bold,
            ) = decode_udp_bytes_content(
                self.eth_udp, 72 + elem * 8, 72 + (elem + 1) * 8, "<IBBBB"
            )
            line_info_list.append(
                (line_id, line_type, line_marking, line_color, line_bold)
            )
        return line_info_list


class ProfileLinkIdentifier(ProfileHead):
    def link_info(self):
        link_id = decode_udp_bytes_content(self.eth_udp, 71, 79, "<Q")[0]
        return link_id


class ProfileMergePoint(ProfileHead):
    def merge_point_count(self):
        point_count = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        return point_count

    def merge_point_info(self):
        length_, *_ = self.ehp_head()
        point_info_length = (length_ + 12) - 71
        merge_point_all = point_info_length / 9

        merge_point_list = list()

        for elem in range(0, int(merge_point_all)):
            path_id, offset, is_master = decode_udp_bytes_content(
                self.eth_udp, 72 + elem * 9, 72 + (elem + 1) * 9, "<II?"
            )
            merge_point_list.append((path_id, offset, is_master))
        return merge_point_list


class ProfileNode(ProfileHead):
    def node_count(self):
        nodes = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")
        return nodes

    def node_info(self):
        length_, _, _, _ = self.ehp_head()
        node_info_length = (length_ + 12) - 71
        node_point_all = node_info_length / 14

        node_point_list = list()
        for elem in range(0, int(node_point_all)):
            (
                sub_path,
                probability,
                turn_angle,
                comp_int_sec,
                right_of_way,
            ) = decode_udp_bytes_content(
                self.eth_udp, 72 + elem * 14, 72 + (elem + 1) * 14, "<Iff?B"
            )
            node_point_list.append((sub_path, probability, turn_angle, comp_int_sec, right_of_way))
        return node_point_list


class ProfileNumberOfLanesDrivingDirection(ProfileHead):
    def number_of_lane(self):
        number_ = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        return number_


# 1.24 version exclude
class ProfilePole(ProfileHead):
    def pole_type(self):
        pole_type = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        return pole_type

    def pole_info(self):
        pole_position = list()
        for index_ in range(9):
            # The pole coordinate list:center position and 8 bounding positions
            pos_ = decode_udp_bytes_content(self.eth_udp, 72 + index_ * 12, 72 + (index_ + 1) * 12, "<iii")
            pole_position.append(pos_)
        return pole_position  # pole_bounding_box


class ProfileRoadGeometry(ProfileHead):
    def road_geo_count(self):
        geo_count = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")
        return geo_count

    def road_geo_info(self):
        length_, _, _, _ = self.ehp_head()
        point_info_length = (length_ + 12) - 71
        merge_point_all = point_info_length / 12

        merge_point_list = list()

        for elem in range(0, int(merge_point_all)):
            road_geo_lat, road_geo_lon, road_geo_alt = decode_udp_bytes_content(
                self.eth_udp, 72 + elem * 12, 72 + (elem + 1) * 12, "<iii"
            )
            merge_point_list.append((road_geo_lat, road_geo_lon, road_geo_alt))
        return merge_point_list


class ProfileSlope(ProfileHead):
    def slope_count(self):
        slope_ = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")[0]
        return slope_

    def slope_info(self):
        length_, _, _, _ = self.ehp_head()
        slope_info_length = (length_ + 12) - 71
        slope_all = slope_info_length / 12

        slope_info_list = list()
        for elem in range(0, int(slope_all)):
            slope_offset, slope, cross_slope = decode_udp_bytes_content(
                self.eth_udp, 72 + elem * 12, 72 + (elem + 1) * 12, "<Iff"
            )
            slope_info_list.append((slope_offset, slope, cross_slope))
        return slope_info_list


# 1.24 version exclude
class ProfileTollgate(ProfileHead):
    def toll_gate(self):
        toll_ = decode_udp_bytes_content(self.eth_udp, 71, 72, "<?")[0]
        return toll_


# 1.24 version exclude ,failed
class ProfileTrafficSign(ProfileHead):
    def traffic_sign_type(self):
        type_, sharp_ = decode_udp_bytes_content(self.eth_udp, 71, 73, "<BB")
        return type_, sharp_

    def traffic_sign(self):
        traffic_sign_pos = list()
        for index_ in range(9):
            (
                traffic_sign_lat,
                traffic_sign_lon,
                traffic_sign_alt,
                # traffic_sign_bounding_box,
            ) = decode_udp_bytes_content(self.eth_udp, 73 + index_ * 12, 73 + (index_ + 1) * 12, "<iii")
            traffic_sign_pos.append((traffic_sign_lat, traffic_sign_lon, traffic_sign_alt))
        return traffic_sign_pos


class ProfileTunnel(ProfileHead):
    def tunnel_info(self):
        is_tunnel = decode_udp_bytes_content(self.eth_udp, 71, 72, "<?")[0]
        return is_tunnel


# Exclude
class DynamicInfoEvent(ProfileHead):
    def event_info(self):
        sub_type, traffic_speed, jam_level = decode_udp_bytes_content(
            self.eth_udp, 71, 75, "<HBB"
        )
        return sub_type, traffic_speed, jam_level

    def start_2_offset(self):
        start_offset, start_lat, start_lon = decode_udp_bytes_content(
            self.eth_udp, 75, 87, "<Iii"
        )
        return start_offset, start_lat, start_lon

    def end_2_offset(self):
        end_offset, end_lat, end_lon = decode_udp_bytes_content(
            self.eth_udp, 87, 99, "<Iii"
        )
        return end_offset, end_lat, end_lon


# Exclude
class DynamicInfoMeteorology(ProfileHead):
    def meteorology_info(self):
        precipitation, wind_direction, wind_scale, weather = decode_udp_bytes_content(
            self.eth_udp, 71, 78, "<IBBB"
        )
        return precipitation, wind_direction, wind_scale, weather


# Exclude
class DynamicInfoEmergency(ProfileHead):
    def emergency_count(self):
        total_count = decode_udp_bytes_content(self.eth_udp, 71, 72, "<B")
        return total_count

    def emergency_info(self):
        count_ = self.emergency_count()

        emg_info_list = list()
        for elem in range(0, count_):
            emg_ = decode_udp_bytes_content(
                self.eth_udp, 72 + elem * 4, 72 + (elem + 1) * 4, "<I"
            )
            emg_info_list.append(emg_)
        return emg_info_list
