import struct


class IpParesor:
    HEADER_LENGTH = 20

    def paresing_header(self, packet):
        header_packet = packet[:self.HEADER_LENGTH]
        header_result = {}

        # 解析ip_version, header_length, service_type, packet_length
        line1 = header_packet[:4]
        line1_result = struct.unpack('>BBH', line1)
        ip_version = line1_result[0] >> 4
        header_length = line1_result[0] & 15
        service_type = line1_result[1]
        packet_length = line1_result[2]

        # 解析identification, tag, packet_offset
        line2 = header_packet[4:8]
        line2_result = struct.unpack('>HBB', line2)
        identification = line2_result[0]
        tag = line2_result[1] >> 5
        line2_result = struct.unpack('>HH', line2)
        packet_offset = line2_result[1] & 8191

        # 解析ttl, packet_protocol, header_checksum
        line3 = header_packet[8:12]
        line3_result = struct.unpack('>BBH', line3)
        ttl = line3_result[0]
        packet_protocol = line3_result[1]
        header_checksum = line3_result[2]

        # 解析source_ip
        line4 = header_packet[12:16]
        line4_result = struct.unpack('>BBBB', line4)
        ip_list = [str(item) for item in line4_result]
        source_ip = '.'.join(ip_list)

        # 解析destination_ip
        line5 = header_packet[16:20]
        line5_result = struct.unpack('>BBBB', line5)
        ip_list5 = [str(item) for item in line5_result]
        destination_ip = '.'.join(ip_list5)

        header_result['ip_version'] = ip_version
        header_result['header_length'] = header_length
        header_result['service_type'] = service_type
        header_result['packet_length'] = packet_length
        header_result['identification'] = identification
        header_result['tag'] = tag
        header_result['packet_offset'] = packet_offset
        header_result['ttl'] = ttl
        header_result['packet_protocol'] = packet_protocol
        header_result['header_checksum'] = header_checksum
        header_result['source_ip'] = source_ip
        header_result['destination_ip'] = destination_ip

        return header_result
