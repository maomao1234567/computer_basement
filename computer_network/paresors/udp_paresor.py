import struct


class UDPParesor:
    HEADER_LENGTH = 8

    def paresing_header(self, packet):
        udp_header = packet[:self.HEADER_LENGTH]
        udp_header_result = {}

        # 解析source_port, destination_port
        line1 = udp_header[:4]
        line1_result = struct.unpack('>HH', line1)
        source_port = line1_result[0]
        destination_port = line1_result[1]

        # 解析packet_length, packet_checksum
        line2 = udp_header[4:8]
        line2_result = struct.unpack('>HH', line2)
        packet_length = line2_result[0]
        packet_checksum = line2_result[1]

        udp_header_result['source_port'] = source_port
        udp_header_result['destination_port'] = destination_port
        udp_header_result['packet_length'] = packet_length
        udp_header_result['packet_checksum'] = packet_checksum

        return udp_header_result
