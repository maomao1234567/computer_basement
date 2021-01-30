import struct


class TcpParesor:
    HEADER_LENGTH = 20

    def paresing_header(self, packet):
        header_packet = packet[:self.HEADER_LENGTH]
        tcp_header_result = {}

        # 解析source_port, destination_port
        line1 = header_packet[:4]
        line1_result = struct.unpack('>HH', line1)
        source_port = line1_result[0]
        destination_port = line1_result[1]

        # 解析sequence
        line2 = header_packet[4:8]
        line2_result = struct.unpack('>L', line2)
        sequence = line2_result[0]

        # 解析acknowledgement
        line3 = header_packet[8:12]
        line3_result = struct.unpack('>L', line3)
        acknowledgement = line3_result[0]

        # 解析header_length, reserve_data, packet_tag, window
        line4 = header_packet[12:16]
        line4_result = struct.unpack('>BBH', line4)
        window = line4_result[2]
        header_length = line4_result[0] >> 4

        bin_str = str(bin(line4_result[0])) + str(bin(line4_result[1]))
        bin_str_list = bin_str.split('b')
        new_bin_str = ''.join(bin_str_list)
        reserve_data = int(new_bin_str[4:10], 2)
        packet_tag = int(new_bin_str[10:16], 2)

        # 解析packet_checksum, urgent_point
        line5 = header_packet[16:20]
        line5_result = struct.unpack('>HH', line5)
        packet_checksum = line5_result[0]
        urgent_point = line5_result[1]

        tcp_header_result['source_port'] = source_port
        tcp_header_result['destination_port'] = destination_port
        tcp_header_result['sequence'] = sequence
        tcp_header_result['acknowledgement'] = acknowledgement
        tcp_header_result['header_length'] = header_length
        tcp_header_result['reserve_data'] = reserve_data
        tcp_header_result['packet_tag'] = packet_tag
        tcp_header_result['window'] = window
        tcp_header_result['packet_checksum'] = packet_checksum
        tcp_header_result['urgent_point'] = urgent_point

        return tcp_header_result
