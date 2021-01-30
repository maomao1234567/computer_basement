from computer_network.paresors.tcp_paresor import TcpParesor


def test_tcp_paresor():
    tcp_paresor = TcpParesor()
    assert tcp_paresor.HEADER_LENGTH == 20


def test_parsing_tcp_header():
    """解析Tcp包中的header数据，这里处理Tcp包header的大小只能有20字节,默认的header字段：
    line1 4字节：source_port 16位，destination_port 16位
    line2 4字节：sequence 32位
    line3 4字节：acknowledgement 32位
    line4 4字节：header_length 4位，reserve_data 6, packet_tag 6位, window 16位
    line5 4字节：packet_checksum 16位，urgent_point 16位
    """
    # 模拟21个字节的Tcp packet
    # 对应的ASCII的数值为65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85
    # 对应的二进制数据为,01000001, 01000010, 01000011, 01000100
    #                  01000101, 01000110, 01000111, 01001001
    #                   01001010，01001011, 01001100, 01001101,
    #                   01001110, 01001111, 01010000, 01010001,
    #                   01010010, 01010011, 01010100, 01010101, 01010110
    tcp_packet = b'ABCDEFGHIJKLMNOPQRST'

    tcp_paresor = TcpParesor()

    tcp_header = tcp_paresor.paresing_header(tcp_packet)
    assert tcp_header['source_port'] == 16706
    assert tcp_header['destination_port'] == 17220
    assert tcp_header['sequence'] == 1162233672
    assert tcp_header['acknowledgement'] == 1229605708
    assert tcp_header['header_length'] == 4
    assert tcp_header['reserve_data'] == 53
    assert tcp_header['packet_tag'] == 14
    assert tcp_header['window'] == 20304
    assert tcp_header['packet_checksum'] == 20818
    assert tcp_header['urgent_point'] == 21332
