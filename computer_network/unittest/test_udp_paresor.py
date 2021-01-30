from computer_network.paresors.udp_paresor import UDPParesor


def test_udp_paresor():
    udp_paresor = UDPParesor()
    assert udp_paresor.HEADER_LENGTH == 8


def test_parsing_udp_header():
    """解析udp包中的header数据，这里处理udp包header的大小只能有8字节,默认的header字段：
    line1 4字节：source_port 16位，destination_port 16位
    line2 4字节：packet_length 16位， packet_checksum 16位
    """
    # 模拟9个字节的IP packet
    # 对应的ASCII的数值为65,66,67,68,69,70,71,72,73,74
    # 对应的二进制数据为,01000001, 01000010, 01000011, 01000100
    #                  01000101, 01000110, 01000111, 01001001
    #                   01001010
    udp_packet = b'ABCDEFGHI'

    udp_paresor = UDPParesor()

    udp_header = udp_paresor.paresing_header(udp_packet)
    assert udp_header['source_port'] == 16706
    assert udp_header['destination_port'] == 17220
    assert udp_header['packet_length'] == 17734
    assert udp_header['packet_checksum'] == 18248

