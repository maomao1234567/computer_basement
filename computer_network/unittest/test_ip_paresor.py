from computer_network.paresors.ip_paresor import IpParesor


def test_ip_paresor():
    ip_paresor = IpParesor()
    assert ip_paresor.HEADER_LENGTH == 20


def test_parsing_ip_header():
    """解析Ip包中的header数据，这里处理ip包header的大小只能有20字节,默认的header字段：
    line1 4字节：ip_version 4位，header_length 4位，service_type 8位，packet_length 16位
    line2 4字节：identification 16位， tag 3位， packet_offset 13位
    line3 4字节：ttl 8位，packet_protocol 8位， header_checksum 16位
    line4 4字节：source_ip 16位
    line5 4字节：destination_ip 16位
    """
    # 模拟21个字节的IP packet
    # 对应的ASCII的数值为65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85
    # 对应的二进制数据为,01000001, 01000010, 01000011, 01000100
    #                  01000101, 01000110, 01000111, 01001001
    #                   01001010，01001011, 01001100, 01001101,
    #                   01001110, 01001111, 01010000, 01010001,
    #                   01010010, 01010011, 01010100, 01010101, 01010110
    ip_packet = b'ABCDEFGHIJKLMNOPQRST'

    ip_paresor = IpParesor()

    ip_header = ip_paresor.paresing_header(ip_packet)
    assert ip_header['ip_version'] == 4
    assert ip_header['header_length'] == 1
    assert ip_header['service_type'] == 66
    assert ip_header['packet_length'] == 17220
    assert ip_header['identification'] == 17734
    assert ip_header['tag'] == 2
    assert ip_header['packet_offset'] == 1864
    assert ip_header['ttl'] == 73
    assert ip_header['packet_protocol'] == 74
    assert ip_header['header_checksum'] == 19276
    assert ip_header['source_ip'] == '77.78.79.80'
    assert ip_header['destination_ip'] == '81.82.83.84'

