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
    pass
