import socket
import struct
import requests
from typing import Dict, Union, List, Optional, Tuple, Annotated
from datetime import datetime
import time
import random
from pydantic import BaseModel, Field
from langchain_core.tools import tool,ToolException

# 定义工具输入模型
class DNSCheckInput(BaseModel):
    domain: str = Field(..., description="要检查的域名，例如 'example.com'")
    record_type: str = Field(default='A', description="DNS记录类型，支持 'A'(IPv4), 'AAAA'(IPv6)")
    nameserver: str = Field(default='8.8.8.8', description="DNS服务器地址")

class PortCheckInput(BaseModel):
    host: str = Field(..., description="主机名或IP地址")
    port: int = Field(..., description="要检查的端口号，范围 1-65535")
    timeout: float = Field(default=3.0, description="连接超时时间（秒）")

class HTTPCheckInput(BaseModel):
    url: str = Field(..., description="要检查的URL")
    method: str = Field(default='GET', description="HTTP请求方法")
    headers: Optional[Dict[str, str]] = Field(default=None, description="可选的HTTP请求头")
    data: Optional[Dict] = Field(default=None, description="POST请求时的数据")
    timeout: float = Field(default=10.0, description="请求超时时间（秒）")
    verify_ssl: bool = Field(default=True, description="是否验证SSL证书")

def create_dns_query(domain: str, record_type: int = 1) -> bytes:
    """创建DNS查询报文
    
    Args:
        domain: 域名
        record_type: 记录类型（1=A, 28=AAAA, 15=MX, 5=CNAME）
    
    Returns:
        DNS查询报文
    """
    # 生成随机事务ID
    transaction_id = random.randint(0, 65535)
    
    # 构建DNS头部
    # QR=0 (查询), OPCODE=0 (标准查询), RD=1 (期望递归)
    flags = 0x0100
    
    # 计数器：问题数=1，其他=0
    qdcount = 1
    ancount = nscount = arcount = 0
    
    # 打包头部
    header = struct.pack('!HHHHHH', 
        transaction_id, flags, qdcount, ancount, nscount, arcount)
    
    # 处理域名部分
    qname = b''
    for part in domain.encode().split(b'.'):
        qname += bytes([len(part)]) + part
    qname += b'\x00'  # 域名结束符
    
    # 打包问题部分（QTYPE和QCLASS）
    question = struct.pack('!HH', record_type, 1)  # 1 = IN类
    
    return header + qname + question

@tool
async def check_dns(input_data: DNSCheckInput) -> Dict[str, Union[bool, str, List[str]]]:
    """使用UDP Socket发送DNS查询检查指定域名

    Args:
        input_data: 包含以下字段的DNSCheckInput对象：
            - domain: 要检查的域名，例如 'example.com'
            - record_type: DNS记录类型，支持 'A'(IPv4), 'AAAA'(IPv6)
            - nameserver: DNS服务器地址，默认使用Google DNS 8.8.8.8

    Returns:
        包含DNS查询结果的字典，包括解析记录、响应时间等信息
    """
    domain = input_data.domain
    record_type = input_data.record_type
    nameserver = input_data.nameserver
    # DNS记录类型映射
    record_types = {
        'A': 1,
        'AAAA': 28,
        'MX': 15,
        'CNAME': 5
    }
    
    if record_type not in record_types:
        return {
            'success': False,
            'domain': domain,
            'record_type': record_type,
            'records': [],
            'response_time_ms': None,
            'timestamp': datetime.now().isoformat(),
            'error': f'Unsupported record type: {record_type}'
        }
    
    try:
        # 创建UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        
        # 创建DNS查询报文
        query = create_dns_query(domain, record_types[record_type])
        
        # 发送查询并记录时间
        start_time = time.time()
        sock.sendto(query, (nameserver, 53))
        
        # 接收响应
        response, _ = sock.recvfrom(512)
        response_time = (time.time() - start_time) * 1000
        
        # 关闭socket
        sock.close()
        
        # 简单解析响应（仅检查响应码）
        if len(response) < 12:
            raise Exception("Response too short")
        
        # 解析DNS响应头
        _, flags, _, ancount, _, _ = struct.unpack('!HHHHHH', response[:12])
        
        # 检查响应码（最后4位）
        rcode = flags & 0x000F
        if rcode != 0:
            raise Exception(f"DNS response code: {rcode}")
            
        # 通过getaddrinfo获取实际IP地址（简化处理）
        records = []
        if ancount > 0:
            try:
                addrs = socket.getaddrinfo(domain, None)
                for addr in addrs:
                    if ((record_type == 'A' and addr[0] == socket.AF_INET) or 
                        (record_type == 'AAAA' and addr[0] == socket.AF_INET6)):
                        records.append(addr[4][0])
            except socket.gaierror:
                pass
        
        return {
            'success': True,
            'domain': domain,
            'record_type': record_type,
            'records': list(set(records)),  # 去重
            'response_time_ms': round(response_time, 2),
            'timestamp': datetime.now().isoformat(),
            'error': None
        }
        
    except Exception as e:
        return {
            'success': False,
            'domain': domain,
            'record_type': record_type,
            'records': [],
            'response_time_ms': None,
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }

async def check_port(input_data: PortCheckInput) -> Dict[str, Union[bool, str, float]]:
    """使用TCP连接检查指定主机端口是否开放

    Args:
        input_data: 包含以下字段的PortCheckInput对象：
            - host: 主机名或IP地址，例如 'example.com' 或 '192.168.1.1'
            - port: 要检查的端口号，范围 1-65535
            - timeout: 连接超时时间，单位为秒

    Returns:
        包含端口检查结果的字典，包括连接状态、响应时间等信息
    """
    host = input_data.host
    port = input_data.port
    timeout = input_data.timeout
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((host, port))
        response_time = (time.time() - start_time) * 1000  # 转换为毫秒
        
        sock.close()
        
        return {
            'success': result == 0,
            'host': host,
            'port': port,
            'response_time_ms': round(response_time, 2),
            'timestamp': datetime.now().isoformat(),
            'error': None if result == 0 else f'Port {port} is closed'
        }
    except Exception as e:
        return {
            'success': False,
            'host': host,
            'port': port,
            'response_time_ms': None,
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }

async def check_http_response(input_data: HTTPCheckInput) -> Dict[str, Union[bool, str, float, int]]:
    """检查HTTP服务的可用性和响应状态

    Args:
        input_data: 包含以下字段的HTTPCheckInput对象：
            - url: 要检查的URL，例如 'https://example.com'
            - method: HTTP请求方法，支持 'GET', 'POST' 等
            - headers: 可选的HTTP请求头，例如 {'User-Agent': 'MyBot'}
            - data: POST请求时的数据
            - timeout: 请求超时时间，单位为秒
            - verify_ssl: 是否验证SSL证书

    Returns:
        包含HTTP检查结果的字典，包括状态码、响应时间、内容长度等信息
    """
    url = input_data.url
    method = input_data.method
    headers = input_data.headers
    data = input_data.data
    timeout = input_data.timeout
    verify_ssl = input_data.verify_ssl
    try:
        start_time = time.time()
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers or {},
            json=data if method.upper() != 'GET' else None,
            timeout=timeout,
            verify=verify_ssl
        )
        response_time = (time.time() - start_time) * 1000  # 转换为毫秒
        
        return {
            'success': True,
            'url': url,
            'status_code': response.status_code,
            'response_time_ms': round(response_time, 2),
            'content_length': len(response.content),
            'timestamp': datetime.now().isoformat(),
            'error': None
        }
    except Exception as e:
        return {
            'success': False,
            'url': url,
            'status_code': None,
            'response_time_ms': None,
            'content_length': None,
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }


# 使用示例
if __name__ == '__main__':
    import asyncio
    
    async def run_async_tests():
        """运行异步测试示例"""
        # 创建输入数据对象
        dns_input = DNSCheckInput(
            domain='google.com',
            record_type='A'
        )
        
        port_input = PortCheckInput(
            host='google.com',
            port=443
        )
        
        http_input = HTTPCheckInput(
            url='https://www.google.com'
        )
        
        # 异步调用工具函数
        dns_result = await check_dns.ainvoke(input={"input_data":dns_input})
        print("DNS Check Result:", dns_result)
        
        port_result = await check_port(port_input)
        print("Port Check Result:", port_result)
        
        http_result = await check_http_response(http_input)
        print("HTTP Check Result:", http_result)
    
    # 运行异步测试
    asyncio.run(run_async_tests())
