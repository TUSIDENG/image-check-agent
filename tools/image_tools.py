import asyncio
import requests
from typing import Dict, Union, Optional
from datetime import datetime
import time
from pydantic import BaseModel, Field
from langchain_core.tools import tool, ToolException

# 定义工具输入模型
class ImageCheckInput(BaseModel):
    image_name: str = Field(..., description="要检查的Docker镜像名称，例如 'nginx:latest' 或 'hello-world'")
    registry: Optional[str] = Field(default=None, description="可选的镜像注册表地址，例如 'docker.io' 或 'myregistry.com'")
    timeout: float = Field(default=30.0, description="HTTP请求超时时间（秒）")

def _parse_image_name(image_name: str, registry_override: Optional[str]) -> Dict[str, str]:
    """解析镜像名称，提取注册表、仓库和标签"""
    
    # 默认注册表
    default_registry = 'registry-1.docker.io'
    
    # 1. 确定最终注册表
    if registry_override:
        # 如果提供了 registry 参数，使用它
        registry = registry_override
    else:
        # 否则，尝试从 image_name 中解析
        parts = image_name.split('/')
        if '.' in parts[0] and len(parts) > 1:
            # image_name 包含注册表 (e.g., 'myregistry.com/myimage:tag')
            registry = parts[0]
            image_name = '/'.join(parts[1:]) # 移除注册表部分
        elif '.' in parts[0] and len(parts) == 1 and ':' in parts[0]:
            # 仅包含 registry:port (e.g., 'myregistry.com:5000') - treat as registry
            registry = parts[0]
            image_name = ''
        else:
            # 否则，不包含注册表，默认为 Docker Hub
            registry = default_registry
            
    # 移除协议头，确保 registry 只是主机名
    if registry.startswith('https://'):
        registry = registry[len('https://'):]
    elif registry.startswith('http://'):
        registry = registry[len('http://'):]
            
    # 2. 解析仓库和标签
    if ':' not in image_name:
        repository = image_name
        tag = 'latest'
    else:
        repository, tag = image_name.split(':', 1)

    # 3. 处理 Docker Hub 官方镜像 (e.g., 'hello-world' -> 'library/hello-world')
    if registry == default_registry and '/' not in repository:
        repository = f'library/{repository}'

    return {
        'registry': registry,
        'repository': repository,
        'tag': tag
    }

def _check_image_manifest_sync(image_name: str, registry: Optional[str], timeout: float) -> Dict[str, Union[bool, str, float]]:
    """同步函数：通过 Docker Registry API 检查镜像清单是否存在"""
    
    parsed = _parse_image_name(image_name, registry)
    registry_host = parsed['registry']
    repository = parsed['repository']
    tag = parsed['tag']
    
    # 1. 获取认证 token (对于 Docker Hub 公共镜像，通常需要先获取 token)
    # 注意：对于非 Docker Hub 注册表，认证流程可能不同，这里仅实现 Docker Hub 兼容的公共访问
    is_docker_hub_or_mirror = (registry_host == 'registry-1.docker.io' or
                               registry_host.endswith('docker.io') or
                               'daocloud.io' in registry_host)
                               
    token = None
    
    start_time = time.time()
    
    try:
        if is_docker_hub_or_mirror:
            # 对于 Docker Hub 及其镜像，认证仍需指向 Docker Hub 官方认证服务
            token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
            
            # 尝试获取 token
            token_response = requests.get(token_url, timeout=timeout)
            token_response.raise_for_status()
            token = token_response.json().get('token')
            
            if not token:
                # 如果无法获取 token，尝试匿名访问
                pass

        # 2. 构造 manifest URL
        # 注册表 API 访问通常使用 HTTPS
        manifest_url = f"https://{registry_host}/v2/{repository}/manifests/{tag}"
        
        headers = {
            # 接受 V2 Manifest Schema 2 或 V1
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/json'
        }
        if token:
            headers['Authorization'] = f'Bearer {token}'
        
        # 3. 发送 HEAD 请求检查 manifest
        manifest_response = requests.head(manifest_url, headers=headers, timeout=timeout)
        
        response_time = (time.time() - start_time) * 1000
        
        if manifest_response.status_code == 200:
            return {
                'success': True,
                'image_name': image_name,
                'registry': registry_host,
                'response_time_ms': round(response_time, 2),
                'timestamp': datetime.now().isoformat(),
                'error': None,
                'status_code': manifest_response.status_code,
                'message': f"Image manifest found (Status: {manifest_response.status_code})"
            }
        elif manifest_response.status_code == 404:
            return {
                'success': False,
                'image_name': image_name,
                'registry': registry_host,
                'response_time_ms': round(response_time, 2),
                'timestamp': datetime.now().isoformat(),
                'error': f"Image manifest not found (Status: {manifest_response.status_code})",
                'status_code': manifest_response.status_code,
                'message': f"Image manifest not found (Status: {manifest_response.status_code})"
            }
        else:
            # 抛出其他 HTTP 错误，例如 401 (Unauthorized)
            manifest_response.raise_for_status() 

    except requests.exceptions.RequestException as e:
        response_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'image_name': image_name,
            'registry': registry_host,
            'response_time_ms': round(response_time, 2),
            'timestamp': datetime.now().isoformat(),
            'error': f"HTTP Request Error: {e}",
            'status_code': None,
            'message': str(e)
        }
    except Exception as e:
        response_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'image_name': image_name,
            'registry': registry_host,
            'response_time_ms': round(response_time, 2),
            'timestamp': datetime.now().isoformat(),
            'error': f"An unexpected error occurred: {e}",
            'status_code': None,
            'message': str(e)
        }


@tool
async def check_image_pull(input_data: ImageCheckInput) -> Dict[str, Union[bool, str, float, int]]:
    """尝试通过 Docker Registry API 检查指定的Docker镜像清单是否存在，模拟拉取检查。
    不可以用于检测非开发镜像，有报错：401 Client Error: Unauthorized for url: https://docker.m.daocloud.io/v2/hello-world/manifests/latest
    
    Args:
        input_data: 包含以下字段的ImageCheckInput对象：
            - image_name: 要检查的Docker镜像名称，例如 'nginx:latest' 或 'hello-world'
            - registry: 可选的镜像注册表地址，例如 'docker.io' 或 'myregistry.com'。如果未提供，则从 image_name 中解析或默认为 Docker Hub。
            - timeout: HTTP请求超时时间，单位为秒。
            
    Returns:
        包含镜像检查结果的字典，包括成功状态、响应时间、HTTP状态码等信息。
    """
    # 使用 asyncio.to_thread 在单独的线程中运行同步的 HTTP 操作
    return await asyncio.to_thread(
        _check_image_manifest_sync, 
        input_data.image_name, 
        input_data.registry,
        input_data.timeout
    )

# 使用示例
if __name__ == '__main__':
    import asyncio
    
    async def run_async_tests():
        """运行异步测试示例"""
        # 1. 检查 Docker Hub 官方镜像 (默认注册表)
        image_input_success = ImageCheckInput(
            image_name='hello-world',
            timeout=10.0
        )
        
        # 2. 检查 Docker Hub 非官方镜像 (指定注册表)
        image_input_zd = ImageCheckInput(
            image_name='hello-world',
            registry='docker.m.daocloud.io', # 使用镜像加速器
            timeout=10.0
        )
        
        # 3. 检查一个不存在的镜像
        image_input_fail = ImageCheckInput(
            image_name='nonexistent-image-for-test:latest',
            timeout=10.0
        )
        
        # 异步调用工具函数
        print("--- Checking existing official image (hello-world) ---")
        image_result_success = await check_image_pull.ainvoke(input={"input_data":image_input_success})
        print("Image Pull Check Result (Success):", image_result_success)
        
        print("\n--- Checking existing official image (nginx:latest) with explicit registry ---")
        image_result_zd = await check_image_pull.ainvoke(input={"input_data":image_input_zd})
        print("Image Pull Check Result (Nginx):", image_result_zd)
        
        print("\n--- Checking non-existent image ---")
        image_result_fail = await check_image_pull.ainvoke(input={"input_data":image_input_fail})
        print("Image Pull Check Result (Fail):", image_result_fail)
        
    # 运行异步测试
    asyncio.run(run_async_tests())