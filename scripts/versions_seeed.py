#! /usr/bin/env python3
from dotenv import load_dotenv
load_dotenv()

import os
import struct
import zipfile
import boto3
from botocore.config import Config
import json
import requests
from requests.exceptions import RequestException
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def extract_zip(zip_path, extract_path):
    if not os.path.exists(extract_path):
        os.makedirs(extract_path)
    logger.info(f"Extracting {zip_path} to {extract_path}")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

def post_info_to_server(info, firmware_dir):
    """
    将固件信息和文件发送到服务器
    
    Args:
        info: 包含固件信息的字典
        firmware_dir: 固件目录路径
    """
    try:
        logger.info("开始上传固件到服务器")
        
        # 从环境变量获取服务器URL和token
        server_url = os.environ.get('VERSIONS_SERVER_URL')
        server_token = os.environ.get('VERSIONS_TOKEN')
        
        if not server_url or not server_token:
            logger.error("缺少服务器配置")
            logger.error("需要: VERSIONS_SERVER_URL, VERSIONS_TOKEN")
            raise Exception("Missing SERVER_URL or TOKEN in environment variables")

        logger.info(f"使用服务器: {server_url}")

        # 准备请求头
        headers = {
            'Authorization': f'Bearer {server_token}'
        }
        
        # 准备multipart/form-data请求
        files = {
            'xiaozhi_bin': ('xiaozhi.bin', open(os.path.join(firmware_dir, 'xiaozhi.bin'), 'rb'), 'application/octet-stream'),
            'merged_binary_bin': ('merged-binary.bin', open(os.path.join(firmware_dir, 'merged-binary.bin'), 'rb'), 'application/octet-stream'),
            'info_json': ('info.json', open(os.path.join(firmware_dir, 'info.json'), 'rb'), 'application/json')
        }
        
        data = {
            'jsonData': json.dumps(info)
        }
        
        # 发送POST请求
        logger.info("发送固件和版本信息...")
        response = requests.post(
            server_url,
            headers=headers,
            files=files,
            data=data
        )
        
        # 打印响应信息
        logger.info("HTTP响应详情:")
        logger.info(f"Status Code: {response.status_code}")
        logger.info(f"Response Headers: {json.dumps(dict(response.headers), indent=2)}")
        try:
            response_json = response.json()
            logger.info(f"Response Body: {json.dumps(response_json, indent=2)}")
        except:
            logger.info(f"Response Body: {response.text}")
        
        # 检查响应状态
        response.raise_for_status()
        
        logger.info(f"固件上传成功: {info['tag']}")
        
    except RequestException as e:
        if hasattr(e.response, 'json'):
            error_msg = e.response.json().get('error', str(e))
        else:
            error_msg = str(e)
        logger.error(f"固件上传失败: {error_msg}")
        raise
    except Exception as e:
        logger.error(f"固件上传错误: {str(e)}")
        raise
    finally:
        # 关闭所有打开的文件
        for file in files.values():
            file[1].close()

def get_chip_id_string(chip_id):
    return {
        0x0000: "esp32",
        0x0002: "esp32s2",
        0x0005: "esp32c3",
        0x0009: "esp32s3",
        0x000C: "esp32c2",
        0x000D: "esp32c6",
        0x0010: "esp32h2",
        0x0011: "esp32c5",
        0x0012: "esp32p4",
        0x0017: "esp32c5",
    }[chip_id]

def get_flash_size(size):
    return {
        0x0: "1MB",
        0x1: "2MB",
        0x2: "4MB",
        0x3: "8MB",
        0x4: "16MB",
        0x5: "32MB",
        0x6: "64MB",
        0x7: "128MB",
    }[size]

def get_app_desc(data):
    magic = struct.unpack("<I", data[0x00:0x04])[0]
    if magic != 0xabcd5432:
        raise Exception("Invalid app desc magic")
    version = data[0x10:0x30].decode("utf-8").strip('\0')
    project_name = data[0x30:0x50].decode("utf-8").strip('\0')
    time = data[0x50:0x60].decode("utf-8").strip('\0')
    date = data[0x60:0x70].decode("utf-8").strip('\0')
    idf_ver = data[0x70:0x90].decode("utf-8").strip('\0')
    elf_sha256 = data[0x90:0xb0].hex()
    return {
        "name": project_name,
        "version": version,
        "compile_time": date + "T" + time,
        "idf_version": idf_ver,
        "elf_sha256": elf_sha256,
    }

def get_board_name(dir_path):
    # Extract board name from directory path
    return os.path.basename(dir_path).split('_')[1] if '_' in os.path.basename(dir_path) else "unknown"

def read_binary(dir_path):
    merged_bin_path = os.path.join(dir_path, "merged-binary.bin")
    if not os.path.exists(merged_bin_path):
        logger.error(f"File not found: {merged_bin_path}")
        return None
        
    try:
        merged_bin_data = open(merged_bin_path, "rb").read()
    except Exception as e:
        logger.error(f"Error reading {merged_bin_path}: {str(e)}")
        return None

    # find app partition
    if merged_bin_data[0x100000] == 0xE9:
        data = merged_bin_data[0x100000:]
    elif merged_bin_data[0x200000] == 0xE9:
        data = merged_bin_data[0x200000:]
    else:
        logger.error(f"{dir_path} is not a valid image")
        return None

    # get flash size
    flash_size = get_flash_size(data[0x3] >> 4)
    chip_id = get_chip_id_string(data[0xC])
    
    # get segments
    segment_count = data[0x1]
    segments = []
    offset = 0x18
    for i in range(segment_count):
        segment_size = struct.unpack("<I", data[offset + 4:offset + 8])[0]
        offset += 8
        segment_data = data[offset:offset + segment_size]
        offset += segment_size
        segments.append(segment_data)
    assert offset < len(data), "offset is out of bounds"
    
    # extract bin file
    bin_path = os.path.join(dir_path, "xiaozhi.bin")
    if not os.path.exists(bin_path):
        logger.info(f"extract bin file to {bin_path}")
        open(bin_path, "wb").write(data)

    # The app desc is in the first segment
    desc = get_app_desc(segments[0])
    return {
        "chip_id": chip_id,
        "flash_size": flash_size,
        "board": get_board_name(dir_path),
        "application": desc,
        "firmware_size": len(data),
    }

def main():
    logger.info("开始处理固件发布")
    
    # 检查环境变量
    required_vars = [
        'VERSIONS_SERVER_URL',
        'VERSIONS_TOKEN'
    ]
    
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    if missing_vars:
        logger.error("缺少必要的环境变量:")
        for var in missing_vars:
            logger.error(f"  - {var}")
        return
    
    logger.info("环境变量检查完成")
    
    release_dir = "releases"
    # 确保releases目录存在
    if not os.path.exists(release_dir):
        logger.info(f"创建目录: {release_dir}")
        os.makedirs(release_dir)
        logger.info(f"目录创建完成: {release_dir}")
        return  # 如果目录是新创建的，直接返回，因为没有文件需要处理
    
    # look for zip files startswith "v"
    zip_files = [f for f in os.listdir(release_dir) if f.startswith("v") and f.endswith(".zip")]
    logger.info(f"找到 {len(zip_files)} 个固件包")
    
    for name in zip_files:
        logger.info(f"处理固件包: {name}")
        tag = name[:-4]
        folder = os.path.join(release_dir, tag)
        info_path = os.path.join(folder, "info.json")
        
        if not os.path.exists(info_path):
            logger.info(f"处理新固件: {tag}")
            if not os.path.exists(folder):
                logger.info(f"创建目录: {folder}")
                os.makedirs(folder)
                logger.info(f"解压固件包: {name}")
                extract_zip(os.path.join(release_dir, name), folder)
                
                # 检查解压后的文件是否存在
                merged_bin_path = os.path.join(folder, "merged-binary.bin")
                if not os.path.exists(merged_bin_path):
                    logger.error(f"解压失败: {merged_bin_path} 不存在")
                    continue
            
            logger.info("读取固件信息")
            info = read_binary(folder)
            if info is None:
                logger.error(f"无法读取固件信息: {tag}")
                continue
                
            info["tag"] = tag
            
            logger.info("保存固件信息")
            open(info_path, "w").write(json.dumps(info, indent=4))
            
            logger.info("上传固件到服务器")
            post_info_to_server(info, folder)
        else:
            logger.info(f"跳过已处理的固件: {tag}")

    logger.info("固件处理完成")

if __name__ == "__main__":
    main()