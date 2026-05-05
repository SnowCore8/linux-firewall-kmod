#!/usr/bin/env python3
"""
自动翻译脚本：对比 site-docs/ 中的 .zh.md 和 .en.md 文件，
使用 Google Translate 公共 API 进行双向翻译同步。

使用方法:
    python scripts/auto_translate.py

依赖安装:
    pip install -r scripts/requirements.txt
"""

import os
import re
import time
import sys
import logging
import requests
from pathlib import Path

try:
    from deep_translator import GoogleTranslator
except ImportError:
    print("错误: 未安装 deep-translator 库")
    print("请运行: pip install -r scripts/requirements.txt")
    sys.exit(1)

# === 配置常量 ===
DOCS_DIR = "site-docs"
MAX_RETRIES = 3
DELAY = 1.5  # 请求间隔秒数
RETRY_DELAY = 2  # 重试基础间隔秒数
REQUEST_TIMEOUT = 30  # 请求超时秒数

# === Monkey-patch requests 添加默认超时 ===
_original_requests_get = requests.get
_original_requests_post = requests.post


def _patched_requests_get(*args, **kwargs):
    """为所有 requests.get 调用添加默认超时"""
    if 'timeout' not in kwargs:
        kwargs['timeout'] = REQUEST_TIMEOUT
    return _original_requests_get(*args, **kwargs)


def _patched_requests_post(*args, **kwargs):
    """为所有 requests.post 调用添加默认超时"""
    if 'timeout' not in kwargs:
        kwargs['timeout'] = REQUEST_TIMEOUT
    return _original_requests_post(*args, **kwargs)


requests.get = _patched_requests_get
requests.post = _patched_requests_post

# === 日志配置 ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# === 全局翻译器缓存 ===
_translator_cache = {}


def _get_translator(src_lang, dest_lang):
    """
    获取或创建翻译器实例（函数级别缓存）

    Args:
        src_lang: 源语言代码
        dest_lang: 目标语言代码

    Returns:
        GoogleTranslator: 翻译器实例
    """
    cache_key = f"{src_lang}->{dest_lang}"
    if cache_key not in _translator_cache:
        _translator_cache[cache_key] = GoogleTranslator(source=src_lang, target=dest_lang)
    return _translator_cache[cache_key]


def translate_segment(text, src_lang, dest_lang):
    """
    翻译单个文本段，带重试机制和指数退避

    Args:
        text: 待翻译文本段
        src_lang: 源语言代码
        dest_lang: 目标语言代码

    Returns:
        str: 翻译后的文本，失败返回 None
    """
    if not text.strip():
        return text

    translator = _get_translator(src_lang, dest_lang)

    for attempt in range(MAX_RETRIES):
        try:
            result = translator.translate(text)
            if result:
                return result
        except (OSError, IOError, UnicodeDecodeError, Exception) as e:
            logger.warning(f"翻译失败 (尝试 {attempt + 1}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES - 1:
                # 指数退避：2s, 4s, 8s
                time.sleep(RETRY_DELAY * (2 ** attempt))

    logger.error(f"翻译失败，已达最大重试次数: {text[:50]}...")
    return None


def extract_code_blocks(text):
    """
    提取代码块，返回替换后的文本和代码块字典

    Args:
        text: 原始文本

    Returns:
        tuple: (替换占位符后的文本, 代码块字典 {索引: 原始代码块})
    """
    blocks = {}
    counter = 0

    def replacer(match):
        nonlocal counter
        placeholder = f"__CODE_BLOCK_{counter}__"
        blocks[counter] = match.group(0)
        counter += 1
        return placeholder

    # 匹配带语言标识的代码块：```python ... ```
    text = re.sub(r'```[\w]*\n[\s\S]*?```', replacer, text)
    # 匹配行内代码：`code`
    text = re.sub(r'`[^`]+`', replacer, text)

    return text, blocks


def restore_code_blocks(text, blocks):
    """
    还原代码块占位符

    Args:
        text: 包含占位符的文本
        blocks: 代码块字典 {索引: 原始代码块}

    Returns:
        str: 还原后的文本
    """
    for idx, block in blocks.items():
        placeholder = f"__CODE_BLOCK_{idx}__"
        text = text.replace(placeholder, block)
    return text


def translate_text(text, src_lang, dest_lang):
    """
    翻译完整文本，按行处理保留原始换行符结构

    Args:
        text: 待翻译文本
        src_lang: 源语言代码（zh-CN 或 en）
        dest_lang: 目标语言代码（en 或 zh-CN）

    Returns:
        tuple: (翻译后的文本, 失败段落列表)
    """
    # 提取代码块
    text, blocks = extract_code_blocks(text)

    # 按行处理，保留原始换行符结构
    lines = text.split('\n')
    translated_lines = []
    failed_segments = []  # 记录失败的段落索引

    for i, line in enumerate(lines):
        if not line.strip():
            translated_lines.append(line)
            continue

        logger.info(f"翻译行 {i + 1}/{len(lines)}")
        result = translate_segment(line, src_lang, dest_lang)

        if result is None:
            logger.warning(f"跳过翻译失败的行 {i + 1}")
            translated_lines.append(line)  # 保留原文
            failed_segments.append(i + 1)  # 记录失败行号（1-based）
        else:
            translated_lines.append(result)

        # 请求间隔，避免限流
        if i < len(lines) - 1:
            time.sleep(DELAY)

    # 合并行并还原代码块
    translated_text = '\n'.join(translated_lines)
    translated_text = restore_code_blocks(translated_text, blocks)

    return translated_text, failed_segments


def process_file_pair(zh_path, en_path):
    """
    处理一对中英文文档

    Args:
        zh_path: 中文文件路径 (Path 对象)
        en_path: 英文文件路径 (Path 对象)

    Returns:
        str: 操作结果 (translated_zh_to_en / translated_en_to_zh / skipped / error)
    """
    # 获取文件修改时间
    zh_mtime = zh_path.stat().st_mtime
    en_mtime = en_path.stat().st_mtime

    # 判断翻译方向
    if zh_mtime > en_mtime:
        direction = "zh -> en"
        src_path, dest_path = zh_path, en_path
        src_lang, dest_lang = "zh-CN", "en"
    elif en_mtime > zh_mtime:
        direction = "en -> zh"
        src_path, dest_path = en_path, zh_path
        src_lang, dest_lang = "en", "zh-CN"
    else:
        logger.info(f"跳过 (文件时间相同): {zh_path.name}")
        return "skipped"

    logger.info(f"开始翻译 ({direction}): {src_path.name} -> {dest_path.name}")

    try:
        # 读取源文件
        src_content = src_path.read_text(encoding='utf-8')

        # 执行翻译
        translated_content, failed_segments = translate_text(src_content, src_lang, dest_lang)

        if translated_content is None:
            logger.error(f"翻译失败: {src_path.name}")
            return "error"

        # 如果有失败的段落，在文件头部添加注释标记
        if failed_segments:
            warning_comment = f"<!-- 警告：以下行翻译失败，保留了原文：{', '.join(map(str, failed_segments))} -->\n\n"
            translated_content = warning_comment + translated_content
            logger.warning(f"文件 {dest_path.name} 包含 {len(failed_segments)} 个未翻译的段落")

        # 写入目标文件
        dest_path.write_text(translated_content, encoding='utf-8')
        logger.info(f"翻译完成: {dest_path.name}")

        return f"translated_{direction.replace(' -> ', '_to_')}"

    except (OSError, IOError, UnicodeDecodeError, Exception) as e:
        logger.error(f"处理文件对时出错: {e}")
        return "error"


def find_doc_pairs(docs_dir):
    """
    查找所有中英文文档对

    Args:
        docs_dir: 文档目录路径

    Returns:
        list: [(zh_path, en_path), ...]
    """
    docs_path = Path(docs_dir)
    if not docs_path.exists():
        logger.error(f"文档目录不存在: {docs_dir}")
        return []

    pairs = []
    zh_files = list(docs_path.glob("*.zh.md"))

    for zh_file in zh_files:
        # 构造对应的英文文件名
        en_name = zh_file.name.replace('.zh.md', '.en.md')
        en_file = docs_path / en_name

        if en_file.exists():
            pairs.append((zh_file, en_file))
        else:
            logger.warning(f"缺少英文文件: {en_name}")

    return pairs


def main():
    """主函数：遍历文档目录，处理所有文件对"""
    logger.info("=" * 50)
    logger.info("自动翻译脚本启动")
    logger.info("=" * 50)

    # 查找文档对
    pairs = find_doc_pairs(DOCS_DIR)

    if not pairs:
        logger.info("未找到需要同步的文档对")
        return

    logger.info(f"找到 {len(pairs)} 个文档对")

    # 统计信息
    stats = {
        "translated_zh_to_en": 0,
        "translated_en_to_zh": 0,
        "skipped": 0,
        "error": 0
    }

    # 处理每个文档对
    for zh_path, en_path in pairs:
        result = process_file_pair(zh_path, en_path)
        if result in stats:
            stats[result] += 1
        logger.info("-" * 30)

    # 输出统计信息
    logger.info("=" * 50)
    logger.info("翻译完成，统计信息:")
    logger.info(f"  中文 -> 英文: {stats['translated_zh_to_en']} 个文件")
    logger.info(f"  英文 -> 中文: {stats['translated_en_to_zh']} 个文件")
    logger.info(f"  跳过 (无变更): {stats['skipped']} 个文件")
    logger.info(f"  翻译失败: {stats['error']} 个文件")
    logger.info("=" * 50)


if __name__ == "__main__":
    main()
