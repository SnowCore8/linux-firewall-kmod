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
RETRY_DELAY = 2  # 重试间隔秒数

# === 日志配置 ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def extract_code_blocks(text):
    """
    提取代码块和行内代码，返回占位符映射

    Args:
        text: 原始 Markdown 文本

    Returns:
        tuple: (替换后的文本, 占位符映射字典)
    """
    blocks = {}
    counter = [0]  # 使用列表保证闭包可修改

    def replace_block(match, is_inline=False):
        """替换代码块为占位符"""
        placeholder = f"__CODE_BLOCK_{counter[0]}__"
        blocks[placeholder] = match.group(0)
        counter[0] += 1
        # 多行代码块添加换行，行内代码保持原样
        if is_inline:
            return placeholder
        return f"\n{placeholder}\n"

    # 先提取多行代码块 ```...```
    text = re.sub(r'```[\s\S]*?```', lambda m: replace_block(m, is_inline=False), text)

    # 再提取行内代码 `...`
    text = re.sub(r'`[^`]+`', lambda m: replace_block(m, is_inline=True), text)

    return text, blocks


def restore_code_blocks(text, blocks):
    """
    还原代码块到翻译后的文本

    Args:
        text: 翻译后的文本
        blocks: 占位符映射字典

    Returns:
        str: 还原后的文本
    """
    for placeholder, original_code in blocks.items():
        text = text.replace(placeholder, original_code)
    return text


def translate_segment(text, src_lang, dest_lang):
    """
    翻译单个文本段，带重试机制

    Args:
        text: 待翻译文本段
        src_lang: 源语言代码
        dest_lang: 目标语言代码

    Returns:
        str: 翻译后的文本，失败返回 None
    """
    if not text.strip():
        return text

    for attempt in range(MAX_RETRIES):
        try:
            translator = GoogleTranslator(source=src_lang, target=dest_lang)
            result = translator.translate(text)
            if result:
                return result
        except Exception as e:
            logger.warning(f"翻译失败 (尝试 {attempt + 1}/{MAX_RETRIES}): {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)

    logger.error(f"翻译失败，已达最大重试次数: {text[:50]}...")
    return None


def translate_text(text, src_lang, dest_lang):
    """
    翻译完整文本，按段落分割处理

    Args:
        text: 待翻译文本
        src_lang: 源语言代码（zh-CN 或 en）
        dest_lang: 目标语言代码（en 或 zh-CN）

    Returns:
        str: 翻译后的文本，失败返回 None
    """
    # 提取代码块
    text, blocks = extract_code_blocks(text)

    # 按段落分割（保留空行）
    paragraphs = text.split('\n\n')
    translated_paragraphs = []

    for i, paragraph in enumerate(paragraphs):
        if not paragraph.strip():
            translated_paragraphs.append(paragraph)
            continue

        logger.info(f"翻译段落 {i + 1}/{len(paragraphs)}")
        result = translate_segment(paragraph, src_lang, dest_lang)

        if result is None:
            logger.warning(f"跳过翻译失败的段落 {i + 1}")
            translated_paragraphs.append(paragraph)  # 保留原文
        else:
            translated_paragraphs.append(result)

        # 请求间隔，避免限流
        if i < len(paragraphs) - 1:
            time.sleep(DELAY)

    # 合并段落并还原代码块
    translated_text = '\n\n'.join(translated_paragraphs)
    return restore_code_blocks(translated_text, blocks)


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
        translated_content = translate_text(src_content, src_lang, dest_lang)

        if translated_content is None:
            logger.error(f"翻译失败: {src_path.name}")
            return "error"

        # 写入目标文件
        dest_path.write_text(translated_content, encoding='utf-8')
        logger.info(f"翻译完成: {dest_path.name}")

        return f"translated_{direction.replace(' -> ', '_to_')}"

    except Exception as e:
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
