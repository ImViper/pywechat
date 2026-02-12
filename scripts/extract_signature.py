"""
IDA Pro 签名提取辅助工具

帮助从 IDA Pro 导出的汇编代码中提取函数签名。

用法:
    1. 在 IDA Pro 中定位到函数入口
    2. 选中前 16-32 字节的汇编代码
    3. 右键 → "Copy to assembly"
    4. 将复制的文本粘贴到 ida_export.txt
    5. 运行此脚本: python scripts/extract_signature.py ida_export.txt

示例输入（ida_export.txt）:
    .text:0000000001A73150 48 89 5C 24 10    mov     [rsp+arg_8], rbx
    .text:0000000001A73155 57                push    rdi
    .text:0000000001A73156 48 83 EC 30       sub     rsp, 30h
    .text:0000000001A7315A 48 8B F9          mov     rdi, rcx

输出:
    Signature: 48 89 5C 24 ?? 57 48 83 EC 30 48 8B F9
"""

import re
import sys
from pathlib import Path


def extract_signature_from_ida_text(text: str, max_bytes: int = 24) -> str:
    """
    从 IDA Pro 导出的文本中提取签名。

    Args:
        text: IDA Pro 导出的汇编文本
        max_bytes: 最大字节数（默认 24）

    Returns:
        签名字符串，例如 "48 89 5C 24 ?? 57 48 83 EC 30"
    """
    # IDA Pro 格式示例：
    # .text:0000000001A73150 48 89 5C 24 10    mov     [rsp+arg_8], rbx
    #
    # 我们需要提取：48 89 5C 24 10

    pattern = re.compile(
        r'\.text:[0-9A-Fa-f]+\s+((?:[0-9A-Fa-f]{2}\s+)+)',
        re.MULTILINE
    )

    bytes_list = []

    for match in pattern.finditer(text):
        # 提取十六进制字节（如 "48 89 5C 24 10 "）
        hex_bytes = match.group(1).strip().split()
        bytes_list.extend(hex_bytes)

        if len(bytes_list) >= max_bytes:
            break

    if not bytes_list:
        # 尝试另一种格式（纯十六进制）
        # 例如: 48 89 5C 24 10 57 48 83 EC 30
        hex_pattern = re.compile(r'\b([0-9A-Fa-f]{2})\b')
        matches = hex_pattern.findall(text)
        bytes_list = matches[:max_bytes]

    if not bytes_list:
        return ""

    # 截取到 max_bytes
    signature_bytes = bytes_list[:max_bytes]

    # 将可能的地址字节替换为通配符 ??
    # 启发式：如果某个字节看起来像地址的一部分（如 mov [rsp+XX]），替换为 ??
    # 简化版：每 4-5 个字节中，如果有立即数部分，替换为 ??

    signature = ' '.join(signature_bytes)

    print(f"\n[EXTRACTED] {len(signature_bytes)} bytes:")
    print(f"  {signature}")

    return signature


def suggest_wildcard_positions(signature: str) -> str:
    """
    建议哪些字节应该替换为通配符。

    常见模式：
    - mov [rsp+XX] → XX 应该是 ??
    - mov reg, imm → imm 可能需要 ??
    """
    bytes_list = signature.split()

    # 简单启发式：检查是否有 "24 XX" 模式（rsp 偏移）
    suggested = []
    for i, byte_val in enumerate(bytes_list):
        if i > 0 and bytes_list[i-1] == '24':
            # 这可能是 [rsp+XX] 的偏移部分
            suggested.append(f"  Byte {i}: {byte_val} → ?? (likely stack offset)")

    if suggested:
        print("\n[SUGGESTIONS] Consider replacing these bytes with ??:")
        for s in suggested:
            print(s)

        # 应用建议
        modified_bytes = bytes_list.copy()
        for i, byte_val in enumerate(bytes_list):
            if i > 0 and bytes_list[i-1] == '24':
                modified_bytes[i] = '??'

        modified_sig = ' '.join(modified_bytes)
        print(f"\n[MODIFIED] Suggested signature:")
        print(f"  {modified_sig}")
        return modified_sig

    return signature


def main():
    if len(sys.argv) < 2:
        print("用法: python scripts/extract_signature.py <ida_export.txt>")
        print("\n示例:")
        print("  1. 在 IDA Pro 中选中函数前 16-32 字节")
        print("  2. 右键 → 'Copy to assembly'")
        print("  3. 粘贴到 ida_export.txt")
        print("  4. python scripts/extract_signature.py ida_export.txt")
        sys.exit(1)

    input_file = Path(sys.argv[1])

    if not input_file.exists():
        print(f"[ERROR] File not found: {input_file}")
        sys.exit(1)

    print("="*70)
    print("IDA Pro 签名提取工具")
    print("="*70)

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    print(f"\n[INPUT] Reading from: {input_file}")
    print(f"  File size: {len(text)} bytes")

    # 提取签名
    signature = extract_signature_from_ida_text(text, max_bytes=24)

    if not signature:
        print("\n[ERROR] No signature found in input file")
        print("\n[HINT] Expected format:")
        print("  .text:0000000001A73150 48 89 5C 24 10    mov     [rsp+arg_8], rbx")
        print("  .text:0000000001A73155 57                push    rdi")
        print("  ...")
        sys.exit(1)

    # 建议通配符位置
    modified_sig = suggest_wildcard_positions(signature)

    print("\n" + "="*70)
    print("下一步：更新代码")
    print("="*70)
    print(f"\n编辑文件: hook/src/sns_moments_poc.cpp")
    print(f"  找到 line 155:")
    print(f'    const char* signature = "...";')
    print(f"\n  替换为:")
    print(f'    const char* signature = "{modified_sig}";')
    print(f"\n然后编译并测试:")
    print(f"  python scripts/phase0_auto_test.py --all")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
