# -*- coding: utf-8 -*-
"""
无线网络安全测试工具的命令行入口。

本文件刻意保持独立，避免影响现有 GUI 入口。
当前 CLI 支持 Windows 和 macOS。
"""
from __future__ import annotations

import argparse
import json
import platform
import shlex
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


APP_VERSION = "1.3.1"
DEFAULT_PASSWORD_FILE = "passwords.txt"
DEFAULT_DICT_FILE = "dict/pwdict.json"
MAX_JSON_DICT_BYTES = 20 * 1024 * 1024
SECURITY_NOTICE = """安全测试说明：
本工具仅允许用于学习研究、授权安全测试或你本人拥有并控制的无线网络安全检查。
严禁用于未授权网络访问、密码猜测、非法渗透测试、牟利、破坏或任何违反法律法规的行为。
测试前必须显式加入授权确认参数：--i-am-authorized
继续运行即表示你确认已经获得目标网络所有者的明确授权，并自行承担合规责任。"""
AUTHORIZED_TEST_COMMAND_EXAMPLE = 'wstt test --ssid "你的WiFi名称" --password-file passwords.txt --security WPA2PSK --i-am-authorized'
HELP_EPILOG = SECURITY_NOTICE + """

命令示例：
  wlan-sec-test-tool-cli
  wlan-sec-test-tool-cli shell
  wlan-sec-test-tool-cli interfaces
  wlan-sec-test-tool-cli scan --iface-index 0 --scan-time 8
  wlan-sec-test-tool-cli test --ssid "你的WiFi名称" --password-file passwords.txt --security WPA2PSK --i-am-authorized

短命令：
  wstt
  wstt scan --iface-index 0
"""
SHELL_HELP = """长驻 CLI 会话命令：
  help 或 ?                      显示本帮助
  interfaces                     列出无线网卡
  scan --iface-index 0           扫描附近 Wi-Fi
  test --ssid "你的WiFi名称" --password-file passwords.txt --security WPA2PSK --i-am-authorized
  clear                          清屏
  exit 或 quit                   退出会话

提示：
  也可以输入完整命令，例如：wstt scan --iface-index 0
  Windows 路径建议使用引号或正斜杠，例如："C:\\Users\\you\\passwords.txt" 或 C:/Users/you/passwords.txt
"""

SECURITY_CHOICES = (
    "auto",
    "WPA",
    "WPAPSK",
    "WPA2",
    "WPA2PSK",
    "WPA3",
    "WPA3SAE",
    "OPEN",
)


class ChineseArgumentParser(argparse.ArgumentParser):
    """将 argparse 默认帮助和常见参数错误改为中文。"""

    def format_usage(self) -> str:
        return self._translate_help(super().format_usage())

    def format_help(self) -> str:
        return self._translate_help(super().format_help())

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: 错误：{self._translate_error(message)}\n")

    @staticmethod
    def _translate_help(text: str) -> str:
        replacements = {
            "usage:": "用法:",
            "positional arguments:": "位置参数:",
            "options:": "选项:",
            "show this help message and exit": "显示帮助信息并退出",
            "show program's version number and exit": "显示程序版本并退出",
        }
        for source, target in replacements.items():
            text = text.replace(source, target)
        return text

    @staticmethod
    def _translate_error(message: str) -> str:
        replacements = {
            "the following arguments are required:": "缺少必填参数：",
            "invalid choice:": "无效选项：",
            "choose from": "可选值：",
            "argument": "参数",
            "expected one argument": "需要一个参数值",
        }
        for source, target in replacements.items():
            message = message.replace(source, target)
        return message


@dataclass(frozen=True)
class WiFiApi:
    system: str
    const: Any
    pywifi_cls: Any
    profile_cls: Any


def load_wifi_api() -> WiFiApi:
    system = platform.system()
    if system == "Darwin":
        try:
            from wifi_macos import MacOSConst, MacOSProfile, MacOSWiFi
        except ImportError as exc:
            raise RuntimeError("缺少 macOS Wi-Fi 后端模块：wifi_macos.py。") from exc

        return WiFiApi(
            system=system,
            const=MacOSConst,
            pywifi_cls=MacOSWiFi,
            profile_cls=MacOSProfile,
        )
    if system == "Windows":
        try:
            from pywifi import Profile, PyWiFi, const
        except ImportError as exc:
            raise RuntimeError("缺少依赖：pywifi。请先安装 requirements_win.txt。") from exc

        return WiFiApi(
            system=system,
            const=const,
            pywifi_cls=PyWiFi,
            profile_cls=Profile,
        )
    raise RuntimeError(f"当前系统暂不支持 CLI：{system}。目前仅支持 Windows 和 macOS。")


def get_interfaces(api: WiFiApi) -> list[Any]:
    interfaces = api.pywifi_cls().interfaces()
    if not interfaces:
        raise RuntimeError("未找到无线网卡。")
    return interfaces


def select_interface(interfaces: list[Any], index: int) -> Any:
    if index < 0 or index >= len(interfaces):
        raise RuntimeError(f"无线网卡序号无效：{index}。可用范围：0..{len(interfaces) - 1}。")
    return interfaces[index]


def clean_one_line(value: Any) -> str:
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def network_ssid(network: Any) -> str:
    return clean_one_line(getattr(network, "ssid", ""))


def network_bssid(network: Any) -> str:
    return clean_one_line(getattr(network, "bssid", ""))


def network_security(network: Any) -> str:
    if hasattr(network, "security"):
        return clean_one_line(getattr(network, "security"))
    akm = getattr(network, "akm", None)
    cipher = getattr(network, "cipher", None)
    return clean_one_line(f"akm={akm}, cipher={cipher}")


def scan_networks(iface: Any, scan_time: float) -> list[Any]:
    iface.scan()
    time.sleep(scan_time)
    return list(iface.scan_results())


def cmd_interfaces(args: argparse.Namespace) -> int:
    api = load_wifi_api()
    interfaces = get_interfaces(api)
    for index, iface in enumerate(interfaces):
        print(f"[{index}] {clean_one_line(iface.name())}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    api = load_wifi_api()
    iface = select_interface(get_interfaces(api), args.iface_index)
    print(f"正在使用无线网卡 [{args.iface_index}] {clean_one_line(iface.name())} 扫描 Wi-Fi ...")
    networks = scan_networks(iface, args.scan_time)
    if not networks:
        print("未扫描到 Wi-Fi 网络。")
        return 0

    seen_ssids: dict[str, int] = {}
    for index, network in enumerate(networks, 1):
        ssid = network_ssid(network)
        seen_ssids[ssid] = seen_ssids.get(ssid, 0) + 1
        bssid = network_bssid(network) or "-"
        print(f"{index:>3}. SSID={ssid}  BSSID={bssid}  安全类型={network_security(network)}")

    duplicates = sorted(ssid for ssid, count in seen_ssids.items() if ssid and count > 1)
    if duplicates:
        print("")
        print("警告：发现重复 SSID。测试前建议先通过 GUI 或人工方式确认目标网络：")
        for ssid in duplicates:
            print(f"  - {ssid}")
    return 0


def load_json_passwords(path: Path, ssid: str) -> Iterator[str]:
    if not path.exists():
        return
    if not path.is_file():
        raise RuntimeError(f"密码字典路径不是文件：{path}")
    if path.stat().st_size > MAX_JSON_DICT_BYTES:
        raise RuntimeError(f"密码字典文件过大：{path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"密码字典 JSON 格式无效：{path}") from exc
    if not isinstance(data, list):
        raise RuntimeError(f"密码字典 JSON 顶层必须是列表：{path}")

    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("ssid") != ssid:
            continue
        password = item.get("pwd")
        if isinstance(password, str) and password:
            yield password


def load_text_passwords(path: Path) -> Iterator[str]:
    if not path.exists():
        raise RuntimeError(f"密码本不存在：{path}")
    if not path.is_file():
        raise RuntimeError(f"密码本路径不是文件：{path}")

    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            password = line.strip()
            if password:
                yield password


def find_scanned_profile(networks: list[Any], ssid: str) -> Any | None:
    matches = [network for network in networks if getattr(network, "ssid", None) == ssid]
    if len(matches) > 1:
        print("警告：扫描结果中存在重复 SSID，将使用第一个匹配到的网络配置。")
    return matches[0] if matches else None


def build_windows_profile(api: WiFiApi, ssid: str, password: str, security: str, scanned_profile: Any | None) -> Any:
    profile = api.profile_cls()
    if security == "auto" and scanned_profile is not None:
        profile.ssid = getattr(scanned_profile, "ssid", ssid)
        profile.auth = getattr(scanned_profile, "auth", api.const.AUTH_ALG_OPEN)
        profile.akm = getattr(scanned_profile, "akm", api.const.AKM_TYPE_WPA2PSK)
        profile.cipher = getattr(scanned_profile, "cipher", api.const.CIPHER_TYPE_CCMP)
    else:
        profile.ssid = ssid
        profile.auth = api.const.AUTH_ALG_OPEN
        profile.akm = windows_akm_value(api, security)
        profile.cipher = api.const.CIPHER_TYPE_CCMP

    profile.key = password
    return profile


def windows_akm_value(api: WiFiApi, security: str) -> Any:
    if security == "auto":
        return api.const.AKM_TYPE_WPA2PSK
    if security == "OPEN":
        return api.const.AKM_TYPE_NONE

    try:
        from pywifi import _wifiutil_win

        akm_dict = _wifiutil_win.akm_str_to_value_dict
        return akm_dict.get(security, api.const.AKM_TYPE_NONE)
    except Exception:
        fallback = {
            "WPA": getattr(api.const, "AKM_TYPE_WPA", api.const.AKM_TYPE_NONE),
            "WPAPSK": getattr(api.const, "AKM_TYPE_WPAPSK", api.const.AKM_TYPE_NONE),
            "WPA2": getattr(api.const, "AKM_TYPE_WPA2", api.const.AKM_TYPE_NONE),
            "WPA2PSK": getattr(api.const, "AKM_TYPE_WPA2PSK", api.const.AKM_TYPE_NONE),
            "WPA3": getattr(api.const, "AKM_TYPE_WPA3", api.const.AKM_TYPE_NONE),
            "WPA3SAE": getattr(api.const, "AKM_TYPE_WPA3SAE", api.const.AKM_TYPE_NONE),
        }
        return fallback.get(security, api.const.AKM_TYPE_NONE)


def connect_once(
    api: WiFiApi,
    iface: Any,
    ssid: str,
    password: str,
    security: str,
    connect_time: float,
    scanned_profile: Any | None,
) -> bool:
    if api.system == "Darwin":
        connected = iface.connect(ssid, password)
        time.sleep(connect_time)
        if connected and iface.status() == api.const.IFACE_CONNECTED:
            iface.disconnect()
            return True
        return False

    profile = build_windows_profile(api, ssid, password, security, scanned_profile)
    added_profile = None
    try:
        try:
            iface.remove_network_profile(profile)
        except Exception:
            pass
        added_profile = iface.add_network_profile(profile)
        iface.connect(added_profile)
        time.sleep(connect_time)
        return iface.status() == api.const.IFACE_CONNECTED
    finally:
        if added_profile is not None:
            try:
                iface.remove_network_profile(profile)
            except Exception:
                pass


def iter_password_candidates(args: argparse.Namespace) -> Iterator[tuple[str, str]]:
    dict_path = Path(args.dict_file)
    for password in load_json_passwords(dict_path, args.ssid):
        yield "JSON 字典", password

    password_path = Path(args.password_file)
    for password in load_text_passwords(password_path):
        yield "文本密码本", password


def cmd_test(args: argparse.Namespace) -> int:
    if not args.i_am_authorized:
        raise RuntimeError(
            "拒绝运行：执行安全测试前必须传入 --i-am-authorized，表示你已获得目标网络所有者明确授权。禁止对未授权网络进行测试。\n"
            f"授权测试命令示例：{AUTHORIZED_TEST_COMMAND_EXAMPLE}"
        )

    print(SECURITY_NOTICE)
    print("")

    api = load_wifi_api()
    iface = select_interface(get_interfaces(api), args.iface_index)

    scanned_profile = None
    if api.system == "Windows" and args.security == "auto":
        print("正在扫描一次，用于识别目标网络安全类型 ...")
        scanned_profile = find_scanned_profile(scan_networks(iface, args.scan_time), args.ssid)
        if scanned_profile is None:
            print("警告：扫描时未找到目标 SSID，将回退为 WPA2PSK 配置。")

    print(f"正在使用无线网卡 [{args.iface_index}] {clean_one_line(iface.name())} 测试 SSID={clean_one_line(args.ssid)}。")
    print("密码候选值不会输出到终端。")

    attempts = 0
    try:
        iface.disconnect()
        time.sleep(1)
        for source, password in iter_password_candidates(args):
            if args.max_attempts is not None and attempts >= args.max_attempts:
                print(f"已达到 --max-attempts={args.max_attempts}，停止测试。")
                return 2

            attempts += 1
            print(f"第 {attempts} 次尝试（来源：{source}）...")
            if connect_once(api, iface, args.ssid, password, args.security, args.connect_time, scanned_profile):
                print(f"测试成功：SSID={clean_one_line(args.ssid)} 接受了第 {attempts} 个候选密码。")
                return 0

        print(f"已完成 {attempts} 次尝试，未发现可成功连接的候选密码。")
        return 1
    except KeyboardInterrupt:
        print("")
        print("用户中断。")
        return 130
    finally:
        try:
            iface.disconnect()
        except Exception:
            pass


def strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def split_shell_command(line: str) -> list[str]:
    if platform.system() == "Windows":
        return [strip_matching_quotes(part) for part in shlex.split(line, posix=False)]
    return shlex.split(line, posix=True)


def cmd_shell(args: argparse.Namespace) -> int:
    print(SECURITY_NOTICE)
    print("")
    print("已进入长驻 CLI 会话。输入 help 查看命令，输入 exit 退出。")
    print("")

    while True:
        try:
            line = input("wstt> ").strip()
        except EOFError:
            print("")
            print("已退出长驻 CLI 会话。")
            return 0
        except KeyboardInterrupt:
            print("")
            print("已取消当前输入。输入 exit 退出，或继续输入命令。")
            continue

        if not line:
            continue

        lowered = line.lower()
        if lowered in ("exit", "quit", "q"):
            print("已退出长驻 CLI 会话。")
            return 0
        if lowered in ("help", "?"):
            print(SHELL_HELP)
            continue
        if lowered in ("clear", "cls"):
            print("\n" * 80)
            continue

        try:
            command_args = split_shell_command(line)
        except ValueError as exc:
            print(f"命令解析错误：{exc}")
            continue

        if command_args and command_args[0] in ("wstt", "wlan-sec-test-tool-cli"):
            command_args = command_args[1:]

        if command_args and command_args[0] == "shell":
            print("已经在长驻 CLI 会话中。")
            continue

        try:
            exit_code = run_cli_command(command_args, default_to_shell=False)
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 2
        except KeyboardInterrupt:
            print("")
            print("命令已被用户中断。")
            exit_code = 130
        except RuntimeError as exc:
            print(f"错误：{exc}")
            exit_code = 2

        if exit_code != 0:
            print(f"命令结束，退出码：{exit_code}")


def positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("数值必须大于 0")
    return number


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("数值必须大于 0")
    return number


def build_parser(default_to_shell: bool = True) -> argparse.ArgumentParser:
    parser = ChineseArgumentParser(
        prog="wlan-sec-test-tool-cli",
        description="Windows/macOS 无线网络安全测试命令行工具。仅限授权测试，禁止非法使用。",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}", help="显示程序版本并退出。")
    if default_to_shell:
        parser.set_defaults(func=cmd_shell)
    subparsers = parser.add_subparsers(dest="command", required=not default_to_shell, parser_class=ChineseArgumentParser)

    shell_parser = subparsers.add_parser("shell", help="进入长驻 CLI 会话。", formatter_class=argparse.RawDescriptionHelpFormatter)
    shell_parser.set_defaults(func=cmd_shell)

    interfaces_parser = subparsers.add_parser("interfaces", help="列出无线网卡。", formatter_class=argparse.RawDescriptionHelpFormatter)
    interfaces_parser.set_defaults(func=cmd_interfaces)

    scan_parser = subparsers.add_parser("scan", help="扫描附近 Wi-Fi 网络。", formatter_class=argparse.RawDescriptionHelpFormatter)
    scan_parser.add_argument("--iface-index", type=int, default=0, metavar="序号", help="无线网卡序号。默认：0。")
    scan_parser.add_argument("--scan-time", type=positive_float, default=8.0, metavar="秒数", help="扫描等待时间，单位秒。默认：8。")
    scan_parser.set_defaults(func=cmd_scan)

    test_parser = subparsers.add_parser("test", help="使用密码本测试已授权的 Wi-Fi 网络。", formatter_class=argparse.RawDescriptionHelpFormatter)
    test_parser.add_argument("--ssid", required=True, metavar="SSID", help="目标 Wi-Fi 的 SSID。")
    test_parser.add_argument("--password-file", default=DEFAULT_PASSWORD_FILE, metavar="路径", help=f"文本密码本路径。默认：{DEFAULT_PASSWORD_FILE}。")
    test_parser.add_argument("--dict-file", default=DEFAULT_DICT_FILE, metavar="路径", help=f"SSID JSON 密码字典路径。默认：{DEFAULT_DICT_FILE}。")
    test_parser.add_argument("--iface-index", type=int, default=0, metavar="序号", help="无线网卡序号。默认：0。")
    test_parser.add_argument("--security", choices=SECURITY_CHOICES, default="auto", metavar="类型", help="安全类型。默认：auto。")
    test_parser.add_argument("--scan-time", type=positive_float, default=8.0, metavar="秒数", help="Windows 自动识别安全类型时的扫描等待时间，单位秒。默认：8。")
    test_parser.add_argument("--connect-time", type=positive_float, default=3.0, metavar="秒数", help="每次连接尝试的等待时间，单位秒。默认：3。")
    test_parser.add_argument("--max-attempts", type=positive_int, metavar="次数", help="最多尝试的候选密码数量。")
    test_parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="必填确认：表示你已获得目标网络所有者明确授权。未提供时拒绝运行。",
    )
    test_parser.set_defaults(func=cmd_test)
    return parser


def run_cli_command(argv: list[str] | None = None, default_to_shell: bool = True) -> int:
    parser = build_parser(default_to_shell=default_to_shell)
    args = parser.parse_args(argv)
    return int(args.func(args))


def main(argv: list[str] | None = None) -> int:
    try:
        return run_cli_command(argv, default_to_shell=True)
    except RuntimeError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
