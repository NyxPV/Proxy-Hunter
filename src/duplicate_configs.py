#!/usr/bin/env python3
"""
Duplicate Config Checker for proxy_configs.txt (FIXED LINE-BY-LINE LOADER)
ဒီ script က proxy_configs.txt ထဲမှာ duplicate ဖြစ်နေတဲ့ config တွေကို ရှာဖွေပေးပါတယ်။
Duplicate စစ်ဆေးတဲ့အခါ Server:Port + Credential ကို အခြေခံပါတယ်။
"""

import os
import json
import base64
import re
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict
import sys

# Import config_parser
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from config_parser import decode_vmess, parse_vless, parse_trojan, parse_shadowsocks, parse_tuic, parse_hysteria2, parse_wireguard
    CONFIG_PARSER_AVAILABLE = True
    print("✅ Using config_parser.py for parsing")
except ImportError as e:
    CONFIG_PARSER_AVAILABLE = False
    print(f"⚠️  Warning: config_parser.py not found. Using fallback parser. Error: {e}")

# ============================================================
# VALID PROXY URL PATTERNS
# ============================================================

VALID_PROTOCOLS = [
    'vless://',
    'vmess://',
    'trojan://',
    'ss://',
    'tuic://',
    'hy2://',
    'hysteria2://',
    'wireguard://'
]

def is_valid_proxy_url(line: str) -> bool:
    """
    Check if a line is a valid proxy URL
    Returns True only for actual proxy configs, not headers or comments
    """
    line = line.strip()
    if not line:
        return False
    
    # Skip lines that start with //
    if line.startswith('//'):
        return False
    
    # Must start with a valid protocol
    for protocol in VALID_PROTOCOLS:
        if line.startswith(protocol):
            return True
    
    return False

def clean_url(config: str) -> str:
    """Clean HTML entities and common issues in URLs"""
    config = config.replace('&amp;', '&')
    config = config.replace('&#38;', '&')
    config = config.strip()
    return config

# ============================================================
# CREDENTIAL EXTRACTORS
# ============================================================

def extract_credential_vless(parsed: Dict) -> str:
    """Extract unique credential key for VLESS config"""
    uuid = parsed.get('uuid', '')
    security = parsed.get('security', 'none')
    
    if security == 'reality':
        pbk = parsed.get('pbk', '')
        sid = parsed.get('sid', '')
        return f"vless_reality:{uuid}:{pbk}:{sid}"
    else:
        return f"vless:{uuid}"

def extract_credential_vmess(parsed: Dict) -> str:
    """Extract unique credential key for VMess config"""
    uuid = parsed.get('id', parsed.get('uuid', ''))
    aid = parsed.get('aid', parsed.get('alterId', '0'))
    return f"vmess:{uuid}:{aid}"

def extract_credential_trojan(parsed: Dict) -> str:
    """Extract unique credential key for Trojan config"""
    password = parsed.get('password', '')
    return f"trojan:{password}"

def extract_credential_ss(parsed: Dict) -> str:
    """Extract unique credential key for Shadowsocks config"""
    method = parsed.get('method', '')
    password = parsed.get('password', '')
    return f"ss:{method}:{password}"

def extract_credential_tuic(parsed: Dict) -> str:
    """Extract unique credential key for TUIC config"""
    uuid = parsed.get('uuid', '')
    password = parsed.get('password', '')
    return f"tuic:{uuid}:{password}"

def extract_credential_hysteria2(parsed: Dict) -> str:
    """Extract unique credential key for Hysteria2 config"""
    password = parsed.get('password', '')
    return f"hy2:{password}"

def extract_credential_wireguard(parsed: Dict) -> str:
    """Extract unique credential key for WireGuard config"""
    public_key = parsed.get('public_key', '')
    private_key = parsed.get('private_key', '')
    return f"wg:{public_key}:{private_key[:8]}"

# ============================================================
# IMPROVED PARSER
# ============================================================

class ImprovedConfigParser:
    """Parse proxy configs and extract unique keys (server:port:credential)"""
    
    @staticmethod
    def get_unique_key(config: str) -> Optional[Tuple[str, int, str, str]]:
        """
        Extract unique key for duplicate detection
        Returns: (server, port, protocol, credential_key) or None
        """
        # Clean the config first
        config = clean_url(config)
        
        # Validate it's a proxy URL
        if not is_valid_proxy_url(config):
            return None
        
        # Extract protocol
        if '://' not in config:
            return None
        protocol = config.split('://')[0].lower()
        
        try:
            # ----------------------------------------------------
            # VLESS
            # ----------------------------------------------------
            if protocol == 'vless':
                if CONFIG_PARSER_AVAILABLE:
                    parsed = parse_vless(config)
                else:
                    parsed = fallback_parse_vless(config)
                
                if parsed and parsed.get('address') and parsed.get('port'):
                    server = parsed.get('address')
                    port = int(parsed.get('port'))
                    credential = extract_credential_vless(parsed)
                    return (server, port, protocol, credential)
            
            # ----------------------------------------------------
            # VMess
            # ----------------------------------------------------
            elif protocol == 'vmess':
                if CONFIG_PARSER_AVAILABLE:
                    parsed = decode_vmess(config)
                else:
                    parsed = fallback_parse_vmess(config)
                
                if parsed and parsed.get('add') and parsed.get('port'):
                    server = parsed.get('add')
                    port = int(parsed.get('port'))
                    credential = extract_credential_vmess(parsed)
                    return (server, port, protocol, credential)
            
            # ----------------------------------------------------
            # Trojan
            # ----------------------------------------------------
            elif protocol == 'trojan':
                if CONFIG_PARSER_AVAILABLE:
                    parsed = parse_trojan(config)
                else:
                    parsed = fallback_parse_trojan(config)
                
                if parsed and parsed.get('address') and parsed.get('port'):
                    server = parsed.get('address')
                    port = int(parsed.get('port'))
                    credential = extract_credential_trojan(parsed)
                    return (server, port, protocol, credential)
            
            # ----------------------------------------------------
            # Shadowsocks
            # ----------------------------------------------------
            elif protocol == 'ss':
                if CONFIG_PARSER_AVAILABLE:
                    parsed = parse_shadowsocks(config)
                else:
                    parsed = fallback_parse_ss(config)
                
                if parsed and parsed.get('address') and parsed.get('port'):
                    server = parsed.get('address')
                    port = int(parsed.get('port'))
                    credential = extract_credential_ss(parsed)
                    return (server, port, protocol, credential)
            
            # ----------------------------------------------------
            # TUIC
            # ----------------------------------------------------
            elif protocol == 'tuic':
                if CONFIG_PARSER_AVAILABLE:
                    parsed = parse_tuic(config)
                    if parsed and parsed.get('address') and parsed.get('port'):
                        server = parsed.get('address')
                        port = int(parsed.get('port'))
                        credential = extract_credential_tuic(parsed)
                        return (server, port, protocol, credential)
            
            # ----------------------------------------------------
            # Hysteria2
            # ----------------------------------------------------
            elif protocol in ('hy2', 'hysteria2'):
                if CONFIG_PARSER_AVAILABLE:
                    parsed = parse_hysteria2(config)
                    if parsed and parsed.get('address') and parsed.get('port'):
                        server = parsed.get('address')
                        port = int(parsed.get('port'))
                        credential = extract_credential_hysteria2(parsed)
                        return (server, port, protocol, credential)
            
            # ----------------------------------------------------
            # WireGuard
            # ----------------------------------------------------
            elif protocol == 'wireguard':
                if CONFIG_PARSER_AVAILABLE:
                    parsed = parse_wireguard(config)
                    if parsed and parsed.get('address') and parsed.get('port'):
                        server = parsed.get('address')
                        port = int(parsed.get('port'))
                        credential = extract_credential_wireguard(parsed)
                        return (server, port, protocol, credential)
            
            return None
            
        except Exception as e:
            return None

# ============================================================
# FALLBACK PARSERS
# ============================================================

def fallback_parse_vless(config: str) -> Optional[Dict]:
    try:
        config = clean_url(config)
        if not config.startswith('vless://'):
            return None
        
        without_protocol = config.replace('vless://', '')
        
        if '@' not in without_protocol:
            return None
        uuid = without_protocol.split('@')[0]
        
        rest = without_protocol.split('@')[1]
        server_port = rest.split('?')[0].split('#')[0]
        
        if ':' not in server_port:
            return None
        server, port_str = server_port.split(':', 1)
        port = int(port_str.split('/')[0])
        
        security = 'none'
        pbk = ''
        sid = ''
        
        if '?' in rest:
            query = rest.split('?')[1].split('#')[0]
            params = parse_qs(query)
            security = params.get('security', ['none'])[0]
            pbk = params.get('pbk', [''])[0]
            sid = params.get('sid', [''])[0]
        
        return {
            'uuid': uuid,
            'address': server,
            'port': port,
            'security': security,
            'pbk': pbk,
            'sid': sid
        }
    except:
        return None

def fallback_parse_vmess(config: str) -> Optional[Dict]:
    try:
        config = clean_url(config)
        if not config.startswith('vmess://'):
            return None
        
        encoded = config[8:].strip()
        padding = 4 - (len(encoded) % 4)
        if padding != 4:
            encoded += '=' * padding
        
        decoded = base64.b64decode(encoded).decode('utf-8')
        data = json.loads(decoded)
        
        return {
            'add': data.get('add'),
            'port': data.get('port'),
            'id': data.get('id'),
            'aid': data.get('aid', '0')
        }
    except:
        return None

def fallback_parse_trojan(config: str) -> Optional[Dict]:
    try:
        config = clean_url(config)
        if not config.startswith('trojan://'):
            return None
        
        without_protocol = config.replace('trojan://', '')
        
        if '@' not in without_protocol:
            return None
        password = without_protocol.split('@')[0]
        
        rest = without_protocol.split('@')[1]
        server_port = rest.split('?')[0].split('#')[0]
        
        if ':' not in server_port:
            return None
        server, port_str = server_port.split(':', 1)
        port = int(port_str.split('/')[0])
        
        return {
            'password': password,
            'address': server,
            'port': port
        }
    except:
        return None

def fallback_parse_ss(config: str) -> Optional[Dict]:
    try:
        config = clean_url(config)
        if not config.startswith('ss://'):
            return None
        
        without_protocol = config.replace('ss://', '')
        without_fragment = without_protocol.split('#')[0]
        
        if '@' in without_fragment:
            auth_part, server_part = without_fragment.split('@', 1)
            if ':' in auth_part:
                method, password = auth_part.split(':', 1)
            else:
                decoded = base64.b64decode(auth_part + '==').decode('utf-8')
                method, password = decoded.split(':', 1)
            
            if ':' in server_part:
                server, port_str = server_part.split(':', 1)
                port = int(port_str.split('/')[0])
                return {
                    'method': method,
                    'password': password,
                    'address': server,
                    'port': port
                }
        else:
            decoded = base64.b64decode(without_fragment + '==').decode('utf-8')
            return fallback_parse_ss(f"ss://{decoded}")
    except:
        return None

# ============================================================
# DUPLICATE CHECKER CLASS (FIXED LINE-BY-LINE LOADER)
# ============================================================

class DuplicateChecker:
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.configs: List[str] = []
        self.parsed_info: Dict[int, Tuple[str, int, str, str]] = {}
        self.unique_key_map: Dict[str, List[int]] = defaultdict(list)
        self.unparsable_configs: List[Tuple[int, str]] = []
        
    def load_configs(self) -> int:
        """Load ONLY valid proxy configs - LINE BY LINE"""
        if not os.path.exists(self.config_file):
            print(f"❌ Error: File not found - {self.config_file}")
            return 0
        
        with open(self.config_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        print(f"📄 Total lines in file: {len(lines)}")
        
        # Counters for debugging
        header_count = 0
        empty_count = 0
        valid_config_count = 0
        invalid_count = 0
        
        valid_configs = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines
            if not line:
                empty_count += 1
                continue
            
            # Skip header lines (start with //)
            if line.startswith('//'):
                header_count += 1
                continue
            
            # Check if it's a valid proxy URL
            if is_valid_proxy_url(line):
                valid_configs.append(line)
                valid_config_count += 1
            else:
                # This should not happen for valid proxy configs
                invalid_count += 1
                # Print first few invalid lines for debugging
                if invalid_count <= 5:
                    preview = line[:60] + "..." if len(line) > 60 else line
                    print(f"   ⚠️  Skipping invalid line {line_num}: {preview}")
        
        self.configs = valid_configs
        
        print(f"\n📊 File Statistics:")
        print(f"   Header lines (//): {header_count}")
        print(f"   Empty lines: {empty_count}")
        print(f"   Invalid lines: {invalid_count}")
        print(f"   ✅ Valid proxy configs: {len(self.configs)}")
        
        if len(self.configs) != 440:
            print(f"\n⚠️  Warning: Expected ~440 configs, but found {len(self.configs)}")
            print("   Please check if some configs are on multiple lines or malformed.")
        
        # self.save_loaded_configs()
        
        return len(self.configs)
    
    def save_loaded_configs(self):
        """Save loaded configs to a file for debugging"""
        output_file = "loaded_Configs.txt"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("LOADED CONFIGS FROM PROXY_CONFIGS.TXT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Source file: {self.config_file}\n")
                f.write(f"Total valid configs loaded: {len(self.configs)}\n")
                f.write("=" * 80 + "\n\n")
                
                for idx, config in enumerate(self.configs):
                    preview = config[:100] + "..." if len(config) > 100 else config
                    f.write(f"[{idx + 1}] {preview}\n")
                    f.write("-" * 80 + "\n")
            
            print(f"📄 Loaded configs saved to: {output_file}")
        except Exception as e:
            print(f"❌ Error saving loaded configs: {e}")
    
    def analyze_duplicates(self):
        """Analyze duplicates by parsing each config"""
        print("\n" + "=" * 70)
        print("🔍 ANALYZING CONFIGS FOR DUPLICATES...")
        print("📌 Detection method: Server + Port + Credential")
        print("=" * 70)
        
        parsed_count = 0
        for idx, config in enumerate(self.configs):
            if idx > 0 and idx % 100 == 0:
                print(f"  Processing: {idx}/{len(self.configs)} configs... (parsed: {parsed_count})")
            
            result = ImprovedConfigParser.get_unique_key(config)
            
            if result:
                server, port, protocol, credential = result
                unique_key = f"{server}:{port}:{credential}"
                self.unique_key_map[unique_key].append(idx)
                self.parsed_info[idx] = (server, port, protocol, credential)
                parsed_count += 1
            else:
                preview = config[:80] + "..." if len(config) > 80 else config
                self.unparsable_configs.append((idx, preview))
        
        print(f"\n✅ Parsing complete!")
        print(f"   Successfully parsed: {parsed_count} configs")
        print(f"   Unparsable configs: {len(self.unparsable_configs)} configs")
    
    def print_duplicate_report(self):
        """Print detailed duplicate report"""
        print("\n" + "=" * 70)
        print("📊 DUPLICATE ANALYSIS REPORT")
        print("(Based on Server + Port + Credential)")
        print("=" * 70)
        
        duplicates = {k: v for k, v in self.unique_key_map.items() if len(v) > 1}
        
        if not duplicates:
            print("\n✅ No duplicates found! All configs have unique server+port+credential combinations.")
            return
        
        print(f"\n⚠️  Found {len(duplicates)} duplicate groups:")
        print("-" * 70)
        
        total_duplicates = 0
        for key, indices in sorted(duplicates.items(), key=lambda x: -len(x[1])):
            parts = key.split(':', 3)
            server = parts[0]
            port = parts[1]
            credential_preview = parts[3][:40] + "..." if len(parts[3]) > 40 else parts[3]
            
            protocol_info = [self.parsed_info[i][2] for i in indices if i in self.parsed_info]
            protocols_str = ', '.join(set(protocol_info))
            
            print(f"\n📍 {server}:{port} ({protocols_str}) - {len(indices)} configs")
            print(f"   🔑 Credential: {credential_preview}")
            
            for i, idx in enumerate(indices[:5]):
                if idx in self.parsed_info:
                    protocol = self.parsed_info[idx][2]
                    config_preview = self.configs[idx][:80] + "..." if len(self.configs[idx]) > 80 else self.configs[idx]
                    print(f"   [{i+1}] {protocol} - {config_preview}")
                else:
                    print(f"   [{i+1}] [unparsable] - {self.configs[idx][:80]}...")
            if len(indices) > 5:
                print(f"   ... and {len(indices) - 5} more")
            total_duplicates += len(indices) - 1
        
        print("\n" + "-" * 70)
        print(f"📈 SUMMARY:")
        print(f"   Total unique keys: {len(self.unique_key_map)}")
        print(f"   Duplicate groups: {len(duplicates)}")
        print(f"   Total duplicate configs (extra copies): {total_duplicates}")
        print(f"   Unique configs (if deduplicated): {len(self.unique_key_map)}")
    
    def print_protocol_statistics(self):
        """Print protocol distribution"""
        protocol_counts = defaultdict(int)
        credential_counts = defaultdict(int)
        
        for idx, (server, port, protocol, credential) in self.parsed_info.items():
            protocol_counts[protocol] += 1
            if protocol == 'vless' and 'reality' in credential:
                credential_counts['vless_reality'] += 1
            elif protocol == 'vless':
                credential_counts['vless_standard'] += 1
            else:
                credential_counts[protocol] += 1
        
        print("\n" + "=" * 70)
        print("📊 PROTOCOL DISTRIBUTION")
        print("=" * 70)
        
        for protocol, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
            print(f"   {protocol:<12}: {count:>6} configs")
        
        print("\n📊 CREDENTIAL TYPE BREAKDOWN:")
        for cred_type, count in sorted(credential_counts.items(), key=lambda x: -x[1]):
            print(f"   {cred_type:<18}: {count:>6}")
        
        if self.unparsable_configs:
            print(f"\n   {'unparsable':<12}: {len(self.unparsable_configs):>6} configs")
    
    def print_unparsable_list(self):
        """Print list of unparsable configs"""
        if not self.unparsable_configs:
            return
        
        print("\n" + "=" * 70)
        print("⚠️  UNPARSABLE CONFIGS (Could not extract unique key)")
        print("=" * 70)
        
        for idx, preview in self.unparsable_configs[:15]:
            print(f"\n   [{idx}] {preview}")
        
        if len(self.unparsable_configs) > 15:
            print(f"\n   ... and {len(self.unparsable_configs) - 15} more unparsable configs")
    
    def save_report(self, output_file: str = "duplicate_report.txt"):
        """Save full report to file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("PROXY CONFIGS DUPLICATE ANALYSIS REPORT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Source file: {self.config_file}\n")
                f.write("Detection method: Server + Port + Credential\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("SUMMARY:\n")
                f.write(f"  Total valid configs loaded: {len(self.configs)}\n")
                f.write(f"  Successfully parsed: {len(self.parsed_info)}\n")
                f.write(f"  Unparsable configs: {len(self.unparsable_configs)}\n")
                f.write(f"  Unique keys (server:port:credential): {len(self.unique_key_map)}\n")
                
                duplicates = {k: v for k, v in self.unique_key_map.items() if len(v) > 1}
                total_duplicates = sum(len(v) - 1 for v in duplicates.values())
                f.write(f"  Duplicate groups: {len(duplicates)}\n")
                f.write(f"  Total duplicate configs (extra copies): {total_duplicates}\n\n")
                
                f.write("PROTOCOL DISTRIBUTION:\n")
                protocol_counts = defaultdict(int)
                for idx, (server, port, protocol, credential) in self.parsed_info.items():
                    protocol_counts[protocol] += 1
                for protocol, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
                    f.write(f"  {protocol:<12}: {count}\n")
                f.write("\n")
                
                if duplicates:
                    f.write("DUPLICATE DETAILS:\n")
                    f.write("-" * 80 + "\n")
                    for key, indices in sorted(duplicates.items(), key=lambda x: -len(x[1])):
                        f.write(f"\n📍 {key} - {len(indices)} configs:\n")
                        for i, idx in enumerate(indices):
                            if idx in self.parsed_info:
                                protocol = self.parsed_info[idx][2]
                                config_preview = self.configs[idx][:150] if idx < len(self.configs) else "N/A"
                                f.write(f"   [{i+1}] {protocol} - {config_preview}\n")
                            else:
                                f.write(f"   [{i+1}] [unparsable] - {self.configs[idx][:150]}\n")
                    f.write("\n")
                
                if self.unparsable_configs:
                    f.write("UNPARSABLE CONFIGS:\n")
                    f.write("-" * 80 + "\n")
                    for idx, preview in self.unparsable_configs:
                        f.write(f"\n[{idx}] {preview}\n")
            
            print(f"\n📄 Full report saved to: {output_file}")
        except Exception as e:
            print(f"\n❌ Error saving report: {e}")
    
    def show_summary(self):
        """Show quick summary in console"""
        print("\n" + "=" * 70)
        print("📊 QUICK SUMMARY")
        print("=" * 70)
        
        duplicates = {k: v for k, v in self.unique_key_map.items() if len(v) > 1}
        total_duplicates = sum(len(v) - 1 for v in duplicates.values())
        
        print(f"   📁 Total configs:     {len(self.configs)}")
        print(f"   ✓ Parsed:             {len(self.parsed_info)}")
        print(f"   ✗ Unparsable:         {len(self.unparsable_configs)}")
        print(f"   🔑 Unique keys:        {len(self.unique_key_map)}")
        print(f"   ⚠️  Duplicate groups:   {len(duplicates)}")
        print(f"   📋 Duplicate copies:   {total_duplicates}")
        
        if duplicates:
            print(f"\n   🔝 Top 5 duplicate groups:")
            top_dupes = sorted(duplicates.items(), key=lambda x: -len(x[1]))[:5]
            for key, indices in top_dupes:
                parts = key.split(':', 3)
                server_port = f"{parts[0]}:{parts[1]}"
                protocols = [self.parsed_info[i][2] for i in indices if i in self.parsed_info]
                print(f"      {server_port} -> {len(indices)} copies ({', '.join(set(protocols))})")
    
    def save_deduplicated_configs(self, output_file: str = "deduplicated_configs.txt"):
        """Save only unique configs (keep first occurrence of each duplicate group)"""
        try:
            # Ensure the configs directory exists
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f"📁 Created directory: {output_dir}")

            seen_keys = set()
            unique_configs = []
            
            for idx, config in enumerate(self.configs):
                result = ImprovedConfigParser.get_unique_key(config)
                if result:
                    server, port, protocol, credential = result
                    unique_key = f"{server}:{port}:{credential}"
                    if unique_key not in seen_keys:
                        seen_keys.add(unique_key)
                        unique_configs.append(config)
                else:
                    unique_configs.append(config)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("//profile-title: base64:8J+OryBZYXdTdGFyIFByb3h5IEh1bnRlciB8IOKZvg==\n")
                f.write(f"//profile-update-interval: 1\n")
                f.write(f"//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n")
                f.write(f"//support-url: https://yawstardancebox.github.io/donate/\n")
                f.write(f"//profile-web-page-url: https://github.com/YawStar\n")
                f.write("\n\n")
                
                for config in unique_configs:
                    f.write(f"{config}\n\n")
            
            print(f"\n📄 Deduplicated configs saved to: {output_file}")
            print(f"   Original: {len(self.configs)} → Unique: {len(unique_configs)} (removed {len(self.configs) - len(unique_configs)} duplicates)")
            
        except Exception as e:
            print(f"\n❌ Error saving deduplicated configs: {e}")

# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    print("=" * 70)
    print("🚀 IMPROVED DUPLICATE CONFIG CHECKER (LINE-BY-LINE LOADER)")
    print("   Detection: Server + Port + Credential")
    print("   Only loads valid proxy URLs (vless://, vmess://, trojan://, ss://, etc.)")
    print("=" * 70)
    print()
    
    # Config file path
    config_file = "configs/proxy_configs.txt"
    
    # Check if file exists
    if not os.path.exists(config_file):
        # Try current directory as fallback
        config_file = "proxy_configs.txt"
        if not os.path.exists(config_file):
            print(f"❌ Error: Could not find proxy_configs.txt")
            print("   Please check the file path.")
            print("   Expected paths:")
            print("     - configs/proxy_configs.txt")
            print("     - proxy_configs.txt")
            return
    
    print(f"📁 Found config file: {config_file}")
    
    # Create checker and run analysis
    checker = DuplicateChecker(config_file)
    
    if checker.load_configs() == 0:
        print("❌ No valid proxy configs found in file!")
        return
    
    checker.analyze_duplicates()
    checker.show_summary()
    checker.print_duplicate_report()
    checker.print_protocol_statistics()
    checker.print_unparsable_list()
    checker.save_report("duplicate_report.txt")
    checker.save_deduplicated_configs("configs/proxy_configs_deduplicated.txt")
    
    print("\n" + "=" * 70)
    print("✅ Analysis complete!")
    print("=" * 70)

if __name__ == "__main__":
    main()
