import argparse
import socket
import struct

import pygame

from protocol import HEIGHT, OP_DIMS, OP_FLIP, OP_RUN, WIDTH

SCALE = 7
IPV4_MIN_HEADER = 20
TCP_MIN_HEADER = 20
TCP_SYN = 0x02
TCP_ACK = 0x10

def parse_syn_isn(packet: bytes) -> tuple[str, int, int] | None:
    if len(packet) < IPV4_MIN_HEADER:
        return None

    version_ihl = packet[0]
    if version_ihl >> 4 != 4 or packet[9] != socket.IPPROTO_TCP:
        return None

    ip_header_len = (version_ihl & 0x0F) * 4
    if ip_header_len < IPV4_MIN_HEADER:
        return None

    total_len = struct.unpack_from("!H", packet, 2)[0]
    tcp_offset = ip_header_len
    if total_len < tcp_offset + TCP_MIN_HEADER or len(packet) < tcp_offset + TCP_MIN_HEADER:
        return None

    tcp_header_len = (packet[tcp_offset + 12] >> 4) * 4
    if (
        tcp_header_len < TCP_MIN_HEADER
        or total_len < tcp_offset + tcp_header_len
        or len(packet) < tcp_offset + tcp_header_len
    ):
        return None

    flags = packet[tcp_offset + 13]
    if not (flags & TCP_SYN) or (flags & TCP_ACK):
        return None

    source_ip = socket.inet_ntoa(packet[12:16])
    destination_port, = struct.unpack_from("!H", packet, tcp_offset + 2)
    sequence, = struct.unpack_from("!I", packet, tcp_offset + 4)
    return source_ip, destination_port, sequence


class TcpSynIsnReader:
    def __init__(self, interface: str, port: int, source: str | None = None):
        self.port = port
        self.source = source
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            interface.encode() + b"\0",
        )
        self.sock.bind(("0.0.0.0", 0))

    def read(self) -> int:
        while True:
            packet = self.sock.recv(65535)
            parsed = parse_syn_isn(packet)
            if parsed is None:
                continue

            source_ip, destination_port, sequence = parsed
            if destination_port != self.port:
                continue
            if self.source is not None and source_ip != self.source:
                continue
            return sequence

    def close(self) -> None:
        self.sock.close()


class Display:
    def __init__(self):
        pygame.init()
        self.width = 0
        self.height = 0
        self.framebuffer: bytearray | None = None
        self.screen = None
        self.cursor = 0
        self.frame_valid = False

    def handle(self, word: int) -> None:
        opcode = (word >> 24) & 0xFF
        a = (word >> 16) & 0xFF
        b = (word >> 8) & 0xFF
        c = word & 0xFF

        if opcode == OP_DIMS:
            self._set_dimensions(a, b, c)
        elif opcode == OP_RUN:
            self._run(a, (b << 8) | c)
        elif opcode == OP_FLIP:
            self._present()

    def _set_dimensions(self, width: int, height: int, reserved: int) -> None:
        if (width, height, reserved) != (WIDTH, HEIGHT, 0):
            return

        self.width, self.height = width, height
        self.framebuffer = bytearray(width * height)
        self.cursor = 0
        self.frame_valid = True
        self.screen = pygame.display.set_mode((width * SCALE, height * SCALE))
        pygame.display.set_caption("Bad Apple!! — TCP SYN ISN")
        print(f"[server] dimensions: {width}x{height}")

    def _run(self, gray: int, length: int) -> None:
        if self.framebuffer is None or not self.frame_valid:
            return

        end = self.cursor + length
        if end > len(self.framebuffer):
            self.frame_valid = False
            self.cursor = 0
            return

        self.framebuffer[self.cursor:end] = bytes((gray,)) * length
        self.cursor = end

    def _present(self) -> None:
        if self.framebuffer is None or self.screen is None:
            return

        if not self.frame_valid or self.cursor != len(self.framebuffer):
            self.cursor = 0
            self.frame_valid = True
            return

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                raise KeyboardInterrupt

        rgb = bytearray(len(self.framebuffer) * 3)
        rgb[0::3] = self.framebuffer
        rgb[1::3] = self.framebuffer
        rgb[2::3] = self.framebuffer
        image = pygame.image.frombuffer(bytes(rgb), (self.width, self.height), "RGB")
        scaled = pygame.transform.scale(
            image, (self.width * SCALE, self.height * SCALE)
        )
        self.screen.blit(scaled, (0, 0))
        pygame.display.flip()
        self.cursor = 0

    def close(self) -> None:
        pygame.quit()

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True, help="interface to listen on")
    parser.add_argument("--port", type=int, default=6769, help="TCP destination port")
    parser.add_argument("--source", help="accept SYNs only from this source IP")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    reader = None
    display = None
    try:
        reader = TcpSynIsnReader(args.interface, args.port, args.source)
        display = Display()
        print(
            f"[server] listening for TCP SYN/ISN commands on "
            f"{args.interface}, port {args.port}"
        )
        while True:
            display.handle(reader.read())
    except KeyboardInterrupt:
        print("\n[server] stopped")
    finally:
        if display is not None:
            display.close()
        if reader is not None:
            reader.close()

if __name__ == "__main__":
    main()
