import sys
import socket
import struct
import zlib
import time
from enum import IntEnum
from typing import Optional, List, Dict


class PacketType(IntEnum):
    START = 0
    END = 1
    DATA = 2
    ACK = 3


class RTPPacket:
    HEADER_LAYOUT = "!IIII"
    HEADER_SIZE = struct.calcsize(HEADER_LAYOUT)
    PAYLOAD_LIMIT = 1472 - HEADER_SIZE

    def __init__(self, pkt_type: int, seq_num: int, payload: bytes = b""):
        self.pkt_type = pkt_type
        self.seq_num = seq_num
        self.payload = payload

    def to_bytes(self) -> bytes:
        chk = zlib.crc32(self.payload) & 0xFFFFFFFF
        hdr = struct.pack(self.HEADER_LAYOUT, self.pkt_type, self.seq_num, len(self.payload), chk)
        return hdr + self.payload

    @classmethod
    def from_bytes(cls, raw: bytes) -> Optional["RTPPacket"]:
        if len(raw) < cls.HEADER_SIZE:
            return None
        p_type, seq, p_len, chk = struct.unpack(cls.HEADER_LAYOUT, raw[: cls.HEADER_SIZE])
        data = raw[cls.HEADER_SIZE :]
        if len(data) != p_len:
            return None
        if (zlib.crc32(data) & 0xFFFFFFFF) != chk:
            return None
        return cls(p_type, seq, data)


class SelectiveSender:
    RETRY_TIMEOUT = 0.5

    def __init__(self, dest_host: str, dest_port: int, window_capacity: int):
        self.destination = (dest_host, dest_port)
        self.window_capacity = window_capacity
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.01)

    def _fetch_ack(self) -> Optional[RTPPacket]:
        try:
            buf, _ = self.sock.recvfrom(2048)
            return RTPPacket.from_bytes(buf)
        except socket.timeout:
            return None

    def _dispatch_packet(self, pkt_type: int, seq: int, data: bytes = b"") -> None:
        packet = RTPPacket(pkt_type, seq, data)
        self.sock.sendto(packet.to_bytes(), self.destination)

    def _initiate_session(self) -> None:
        while True:
            self._dispatch_packet(PacketType.START, 0)
            ack = self._fetch_ack()
            if ack and ack.pkt_type == PacketType.ACK and ack.seq_num == 1:
                break

    def _stream_blocks(self, blocks: List[bytes]) -> int:
        total_blocks = len(blocks)
        window_base = 1
        upcoming_seq = 1
        stopwatch: Optional[float] = None
        acknowledged_map: Dict[int, bool] = {}

        while window_base <= total_blocks:
            while upcoming_seq < window_base + self.window_capacity and upcoming_seq <= total_blocks:
                self._dispatch_packet(PacketType.DATA, upcoming_seq, blocks[upcoming_seq - 1])
                acknowledged_map[upcoming_seq] = False
                if stopwatch is None:
                    stopwatch = time.time()
                upcoming_seq += 1

            ack = self._fetch_ack()
            if ack and ack.pkt_type == PacketType.ACK:
                arrived_seq = ack.seq_num
                if arrived_seq in acknowledged_map:
                    acknowledged_map[arrived_seq] = True

                # Trượt cửa sổ qua tất cả các gói đã nhận ACK liên tiếp
                prior_base = window_base
                while window_base in acknowledged_map and acknowledged_map[window_base]:
                    window_base += 1

                if window_base != prior_base:
                    stopwatch = None if window_base == upcoming_seq else time.time()

            # Quá hạn 500ms: CHỈ truyền lại các gói chưa được ACK trong cửa sổ
            if stopwatch and (time.time() - stopwatch >= self.RETRY_TIMEOUT):
                stopwatch = time.time()
                for seq_idx in range(window_base, upcoming_seq):
                    if not acknowledged_map.get(seq_idx, False):
                        self._dispatch_packet(PacketType.DATA, seq_idx, blocks[seq_idx - 1])

        return upcoming_seq

    def _terminate_session(self, final_seq: int) -> None:
        teardown_start = time.time()
        while time.time() - teardown_start < self.RETRY_TIMEOUT:
            self._dispatch_packet(PacketType.END, final_seq)
            ack = self._fetch_ack()
            if ack and ack.pkt_type == PacketType.ACK:
                break

    def execute(self) -> None:
        try:
            content = sys.stdin.buffer.read()
            limit = RTPPacket.PAYLOAD_LIMIT
            blocks = [content[idx : idx + limit] for idx in range(0, len(content), limit)]

            self._initiate_session()
            last_seq = self._stream_blocks(blocks)
            self._terminate_session(last_seq)
        finally:
            self.sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(1)
    sender_node = SelectiveSender(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
    sender_node.execute()
