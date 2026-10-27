import sys
import socket
import struct
import zlib
from enum import IntEnum
from typing import Optional


class PacketType(IntEnum):
    START = 0
    END = 1
    DATA = 2
    ACK = 3


class RTPPacket:
    HEADER_LAYOUT = "!IIII"
    HEADER_SIZE = struct.calcsize(HEADER_LAYOUT)

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


class SelectiveReceiver:
    def __init__(self, bind_host: str, bind_port: int, window_capacity: int):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.window_capacity = window_capacity
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.expected_seq = 1
        self.storage = {}
        self.active_peer = None
        self.connected = False

    def _reply_ack(self, ack_number: int) -> None:
        if self.active_peer:
            ack_pkt = RTPPacket(PacketType.ACK, ack_number, b"")
            self.sock.sendto(ack_pkt.to_bytes(), self.active_peer)

    def _flush_in_order(self) -> None:
        while self.expected_seq in self.storage:
            piece = self.storage.pop(self.expected_seq)
            sys.stdout.buffer.write(piece)
            sys.stdout.buffer.flush()
            self.expected_seq += 1

    def listen_and_serve(self) -> None:
        self.sock.bind((self.bind_host, self.bind_port))
        try:
            while True:
                raw_data, client_addr = self.sock.recvfrom(2048)
                pkt = RTPPacket.from_bytes(raw_data)
                if pkt is None:
                    continue

                if pkt.pkt_type == PacketType.START:
                    if not self.connected:
                        self.connected = True
                        self.active_peer = client_addr
                        self.expected_seq = 1
                        self.storage.clear()
                        self._reply_ack(1)
                    continue

                if not self.connected or client_addr != self.active_peer:
                    continue

                if pkt.pkt_type == PacketType.DATA:
                    if pkt.seq_num >= self.expected_seq + self.window_capacity:
                        continue

                    # Phản hồi ACK với chính xác seq_num của từng gói (Individual ACK)
                    self._reply_ack(pkt.seq_num)

                    if pkt.seq_num >= self.expected_seq:
                        self.storage[pkt.seq_num] = pkt.payload
                        self._flush_in_order()

                elif pkt.pkt_type == PacketType.END:
                    self._reply_ack(pkt.seq_num)
                    break
        finally:
            self.sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(1)
    receiver_node = SelectiveReceiver(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
    receiver_node.listen_and_serve()
