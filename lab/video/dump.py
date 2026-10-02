"""
4-byte packet format (big-endian, 1 byte each field):
    [0x00][gray][run_hi][run_lo]   RUN  -> paint `run` pixels of 8-bit `gray`
    [0x01][ w  ][  h   ][  0   ]   DIMS -> frame dimensions (sent once)
    [0x02][ 0  ][  0   ][  0   ]   FLIP -> frame finished; display + reset cursor
"""
import argparse
import os
import cv2
import numpy as np
import sys
import time
from protocol import HEIGHT, OP_DIMS, OP_FLIP, OP_RUN, WIDTH

DEFAULT_FPS = 24

class FileChannel:
    def __init__(self, sink=None):
        self.sink = sink
        self.out = bytearray() if sink is None else None
        self.packets = 0
        self.bytes = 0

    def send(self, b0: int, b1: int, b2: int, b3: int) -> None:
        packet = bytes((b0 & 0xFF, b1 & 0xFF, b2 & 0xFF, b3 & 0xFF))
        if self.sink is None:
            assert self.out is not None
            self.out.extend(packet)
        else:
            self.sink.write(packet)

        self.packets += 1
        self.bytes += 4

    def flush_frame(self) -> None:
        if self.sink is not None:
            self.sink.flush()

def get_video_frames(path: str, levels: int):
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        raise SystemExit(f"could not open video: {path}")

    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.resize(gray, (WIDTH, HEIGHT), interpolation=cv2.INTER_AREA)
            q = np.round(gray.astype(np.float32) / 255.0 * (levels - 1))
            gray = (q / (levels - 1) * 255.0).astype(np.uint8)
            yield gray.tobytes()
    finally:
        cap.release()


def get_video_fps(path: str) -> int:
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        raise SystemExit(f"could not open video: ${path}")
    try:
        fps = int(cap.get(cv2.CAP_PROP_FPS))
    finally:
        cap.release()
    return fps if fps > 0 else DEFAULT_FPS

def encode_frame(ch: FileChannel, pixels: bytes) -> None:
    i, n = 0, len(pixels)
    while i < n:
        val = pixels[i]
        j = i + 1
        while j < n and pixels[j] == val and (j - i) < 0xFFFF:
            j += 1
        ch.send(OP_RUN, val, (j - i) >> 8, (j - i) & 0xFF)
        i = j
    ch.send(OP_FLIP, 0, 0, 0)
    ch.flush_frame()

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="payload.bin", help="output file, or '-' to stream to stdout")
    ap.add_argument("--video", default="video.mp4" if os.path.exists("video.mp4") else None)
    ap.add_argument("--fps", type=int, default=DEFAULT_FPS)
    ap.add_argument("--levels", type=int, default=2, help="grayscale levels to quantize to (2 = black/white, fewer packets)")
    ap.add_argument("--verbose", type=bool, default=False, help="display more information")

    args = ap.parse_args()
    if not args.video:
        print("missing input video")
        sys.exit(1)

    is_streaming = args.output == "-"
    frames = get_video_frames(args.video, args.levels)
    fps = args.fps if args.fps is not None else get_video_fps(args.video)

    log = sys.stderr if is_streaming else sys.stdout
    print(f"[dump] encoding {args.video} -> {args.output} " f"(levels={args.levels}, fps={fps:.3f})", file=log)

    if not (fps > 0.0 and fps < float("inf")):
        ap.error("frame rate must be finite and greater than zero")

    sink = sys.stdout.buffer if is_streaming else None
    ch = FileChannel(sink)
    ch.send(OP_DIMS, WIDTH, HEIGHT, 0)
    ch.flush_frame()

    start = time.perf_counter()
    shown = 0
    for pixels in frames:
        if is_streaming:
            target = start + shown / fps
            delay = target - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
        before = ch.packets
        encode_frame(ch, pixels)
        shown += 1
        if args.verbose:
            print(f"[frame {shown:5d}] {ch.packets - before:4d} packets  "
                f"(total {ch.packets} packets / {ch.bytes}B)", file=sys.stderr)

    if is_streaming:
        print(f"[dump] streamed {shown} frames, {ch.packets} packets at {fps:.3f} fps", file=sys.stderr)
        return

    with open(args.output, "wb") as f:
        assert ch.out is not None
        f.write(ch.out)

    size_note = f"{ch.bytes} bytes (uncompressed)"
    print(f"[dump] wrote {args.output}: {shown} frames, "
          f"{ch.packets} packets, {size_note} at {fps:.3f} fps")

if __name__ == "__main__":
    main()
