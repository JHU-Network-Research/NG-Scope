"""Receive the plot stream ngscope would otherwise have drawn with srsGUI.

ngscope's plot thread (ngscope/src/dciLib/status_plot.c) normally opens srsGUI windows for
two series -- the PDCCH equalized-symbol constellation and the channel-response magnitude.
When NGSCOPE_PLOT_SOCK names a unix socket, it streams those same two series here instead.

Frame layout, little-endian, matching plot_sink_send():

    uint32 magic 'NGP1'   uint32 seq   uint16 nof_const   uint16 nof_csi
    float  iq[2 * nof_const]
    float  iq[2 * nof_const]
    float  iq[2 * nof_const]
    float  csi[nof_csi]

Frames are decimated to roughly the width of the canvas before being handed on: the wire
carries up to 2048 CSI points and ~2900 constellation points per frame, and pushing all of
that through the JS bridge 20 times a second would cost far more than it shows.
"""

import os
import socket
import struct
import tempfile
import threading

MAGIC = 0x3150474E  # "NGP1"
HEADER = struct.Struct("<IIHHH")

# Enough to draw with; beyond this the extra points land on pixels already lit.
MAX_CONST_POINTS = 1200
MAX_CSI_POINTS = 600


def _recv_exactly(conn, n):
    chunks = bytearray()
    while len(chunks) < n:
        block = conn.recv(n - len(chunks))
        if not block:
            return None
        chunks.extend(block)
    return bytes(chunks)


def _decimate(values, limit):
    """Evenly thin a sequence to at most `limit` points, keeping the first and last."""
    n = len(values)
    if n <= limit:
        return list(values)
    step = n / limit
    return [values[min(n - 1, int(i * step))] for i in range(limit)]


class PlotFeed:
    """Listens on a unix socket for one ngscope connection at a time."""

    def __init__(self, on_frame):
        self._on_frame = on_frame
        self._dir = tempfile.mkdtemp(prefix="ngscope-gui-plot-")
        self.path = os.path.join(self._dir, "plot.sock")
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        self._server.listen(1)
        self._closed = False
        threading.Thread(target=self._accept_loop, name="plot-accept", daemon=True).start()

    # ------------------------------------------------------------------ receive

    def _accept_loop(self):
        while not self._closed:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(
                target=self._read_loop, args=(conn,), name="plot-read", daemon=True
            ).start()

    def _read_loop(self, conn):
        with conn:
            while not self._closed:
                head = _recv_exactly(conn, HEADER.size)
                if head is None:
                    break
                magic, seq, nof_const_pdcch, nof_const_pdsch, nof_csi = HEADER.unpack(head)
                if magic != MAGIC:
                    # Out of step with the stream; there is no way to resynchronise.
                    break

                iq_bytes_pdcch = _recv_exactly(conn, nof_const_pdcch * 2 * 4)
                iq_bytes_pdsch_cw1 = _recv_exactly(conn, nof_const_pdsch * 2 * 4);
                iq_bytes_pdsch_cw2 = _recv_exactly(conn, nof_const_pdsch * 2 * 4);
                csi_bytes = _recv_exactly(conn, nof_csi * 4)
                if iq_bytes_pdcch is None or iq_bytes_pdsch_cw1 is None or iq_bytes_pdsch_cw2 is None or csi_bytes is None:
                    break

                iq_pdcch = struct.unpack(f"<{nof_const_pdcch * 2}f", iq_bytes_pdcch) if nof_const_pdcch else ()
                iq_pdsch_cw1 = struct.unpack(f"<{nof_const_pdsch * 2}f", iq_bytes_pdsch_cw1) if nof_const_pdsch else ()
                iq_pdsch_cw2 = struct.unpack(f"<{nof_const_pdsch * 2}f", iq_bytes_pdsch_cw2) if nof_const_pdsch else ()
                csi = struct.unpack(f"<{nof_csi}f", csi_bytes) if nof_csi else ()

                points_pdcch = list(zip(iq_pdcch[0::2], iq_pdcch[1::2]))
                thinned_pdcch = _decimate(points_pdcch, MAX_CONST_POINTS)

                points_pdsch_cw1 = list(zip(iq_pdsch_cw1[0::2], iq_pdsch_cw1[1::2]))
                thinned_pdsch_cw1 = _decimate(points_pdsch_cw1, MAX_CONST_POINTS)

                points_pdsch_cw2 = list(zip(iq_pdsch_cw2[0::2], iq_pdsch_cw2[1::2]))
                thinned_pdsch_cw2 = _decimate(points_pdsch_cw2, MAX_CONST_POINTS)

                try:
                    self._on_frame({
                        "seq": seq,
                        # Flat [i0, q0, i1, q1, ...] -- half the JSON of nested pairs.
                        "iq_pdcch": [round(v, 4) for pair in thinned_pdcch for v in pair],
                        "iq_pdsch_cw1": [round(v, 4) for pair in thinned_pdsch_cw1 for v in pair],
                        "iq_pdsch_cw2": [round(v, 4) for pair in thinned_pdsch_cw2 for v in pair],
                        "csi": [round(v, 2) for v in _decimate(csi, MAX_CSI_POINTS)],
                        "nof_const_pdcch": nof_const_pdcch,
                        "nof_const_pdsch": nof_const_pdsch,
                        "nof_csi": nof_csi,
                    })
                except Exception:  # noqa: BLE001 - a render failure must not kill the feed
                    pass

    # ------------------------------------------------------------------ teardown

    def close(self):
        self._closed = True
        try:
            self._server.close()
        except OSError:
            pass
        for path in (self.path, self._dir):
            try:
                os.rmdir(path) if path == self._dir else os.unlink(path)
            except OSError:
                pass
