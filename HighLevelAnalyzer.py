# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
#
# SLIP decoder HLA for Saleae Logic 2
#
# Attach this HLA to an Async Serial analyzer. It will:
#   - Read decoded bytes from the serial analyzer
#   - Decode SLIP framing (0xC0, 0xDB escapes)
#   - Emit one AnalyzerFrame per SLIP packet

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame


END = 0xC0  # SLIP END
ESC = 0xDB  # SLIP ESC
ESC_END = 0xDC
ESC_ESC = 0xDD


class Hla(HighLevelAnalyzer):
    """
    SLIP High-Level Analyzer

    Input: Async Serial analyzer frames
      - frame.type == 'data'
      - frame.data['data'] is a bytearray / list of integers

    Output frames (UI-safe primitive types):
      - 'slip_packet': a decoded SLIP packet
      - 'slip_error' : error in SLIP stream (bad escape, etc)
    """

    # What shows up in the bubble text / data table.
    # Keys here must match the frame types and data keys we emit.
    result_types = {
        'slip_packet': {
            'format': 'SLIP len={{data.length}}: {{data.payload_hex}}'
        },
        'slip_error': {
            'format': 'SLIP ERROR: {{data.message}} (byte=0x{{data.byte:02X}})'
        },
    }

    def __init__(self):
        # Called once when the HLA is created
        self._reset_state()

    def _reset_state(self):
        self.escape = False
        self.buffer = bytearray()
        self.frame_start_time = None

    @staticmethod
    def _byte_spans(frame):
        """
        Yield (byte_value, start_time, end_time) for each byte in the frame.

        Async Serial gives one start/end for the whole decoded chunk; to avoid
        SaleaeTime math errors, keep the same times for each byte.
        """
        values = list(frame.data.get('data', []))
        if not values:
            return []
        return [(b, frame.start_time, frame.end_time) for b in values]

    def _emit_packet_frame(self, end_time):
        """Create an AnalyzerFrame for the current SLIP packet, if any."""
        if not self.buffer:
            return None

        payload = list(self.buffer)  # Keep JSON-serializable data for Logic
        payload_hex = ' '.join(f'{b:02X}' for b in payload)

        f = AnalyzerFrame(
            'slip_packet',
            self.frame_start_time if self.frame_start_time else end_time,
            end_time,
            {
                # Keep frame data to primitive types Saleae accepts (no lists)
                'payload_hex': payload_hex,
                'length': len(payload),
            }
        )

        return f

    def _emit_error_frame(self, end_time, message, offending_byte):
        """Create an AnalyzerFrame for an error in the SLIP stream."""
        f = AnalyzerFrame(
            'slip_error',
            self.frame_start_time if self.frame_start_time else end_time,
            end_time,
            {
                'message': message,
                'byte': offending_byte,
            }
        )
        # After an error, reset the state machine
        self._reset_state()
        return f

    def decode(self, frame):
        """
        Called once per input frame from the Async Serial analyzer.

        We may:
          - Return None              -> no output
          - Return a single frame    -> AnalyzerFrame(...)
          - Return a list of frames  -> [AnalyzerFrame(...), ...]
        """
        # We only care about data frames from Async Serial.
        if frame.type != 'data':
            return None

        out_frames = []

        for byte_val, byte_start, byte_end in self._byte_spans(frame):
            # Do not start a packet on a boundary END; wait for data
            if self.frame_start_time is None and byte_val != END:
                self.frame_start_time = byte_start

            if self.escape:
                # Previous byte was ESC; interpret this one specially
                if byte_val == ESC_END:
                    self.buffer.append(END)
                elif byte_val == ESC_ESC:
                    self.buffer.append(ESC)
                else:
                    # Invalid escape sequence
                    err = self._emit_error_frame(
                        byte_end,
                        'Invalid escape sequence after 0xDB',
                        byte_val
                    )
                    if err:
                        out_frames.append(err)
                self.escape = False
                continue

            # Not in escape mode
            if byte_val == ESC:
                # Next byte should be ESC_END or ESC_ESC
                self.escape = True
                if self.frame_start_time is None:
                    self.frame_start_time = byte_start
                continue

            if byte_val == END:
                # END marks the end of the current SLIP packet
                packet = self._emit_packet_frame(byte_end)
                if packet:
                    out_frames.append(packet)
                # Clear state and wait for the next packet (also handles empty packets)
                self._reset_state()
                continue

            # Regular data byte
            self.buffer.append(int(byte_val) & 0xFF)

        if not out_frames:
            return None
        return out_frames
