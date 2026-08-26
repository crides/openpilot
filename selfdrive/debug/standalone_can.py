#!/usr/bin/env python3
"""Standalone CAN bus / UDS tool - talks to the bus directly, no openpilot stack needed.

Normally, openpilot's CAN traffic flows through the whole daemon stack:

  cardd --('sendcan', msgq)--> pandad --> panda (USB/SPI) --> car
  car --> panda --> ('can', msgq) --> logcan / loggerd

...which is why you usually "can't" use opendbc from a one-off script. This
script bypasses all of that. All you need to send standalone messages is:

  1. a transport object that duck-types the panda python API
       can_send(addr, dat, bus, *, fd=False, timeout=0)
       can_recv() -> list[(addr, dat, bus)]
       can_clear(bus), set_safety_mode(mode)
     and one of:
       panda (this repo)      comma panda over USB/SPI
       SocketPanda (panda/python/socketpanda.py)
                             Linux socketcan interface, e.g. a USBCAN-FD
                             adapter or vcan - no panda hardware needed
       MockPanda (this file)  in-memory bus, for testing with no hardware
  2. opendbc client libraries, which take that transport:
       UdsClient  (opendbc/car/uds.py)   UDS / ISO-TP diagnostics
       CANPacker  (opendbc/can/packer.py) pack DBC-defined messages
     (XcpClient / CcpClient in opendbc/car/{xcp,ccp}.py work the same way)

Note: with a real panda you must pick a safety model that allows the TX
addresses (safety checks block non-whitelisted frames):
  - uds:  elm327 (allows 8-byte ISO 15765 diag frames to 0x600-0x7FF,
          0x18DA00F1, 0x18DB33F1, ...) - same as selfdrive/debug/read_dtc_status.py
  - raw/pack: allOutput (allows everything)

Examples (from the repo root, using the repo venv):

  # no hardware at all: full UDS session (session, tester present, VIN,
  # DTCs, ECU reset) against a built-in fake ECU on the in-memory bus
  .venv/bin/python selfdrive/debug/standalone_can.py selftest

  # panda on the OBD-II bus: extended session + read VIN
  .venv/bin/python selfdrive/debug/standalone_can.py uds 0x7df --req "10 03" --req "22 f190" --bus 1

  # host CAN adapter on can0 (no panda): read some data identifiers
  .venv/bin/python selfdrive/debug/standalone_can.py uds 0x612 --req "22 f190" \\
      --transport socketcan --interface can0 --bus 0

  # raw frame, then watch the bus for 2s to see what comes back
  .venv/bin/python selfdrive/debug/standalone_can.py raw 0x18db33f1:1003 --listen 2

  # pack a DBC-defined message with opendbc CANPacker and send it
  # (counters/checksums are filled in automatically)
  .venv/bin/python selfdrive/debug/standalone_can.py pack toyota_nodsu_pt_generated \\
      --msg LTA_RELATED --sig STEER_ANGLE=10
"""
import argparse
import struct
import sys
import time
from collections import deque

from opendbc.car.carlog import carlog
from opendbc.can.packer import CANPacker
from opendbc.car.uds import (UdsClient, IsoTpMessage, SERVICE_TYPE, SESSION_TYPE, DATA_IDENTIFIER_TYPE,
                             RESET_TYPE, DTC_REPORT_TYPE, DTC_STATUS_MASK_TYPE, get_rx_addr_for_tx_addr,
                             get_dtc_num_as_str, get_dtc_status_names, MessageTimeoutError,
                             NegativeResponseError, InvalidServiceIdError, InvalidSubFunctionError)

SAFETY_MODES = {  # opendbc/car/car.capnp SafetyModel
  'silent': 0, 'noOutput': 19, 'elm327': 3, 'allOutput': 17,
}

EPILOG = '''
examples (run from the repo root with the repo venv):

  # no hardware: full UDS session against the built-in fake ECU
  .venv/bin/python selfdrive/debug/standalone_can.py selftest

  # panda on the OBD-II bus: extended session + read VIN
  .venv/bin/python selfdrive/debug/standalone_can.py uds 0x7df --req "10 03" --req "22 f190" --bus 1

  # host CAN adapter on can0 (no panda)
  .venv/bin/python selfdrive/debug/standalone_can.py uds 0x612 --req "22 f190" --transport socketcan --interface can0

  # raw frame, then watch the bus for 2s to see what comes back
  .venv/bin/python selfdrive/debug/standalone_can.py raw 0x18db33f1:1003 --listen 2

  # pack a DBC-defined message with opendbc CANPacker and send it
  # (counters/checksums are filled in automatically)
  .venv/bin/python selfdrive/debug/standalone_can.py pack toyota_nodsu_pt_generated \\
      --msg LTA_RELATED --sig STEER_ANGLE=10
'''.strip()

# ----------------------------------------------------------------------------
# in-memory transport (duck-types panda.Panda / SocketPanda)
# ----------------------------------------------------------------------------

class MockBus:
  """shared in-memory frame queue; frames are (addr, bytes, bus)"""

  def __init__(self):
    self._frames: deque[tuple[int, bytes, int]] = deque()

  def post(self, addr: int, dat: bytes, bus: int = 0) -> None:
    self._frames.append((addr, bytes(dat), bus))

  def drain(self, addrs: frozenset[int] | None) -> list[tuple[int, bytes, int]]:
    """returns frames addressed to any of `addrs` (None = all), preserving order"""
    out: list[tuple[int, bytes, int]] = []
    rest: deque[tuple[int, bytes, int]] = deque()
    while self._frames:
      f = self._frames.popleft()
      (out if addrs is None or f[0] in addrs else rest).append(f)
    self._frames.extend(rest)
    return out

  def clear(self) -> None:
    self._frames.clear()


class FakeEcu:
  """Tiny UDS/ISO-TP ECU (ISO 14229-1 + 15765-2) for testing with no hardware.

  Supports: session control, ECU reset, tester present, readDataByIdentifier
  (VIN + active session), readDtcInformation, and multi-frame responses.
  """

  VIN = b'SUNNYPILOT0000001'

  def __init__(self, addr: int, rx_addr: int, bus: int = 0):
    self.addr = addr  # address we listen on (the tester's tx address)
    self.rx_addr = rx_addr  # address we respond on (the tester's rx address)
    self.bus = bus
    self.session = 1
    self._pending: bytes = b''
    self._offset = 0
    self._seq = 0

  # -- ISO-TP (ISO 15765-2) master side ------------------------------------

  def handle(self, dat: bytes, post) -> None:
    ft = dat[0] >> 4
    if ft == 3:  # flow control
      self._tx_next(post)
    elif ft == 0:  # single frame
      n = dat[0] & 0xF
      self._respond(self._process(dat[1:1 + n]), post)
    else:  # first/consecutive request frames: not supported, NRC
      self._respond(self._nrc(0x00), post)

  def _tx_next(self, post) -> None:
    max_len = 8
    total = len(self._pending)
    if self._offset == 0 and total:
      n = max_len - 2  # first frame: 2-byte length header
      post(self.rx_addr, (struct.pack('!H', 0x1000 | total) + self._pending[:n]).ljust(max_len, b'\x00'))
      self._offset = n
    while self._offset < total:
      self._seq = (self._seq + 1) & 0xF
      n = max_len - 1  # consecutive frame: 1-byte sequence header
      post(self.rx_addr, (bytes([0x20 | self._seq]) + self._pending[self._offset:self._offset + n]).ljust(max_len, b'\x00'))
      self._offset += n
    self._pending = b''

  def _respond(self, resp: bytes, post) -> None:
    self._pending = b''
    if len(resp) < 8:
      post(self.rx_addr, (bytes([len(resp)]) + resp).ljust(8, b'\x00'))
    else:
      self._pending = resp
      self._offset = 0
      self._seq = 0
      self._tx_next(post)

  # -- UDS (ISO 14229-1) ----------------------------------------------------

  def _nrc(self, sid: int) -> bytes:
    return bytes([0x7F, sid, 0x11])  # service not supported

  def _process(self, req: bytes) -> bytes:
    if not req:
      return self._nrc(0x00)
    sid, data = req[0], req[1:]
    if sid == 0x10:  # diagnosticSessionControl
      self.session = data[0] if data else 1
      return bytes([0x50, self.session])
    if sid == 0x11:  # ecuReset
      return bytes([0x51, data[0] if data else 0])
    if sid == 0x3E:  # testerPresent
      return bytes([0x7E, data[0] if data else 0])
    if sid == 0x22:  # readDataByIdentifier
      if data[:2] == b'\xF1\x90':
        return b'\x62\xF1\x90' + self.VIN
      if data[:2] == b'\xF1\x86':
        return b'\x62\xF1\x86' + bytes([self.session])
      return self._nrc(sid)
    if sid == 0x19:  # readDtcInformation
      if data[:1] == b'\x02':  # DTCByStatusMask: count + (3-byte DTC, status) * count
        return b'\x59\x02\x01\x01\x03\x00\x0C'  # 1 DTC: P0103xx, confirmed+pending
      return self._nrc(sid)
    return self._nrc(sid)


class MockPanda:
  """In-memory stand-in for panda.Panda / SocketPanda.

  Implements the duck-typed surface used by the opendbc client libraries
  (can_send / can_recv / can_clear / set_safety_mode). If an FakeEcu is
  attached, frames addressed to it are processed synchronously on can_recv,
  so the full UDS/ISO-TP request-response loop works deterministically.
  """

  def __init__(self, bus: MockBus, rx_addrs: frozenset[int] | None = None,
               ecu: FakeEcu | None = None, bus_num: int = 0):
    self._bus = bus
    self._rx_addrs = rx_addrs  # None = receive everything (loopback-like)
    self._ecu = ecu
    self._bus_num = bus_num
    self.sent: list[tuple[int, bytes, int]] = []
    self.safety_modes: list[int] = []

  def set_safety_mode(self, mode: int, param: int = 0) -> None:
    self.safety_modes.append(mode)

  def can_clear(self, bus: int) -> None:
    self._bus.clear()

  def can_send(self, addr: int, dat: bytes, bus: int, *, fd: bool = False, timeout: int = 0) -> None:
    self.sent.append((addr, bytes(dat), bus))
    if self._ecu is not None and addr == self._ecu.addr:
      self._ecu.handle(bytes(dat), lambda a, d: self._bus.post(a, d, self._bus_num))

  def can_recv(self) -> list[tuple[int, bytes, int]]:
    if self._ecu is not None:
      for _, dat, _ in self._bus.drain(frozenset({self._ecu.addr})):
        self._ecu.handle(dat, lambda a, d: self._bus.post(a, d, self._bus_num))
    return self._bus.drain(self._rx_addrs)


# ----------------------------------------------------------------------------
# transports
# ----------------------------------------------------------------------------

def make_transport(args, rx_addrs: frozenset[int] | None = None, want_ecu: bool = False,
                   ecu_addrs: tuple[int, int] | None = None) -> tuple[object, str]:
  t = args.transport
  if t == 'auto':
    if args.interface is not None:
      t = 'socketcan'
    else:
      try:
        from panda import Panda
        t = 'panda' if Panda.list() else 'mock'
      except Exception as e:
        carlog.warning(f'could not scan for panda ({e}); falling back to mock')
        t = 'mock'
    if t == 'mock':
      carlog.warning('no panda or CAN interface found - using in-memory mock bus '
                     '(nothing reaches a real CAN bus!)')

  if t == 'panda':
    from panda import Panda
    return Panda(serial=args.serial), 'panda'
  if t == 'socketcan':
    from panda.python.socketpanda import SocketPanda
    if args.interface is None:
      raise SystemExit('socketcan transport requires --interface (e.g. can0 or vcan0)')
    try:
      return SocketPanda(args.interface), 'socketcan'
    except OSError as e:
      raise SystemExit(f'failed to open socketcan interface {args.interface!r}: {e} '
                       f'(try: sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0)')
  bus = MockBus()
  ecu = FakeEcu(*ecu_addrs, bus=args.bus) if want_ecu and ecu_addrs else None
  return MockPanda(bus, rx_addrs, ecu, bus_num=args.bus), 'mock'


def set_panda_safety(transport: object, tname: str, mode_name: str | None) -> None:
  if tname != 'panda' or mode_name is None:
    return
  mode = SAFETY_MODES[mode_name]
  transport.set_safety_mode(mode)
  carlog.info(f'set panda safety mode: {mode_name} ({mode})')


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

def parse_int(v: str) -> int:
  return int(v, 0)


def parse_hex_bytes(v: str) -> bytes:
  try:
    b = bytes.fromhex(v.replace(' ', '').replace(':', ''))
  except ValueError:
    raise SystemExit(f'invalid hex: {v!r} (want e.g. "10 03", "10:03" or "1003")')
  if not b:
    raise SystemExit(f'empty hex data: {v!r}')
  return b


def hexify(b: bytes) -> str:
  return b.hex(' ').upper()


def parse_frame(spec: str, default_bus: int = 0) -> tuple[int, bytes, int]:
  """ADDR:DATA[:BUS]"""
  parts = spec.split(':')
  if len(parts) not in (2, 3):
    raise SystemExit(f'expected ADDR:DATA[:BUS], got {spec!r}')
  addr = parse_int(parts[0])
  dat = parse_hex_bytes(parts[1])
  bus = parse_int(parts[2]) if len(parts) == 3 else default_bus
  return addr, dat, bus


def listen(transport: object, seconds: float) -> None:
  print(f'-- listening on {seconds:.1f}s ...')
  t_end = time.monotonic() + seconds
  count = 0
  while time.monotonic() < t_end:
    for addr, dat, bus in transport.can_recv():
      count += 1
      bus_num = bus & 0x7F
      flags = []
      if bus >= 192:
        flags.append("REJECTED")
        bus_num = bus - 192
      elif bus >= 128:
        flags.append("TX_ACK")
        bus_num = bus - 128
      flag_str = f" [{','.join(flags)}]" if flags else ""
      
      print(f'RX bus={bus_num}{flag_str} {addr:#06x} ({len(dat)}): {hexify(dat)}')
    time.sleep(0.01)
  print(f'-- {count} frame(s) received')


# ----------------------------------------------------------------------------
# subcommands
# ----------------------------------------------------------------------------

def cmd_uds(args) -> int:
  tx_addr = parse_int(args.tx_addr)
  rx_addr = parse_int(args.rx_addr) if args.rx_addr else get_rx_addr_for_tx_addr(tx_addr)
  reqs = [parse_hex_bytes(r) for r in args.req]

  ecu = not args.no_ecu  # only actually attaches if the transport resolves to mock
  transport, tname = make_transport(args, rx_addrs=frozenset({rx_addr}),
                                    want_ecu=ecu, ecu_addrs=(tx_addr, rx_addr))
  set_panda_safety(transport, tname, 'elm327' if args.obd else 'allOutput')
  
  if tname == 'panda':
    if getattr(args, 'baud', None) is not None:
      transport.set_can_speed_kbps(args.bus, args.baud)
    if getattr(args, 'data_baud', None) is not None:
      transport.set_can_data_speed_kbps(args.bus, args.data_baud)
    if getattr(args, 'non_iso', False):
      transport.set_canfd_non_iso(args.bus, True)

  if tname == 'mock' and ecu:
    carlog.info(f'mock: fake UDS ECU attached at {tx_addr:#x} (responds on {rx_addr:#x})')

  uds = UdsClient(transport, tx_addr, rx_addr, bus=args.bus,
                  sub_addr=args.sub_addr, rx_sub_addr=args.rx_sub_addr,
                  timeout=args.timeout)

  rc = 0
  for i, req in enumerate(reqs, 1):
    print(f'\n[{i}/{len(reqs)}] REQUEST  {tx_addr:#06x}: {hexify(req)}')
    try:
      sid = req[0]
      if sid in SERVICE_TYPE._value2member_map_:
        resp = uds._uds_request(SERVICE_TYPE(sid), data=req[1:])
      else:
        # non-standard service: go below UdsClient, straight to ISO-TP
        isotp = IsoTpMessage(uds._can_client, timeout=args.timeout)
        isotp.send(req)
        resp, _ = isotp.recv()
        if resp is None:
          raise MessageTimeoutError('timeout waiting for response')
      print(f'           RESPONSE {rx_addr:#06x}: {hexify(resp)}')
    except (NegativeResponseError, MessageTimeoutError, InvalidServiceIdError,
            InvalidSubFunctionError, AssertionError) as e:
      print(f'           FAILED: {e}')
      rc = 1
  return rc


def cmd_selftest(args) -> int:
  tx_addr = 0x700
  rx_addr = get_rx_addr_for_tx_addr(tx_addr)
  bus = MockBus()
  ecu = FakeEcu(tx_addr, rx_addr, bus=args.bus)
  transport = MockPanda(bus, frozenset({rx_addr}), ecu, bus_num=args.bus)
  uds = UdsClient(transport, tx_addr, rx_addr, bus=args.bus, timeout=1.0)

  print(f'selftest: in-memory bus, fake ECU at {tx_addr:#x}, responses on {rx_addr:#x}')
  failures = []

  def check(name: str, fn, *a, **kw) -> bytes | None:
    try:
      r = fn(*a, **kw)
      print(f'  ok   {name}')
      return r
    except Exception as e:
      print(f'  FAIL {name}: {e}')
      failures.append(name)
      return None

  print('diagnosticSessionControl(EXTENDED):')
  check('session -> extended', uds.diagnostic_session_control, SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  check('testerPresent', uds.tester_present)
  print('readDataByIdentifier(VIN):  (19-byte response -> first frame + consecutive frames)')
  vin = check('vin', uds.read_data_by_identifier, DATA_IDENTIFIER_TYPE.VIN)
  if vin is not None:
    print(f'       VIN = {vin.decode("ascii")}')
  print('readDtcInformation(DTCByStatusMask):')
  dtc = check('dtcs', uds.read_dtc_information, DTC_REPORT_TYPE.DTC_BY_STATUS_MASK, DTC_STATUS_MASK_TYPE.ALL)
  if dtc is not None:
    for i in range(1, len(dtc), 4):
      print(f'       {get_dtc_num_as_str(dtc[i:i + 3])}  {", ".join(get_dtc_status_names(dtc[i + 3])) or "no status"}')
  check('ecuReset(SOFT)', uds.ecu_reset, RESET_TYPE.SOFT)

  # also exercise the raw ISO-TP path with a non-standard service id
  print('non-standard service 0x84 (via raw IsoTpMessage):')
  isotp = IsoTpMessage(uds._can_client, timeout=1.0)
  isotp.send(b'\x84\xAA\xBB')
  resp, _ = isotp.recv()
  if resp is None:
    failures.append('non-standard service (no response)')
    print('  FAIL no response')
  else:
    ok = resp[:1] == b'\xC4' or resp[0] == 0x7F
    print(f'  {"ok  " if ok else "FAIL"} response: {hexify(resp)}')
    if not ok:
      failures.append('non-standard service (bad response)')

  print(f'\nselftest: {"PASS" if not failures else f"FAIL ({len(failures)}): {failures}"}')
  return 1 if failures else 0


def cmd_raw(args) -> int:
  if not args.frame:
    raise SystemExit('raw requires at least one ADDR:HEXDATA[:BUS] frame')
  frames = [parse_frame(f, args.bus) for f in args.frame]
  transport, tname = make_transport(args)  # rx_addrs=None: see everything
  set_panda_safety(transport, tname, 'elm327' if args.obd else 'allOutput')
  
  if tname == 'panda':
    if getattr(args, 'baud', None) is not None:
      transport.set_can_speed_kbps(args.bus, args.baud)
    if getattr(args, 'data_baud', None) is not None:
      transport.set_can_data_speed_kbps(args.bus, args.data_baud)
    if getattr(args, 'non_iso', False):
      transport.set_canfd_non_iso(args.bus, True)

  for addr, dat, bus in frames:
    if len(dat) > 8:
      raise SystemExit(f'{addr:#x}: data too long for classic CAN ({len(dat)} > 8 bytes)')
    transport.can_send(addr, dat, bus)
    print(f'TX bus={bus} {addr:#06x} ({len(dat)}): {hexify(dat)}')
    print(f'   (transport: {tname})')
  if args.listen is not None:
    listen(transport, args.listen)
  return 0


def cmd_pack(args) -> int:
  packer = CANPacker(args.dbc)
  values = {}
  for s in args.sig:
    if '=' not in s:
      raise SystemExit(f'--sig expects NAME=VALUE, got {s!r}')
    k, v = s.split('=', 1)
    values[k] = float(v)

  try:
    addr = parse_int(args.msg)  # 0x1234 style address
    name = None
  except ValueError:
    addr = None  # message name
    name = args.msg

  out_addr, dat, bus = packer.make_can_msg(addr if addr is not None else name, args.bus, values)
  if not dat:
    raise SystemExit('nothing to send (unknown message/signal?)')
  msg = packer.dbc.addr_to_msg.get(out_addr)
  if msg is not None:
    print(f'{args.dbc} / {msg.name} ({out_addr:#x}):')
    for sig in msg.sigs.values():
      if sig.name in values:
        print(f'  {sig.name} = {values[sig.name]}  (size={sig.size} factor={sig.factor} offset={sig.offset})')
  print(f'TX bus={bus} {out_addr:#x} ({len(dat)}): {hexify(bytes(dat))}')

  transport, tname = make_transport(args)
  set_panda_safety(transport, tname, 'allOutput')
  
  if tname == 'panda':
    if getattr(args, 'baud', None) is not None:
      transport.set_can_speed_kbps(args.bus, args.baud)
    if getattr(args, 'data_baud', None) is not None:
      transport.set_can_data_speed_kbps(args.bus, args.data_baud)
    if getattr(args, 'non_iso', False):
      transport.set_canfd_non_iso(args.bus, True)

  transport.can_send(out_addr, dat, bus)
  print(f'   (sent via {tname})')
  if args.listen is not None:
    listen(transport, args.listen)
  return 0


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def add_transport_args(p: argparse.ArgumentParser) -> None:
  p.add_argument('--transport', choices=['auto', 'panda', 'socketcan', 'mock'], default='auto',
                 help='auto = socketcan if --interface, else panda if attached, else mock (default: auto)')
  p.add_argument('--interface', help='socketcan interface name, e.g. can0 or vcan0 (socketcan transport)')
  p.add_argument('--serial', help='panda serial number (panda transport)')
  p.add_argument('--bus', type=int, default=0, help='CAN bus number (default: 0)')
  p.add_argument('--obd', action='store_true', help='multiplex bus 1 to the OBD-II port (panda only)')
  p.add_argument('--baud', type=int, help='CAN baud rate in kbps (e.g. 500)')
  p.add_argument('--data-baud', type=int, help='CAN-FD data baud rate in kbps (e.g. 2000)')
  p.add_argument('--non-iso', action='store_true', help='Use Non-ISO (Bosch) CAN-FD format (panda only)')


def main() -> int:
  parser = argparse.ArgumentParser(description='standalone CAN bus / UDS tool (no openpilot stack required)',
                                   formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)
  parser.add_argument('--debug', action='store_true', help='enable debug logging')
  sub = parser.add_subparsers(dest='cmd', required=True)

  p = sub.add_parser('uds', help='UDS (ISO 14229) requests over ISO-TP, via opendbc UdsClient',
                     formatter_class=argparse.RawDescriptionHelpFormatter)
  p.add_argument('tx_addr', help='tester request address, e.g. 0x7df (functional) or 0x700 (physical)')
  p.add_argument('rx_addr', nargs='?', help='tester response address (default: derived from tx_addr)')
  p.add_argument('--req', action='append', required=True, metavar='HEX',
                 help='UDS payload, e.g. "10 03" (session control) - repeatable')
  p.add_argument('--sub-addr', type=parse_int, help='ISO-TP sub-address (hyundai canfd etc.)')
  p.add_argument('--rx-sub-addr', type=parse_int, help='expected rx sub-address')
  p.add_argument('--timeout', type=float, default=1.0, help='response timeout in seconds (default: 1.0)')
  p.add_argument('--no-ecu', action='store_true', help='mock transport: do not attach the fake ECU')
  add_transport_args(p)
  p.set_defaults(fn=cmd_uds)

  p = sub.add_parser('selftest', help='full UDS session against the built-in fake ECU (no hardware needed)',
                     formatter_class=argparse.RawDescriptionHelpFormatter)
  p.add_argument('--bus', type=int, default=0)
  p.set_defaults(fn=cmd_selftest)

  p = sub.add_parser('raw', help='send raw CAN frame(s) directly')
  p.add_argument('frame', nargs='+', metavar='ADDR:HEXDATA[:BUS]',
                 help='frame(s) to send, e.g. 0x18db33f1:1003 - multiple allowed')
  p.add_argument('--listen', type=float, nargs='?', const=2.0, default=None, metavar='SECS',
                 help="after sending, drain and print received frames for SECS seconds (default 2)")
  add_transport_args(p)
  p.set_defaults(fn=cmd_raw)

  p = sub.add_parser('pack', help='pack a DBC-defined message with opendbc CANPacker and send it')
  p.add_argument('dbc', help='DBC name (e.g. acura_ilx_2016_nidec) or path to a .dbc file')
  p.add_argument('--msg', required=True, help='message name or hex address from the DBC')
  p.add_argument('--sig', action='append', default=[], metavar='NAME=VALUE',
                 help='signal value - repeatable (counters/checksums are filled in automatically)')
  p.add_argument('--listen', type=float, nargs='?', const=2.0, default=None, metavar='SECS',
                 help="after sending, drain and print received frames for SECS seconds (default 2)")
  add_transport_args(p)
  p.set_defaults(fn=cmd_pack)

  args = parser.parse_args()
  if args.debug:
    carlog.setLevel('DEBUG')
  return args.fn(args)


if __name__ == '__main__':
  sys.exit(main())
