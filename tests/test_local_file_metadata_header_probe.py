import os
import shutil
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app import local_file_metadata

NCA_HEADER_SIZE = 0xC00
CONTROL_TAG = b"CTRL"
PROGRAM_TAG = b"PROG"


def _payload(tag, size):
    return tag + bytes(size - len(tag))


class _FakeNcaModule:
    """Stands in for the vendored nca module so no keys or crypto are needed."""

    NCA_HEADER_SIZE = NCA_HEADER_SIZE

    def __init__(self):
        self.header_probe_sizes = []
        self.full_parse_sizes = []

    def NcaHeaderOnly(self, data):
        self.header_probe_sizes.append(len(data))
        content_type = "Control" if data[:4] == CONTROL_TAG else "Program"
        return SimpleNamespace(content_type=content_type)

    def Nca(self, data, master_kek_source=None, titlekey=None):
        self.full_parse_sizes.append(len(data))
        return SimpleNamespace(content_type="Control" if data[:4] == CONTROL_TAG else "Program")


class _ReadTally:
    """Wraps builtins.open to count how many bytes the parser actually pulls off disk."""

    def __init__(self, target):
        self.target = os.path.abspath(target)
        self.bytes_read = 0
        self._real_open = open

    def __call__(self, file, mode="r", *args, **kwargs):
        handle = self._real_open(file, mode, *args, **kwargs)
        if os.path.abspath(str(file)) != self.target:
            return handle
        tally = self

        class _CountingHandle:
            def __init__(self, inner):
                self._inner = inner

            def read(self, *read_args):
                data = self._inner.read(*read_args)
                tally.bytes_read += len(data)
                return data

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def __enter__(self):
                self._inner.__enter__()
                return self

            def __exit__(self, *exc):
                return self._inner.__exit__(*exc)

        return _CountingHandle(handle)


def _build_pfs0(path, files):
    strtab = b""
    offsets = {}
    for name, _ in files:
        offsets[name] = len(strtab)
        strtab += name.encode("utf-8") + b"\x00"

    entries = b""
    data = b""
    for name, payload in files:
        entries += struct.pack("<QQII", len(data), len(payload), offsets[name], 0)
        data += payload

    header = b"PFS0" + struct.pack("<III", len(files), len(strtab), 0)
    with open(path, "wb") as handle:
        handle.write(header + entries + strtab + data)


def _build_hfs0(files):
    strtab = b""
    offsets = {}
    for name, _ in files:
        offsets[name] = len(strtab)
        strtab += name.encode("utf-8") + b"\x00"

    entries = b""
    data = b""
    for name, payload in files:
        entries += struct.pack("<QQII", len(data), len(payload), offsets[name], 0)
        entries += struct.pack("<Q", 0) + bytes(0x20)
        data += payload

    header = struct.pack("<4I", 0x30534648, len(files), len(strtab), 0)
    return header + entries + strtab + data, len(header) + len(entries) + len(strtab)


def _build_xci(path, secure_files):
    secure_blob, _ = _build_hfs0(secure_files)
    root_blob, root_header_size = _build_hfs0([("secure", secure_blob)])

    xci_header = bytearray(0x200)
    struct.pack_into("<3I", xci_header, 0x100, 0x44414548, 0, 0)
    struct.pack_into("<Q", xci_header, 0x130, 0x200)
    struct.pack_into("<Q", xci_header, 0x138, root_header_size)

    with open(path, "wb") as handle:
        handle.write(bytes(xci_header) + root_blob)


class LocalFileMetadataHeaderProbeTests(unittest.TestCase):
    def setUp(self):
        self.test_root = os.path.join(
            os.getcwd(),
            ".tmp",
            "local-metadata-tests",
            "case-header-probe",
        )
        shutil.rmtree(self.test_root, ignore_errors=True)
        os.makedirs(self.test_root, exist_ok=True)
        self.nca_mod = _FakeNcaModule()
        self.modules = self._modules()

    def tearDown(self):
        shutil.rmtree(self.test_root, ignore_errors=True)

    def _modules(self):
        scripts_dir = local_file_metadata.resolve_switch_guides_scripts_dir()
        self.assertIsNotNone(scripts_dir, "vendored switch scripts are required for this test")
        real = local_file_metadata._load_switch_guides_modules(scripts_dir)
        return {
            "pfs0": real["pfs0"],
            "hfs0": real["hfs0"],
            "xci": real["xci"],
            "nca": self.nca_mod,
            "cnmt": SimpleNamespace(
                parse_cnmt=lambda data: SimpleNamespace(title_id=0x0100AAAABBBBCCCC, version=65536)
            ),
            "romfs": SimpleNamespace(),
            "nacp": SimpleNamespace(),
        }

    def _patched_parse(self):
        return patch.multiple(
            local_file_metadata,
            _extract_cnmt_payload_from_meta_nca=lambda nca_obj, pfs0_mod: b"cnmt-payload",
            _extract_nacp_and_icon_from_control_nca=lambda *args, **kwargs: {"name": "Example Title"},
        )

    def test_nsp_control_scan_probes_nca_headers_without_full_reads(self):
        nsp_path = os.path.join(self.test_root, "Example Title.nsp")
        entries = [
            ("Example Title.cnmt.nca", _payload(PROGRAM_TAG, 0x1000)),
            ("decoy.nca", _payload(PROGRAM_TAG, 0x8000)),
            ("control.nca", _payload(CONTROL_TAG, 0x4000)),
            ("program.nca", _payload(PROGRAM_TAG, 0xC000)),
        ]
        _build_pfs0(nsp_path, entries)

        tally = _ReadTally(nsp_path)
        with self._patched_parse(), patch("builtins.open", tally):
            out = local_file_metadata._extract_from_nsp(nsp_path, self.modules)

        self.assertEqual(out.get("title_id"), "0100AAAABBBBCCCC")
        self.assertEqual(out.get("name"), "Example Title")
        # decoy.nca is probed header-only; the largest entry is skipped by the scan entirely
        self.assertEqual(self.nca_mod.header_probe_sizes, [NCA_HEADER_SIZE, NCA_HEADER_SIZE])
        # full parses happen only for the CNMT container and the confirmed control NCA
        self.assertEqual(self.nca_mod.full_parse_sizes, [0x1000, 0x4000])
        # 0x8000 decoy + 0xC000 program never leave the disk in full
        self.assertLess(tally.bytes_read, 0x8000)

    def test_nsp_ncz_entry_is_decompressed_because_it_cannot_be_read_partially(self):
        nsp_path = os.path.join(self.test_root, "Compressed Title.nsp")
        entries = [
            ("Compressed Title.cnmt.nca", _payload(PROGRAM_TAG, 0x1000)),
            ("control.ncz", b"compressed-blob"),
            ("program.nca", _payload(PROGRAM_TAG, 0xC000)),
        ]
        _build_pfs0(nsp_path, entries)

        decompressed = _payload(CONTROL_TAG, 0x4000)
        with self._patched_parse(), patch.object(
            local_file_metadata,
            "_decompress_ncz_bytes",
            return_value=decompressed,
        ) as decompress:
            out = local_file_metadata._extract_from_nsp(nsp_path, self.modules)

        self.assertEqual(out.get("name"), "Example Title")
        self.assertEqual(decompress.call_count, 2)
        self.assertEqual(self.nca_mod.header_probe_sizes, [NCA_HEADER_SIZE])
        self.assertEqual(self.nca_mod.full_parse_sizes, [0x1000, 0x4000])

    def test_xci_control_scan_probes_nca_headers_without_full_reads(self):
        xci_path = os.path.join(self.test_root, "Example Title.xci")
        entries = [
            ("Example Title.cnmt.nca", _payload(PROGRAM_TAG, 0x1000)),
            ("decoy.nca", _payload(PROGRAM_TAG, 0x8000)),
            ("control.nca", _payload(CONTROL_TAG, 0x4000)),
            ("program.nca", _payload(PROGRAM_TAG, 0xC000)),
        ]
        _build_xci(xci_path, entries)

        tally = _ReadTally(xci_path)
        with self._patched_parse(), patch("builtins.open", tally):
            out = local_file_metadata._extract_from_xci(xci_path, self.modules)

        self.assertEqual(out.get("title_id"), "0100AAAABBBBCCCC")
        self.assertEqual(self.nca_mod.header_probe_sizes, [NCA_HEADER_SIZE, NCA_HEADER_SIZE])
        self.assertEqual(self.nca_mod.full_parse_sizes, [0x1000, 0x4000])
        self.assertLess(tally.bytes_read, 0x8000)

    def test_xci_largest_entry_fallback_probes_header_only(self):
        xci_path = os.path.join(self.test_root, "Fallback Title.xci")
        entries = [
            ("Fallback Title.cnmt.nca", _payload(PROGRAM_TAG, 0x1000)),
            ("decoy.nca", _payload(PROGRAM_TAG, 0x8000)),
            ("control.nca", _payload(CONTROL_TAG, 0xC000)),
        ]
        _build_xci(xci_path, entries)

        with self._patched_parse():
            out = local_file_metadata._extract_from_xci(xci_path, self.modules)

        self.assertEqual(out.get("name"), "Example Title")
        # decoy probe, then the largest-entry fallback probe, both header-sized
        self.assertEqual(self.nca_mod.header_probe_sizes, [NCA_HEADER_SIZE, NCA_HEADER_SIZE])
        self.assertEqual(self.nca_mod.full_parse_sizes, [0x1000, 0xC000])


if __name__ == "__main__":
    unittest.main()
