from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "compat_generate", ROOT / "tools/compat/generate.py"
)
generate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(generate)


class GeneratorTests(unittest.TestCase):
    def test_provenance_matches_repository_go_find_pin(self) -> None:
        provenance = json.loads(
            (ROOT / "compat/upstream/provenance.json").read_text(encoding="utf-8")
        )
        go_find = (ROOT / "tools/go-find.sh").read_text(encoding="utf-8")
        self.assertIn(
            f"{provenance['module']}@{provenance['version']}",
            go_find,
        )
        go_sum = (ROOT / "tools/speedtest-interop/go.sum").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"{provenance['module']} {provenance['version']} {provenance['sum']}",
            go_sum,
        )
        self.assertIn(
            f"{provenance['module']} {provenance['version']}/go.mod {provenance['go_mod_sum']}",
            go_sum,
        )

    def test_identifier_guards_detect_shrinkage(self) -> None:
        old = {
            "denominator": generate.id_guard(["a", "b"]),
            "guards": {"local": generate.id_guard(["x", "y"])},
        }
        new = {
            "denominator": generate.id_guard(["a"]),
            "guards": {"local": generate.id_guard(["x"])},
        }
        self.assertEqual(
            generate.removed_guard_ids(old, new),
            {"denominator": ["b"], "local": ["y"]},
        )

    def test_writer_refuses_guarded_removals_without_explicit_review(self) -> None:
        def document(ids: list[str], signature: str = "v1") -> dict:
            value = generate.base_document("fixture")
            shapes = [
                {"id": identifier, "signature": signature} for identifier in ids
            ]
            value.update(
                {
                    "denominator": {"source": "fixture", **generate.id_guard(ids)},
                    "guards": {
                        "local": generate.id_guard(ids),
                        "local_shape": generate.shape_guard(shapes),
                    },
                    "inventory": {"local": shapes},
                    "comparisons": [
                        {
                            "id": "compare:" + identifier,
                            "denominator_id": identifier,
                            "classification": "exact",
                            "upstream_ids": [],
                            "local_ids": [identifier],
                            "note": "fixture",
                        }
                        for identifier in ids
                    ],
                }
            )
            return value

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(generate.canonical_json(document(["a", "b"])), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing denominator/API shrink"):
                generate.emit_json(
                    path,
                    document(["a"]),
                    check=False,
                    allow_removals=False,
                )

            shape_path = Path(directory) / "shape.json"
            shape_path.write_text(
                generate.canonical_json(document(["a"], "v1")), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "local_shape"):
                generate.emit_json(
                    shape_path,
                    document(["a"], "v2"),
                    check=False,
                    allow_removals=False,
                )

    def test_cli_flattener_preserves_alias_groups(self) -> None:
        commands, flags = generate.flatten_local_cli(
            {
                "name": "rustscale",
                "flags": [],
                "commands": [
                    {
                        "name": "ping",
                        "aliases": [],
                        "flags": [
                            {
                                "name": "--count",
                                "aliases": ["--c", "-c"],
                                "value": {"kind": "value"},
                            }
                        ],
                        "subcommands": [],
                    }
                ],
            }
        )
        self.assertEqual([item["id"] for item in commands], ["command:ping"])
        self.assertEqual(flags[0]["aliases"], ["--c", "-c"])

    def test_c_header_is_checked_against_no_mangle_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "api.h"
            source = root / "lib.rs"
            header.write_text(
                "#define RS_OK 0\nint ts_new(void);\nint ts_close(int handle);\n",
                encoding="utf-8",
            )
            source.write_text(
                '#[no_mangle]\npub extern "C" fn ts_new() -> i32 { 1 }\n'
                '#[no_mangle]\npub extern "C" fn ts_close(_: i32) -> i32 { 0 }\n',
                encoding="utf-8",
            )
            items, consistency = generate.extract_c_abi(header, source)
            self.assertTrue(consistency["match"])
            self.assertEqual(
                [item["id"] for item in items],
                ["constant:RS_OK", "function:ts_close", "function:ts_new"],
            )

    def test_python_extractor_requires_explicit_exports_and_tracks_c_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binding.py"
            path.write_text(
                '__all__ = ["Client", "VALUE"]\n'
                "VALUE = 7\n"
                "class Client:\n"
                "    def dial(self, addr: str = 'peer:80') -> int:\n"
                "        return _lib.ts_dial(1, b'tcp', addr.encode())\n",
                encoding="utf-8",
            )
            items, symbols = generate.extract_python_api(path)
            self.assertEqual(symbols, ["ts_dial"])
            self.assertIn("class:Client", {item["id"] for item in items})
            method = next(item for item in items if item["id"] == "method:Client.dial")
            self.assertEqual(method["signature"]["returns"], "int")

    def test_localapi_macro_is_the_route_and_schema_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "localapi.rs"
            path.write_text(
                'localapi_contract!("GET", "status", "none", "ipnstate.Status"),\n'
                'localapi_contract!("PUT", "files/<name>", "bytes", "none"),\n',
                encoding="utf-8",
            )
            routes = generate.extract_localapi_contract(path)
            self.assertEqual(
                [route["id"] for route in routes],
                [
                    "route:GET:/localapi/v0/status",
                    "route:PUT:/localapi/v0/files/<name>",
                ],
            )
            self.assertEqual(routes[0]["response_schema"], "ipnstate.Status")

    def test_rustdoc_artifact_parser_extracts_public_inherent_methods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "all.html").write_text(
                '<ul><li><a href="struct.Server.html">Server</a></li></ul>',
                encoding="utf-8",
            )
            (root / "index.html").write_text(
                '<a class="mod" href="localapi/index.html">localapi</a>'
                '<dt id="reexport.dep"><code>pub use dep;</code></dt>',
                encoding="utf-8",
            )
            (root / "struct.Server.html").write_text(
                '<pre class="rust item-decl"><code>pub struct Server { /* private fields */ }</code></pre>'
                '<section id="method.up" class="method"><h4 class="code-header">'
                'pub async fn <a>up</a>(&amp;mut self)</h4></section>'
                '<section id="method.clone" class="method"><h4 class="code-header">'
                'fn <a>clone</a>(&amp;self)</h4></section>',
                encoding="utf-8",
            )
            ids = {item["id"] for item in generate.rustdoc_items(root)}
            self.assertEqual(
                ids,
                {
                    "method:Server.up",
                    "module:localapi",
                    "reexport:dep",
                    "struct:Server",
                },
            )

    def test_checked_manifests_cover_every_denominator(self) -> None:
        manifest_dir = ROOT / "compat/manifests"
        if not manifest_dir.exists():
            self.skipTest("manifests have not been generated yet")
        classifications = set()
        for path in sorted(manifest_dir.glob("*.json")):
            with self.subTest(path=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                generate.validate_document(document)
                classifications.update(
                    comparison["classification"]
                    for comparison in document["comparisons"]
                )
        self.assertEqual(classifications, generate.CLASSIFICATIONS)


if __name__ == "__main__":
    unittest.main()
