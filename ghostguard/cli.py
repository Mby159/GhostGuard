"""
Command-line interface for GhostGuard
"""

import json
import sys
from typing import Optional

from ghostguard.core import GhostGuard
from ghostguard.types import RedactionStrategy


def main():
    """Main CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="ghostguard",
        description="Privacy middleware for AI applications - detect, redact, and restore sensitive information",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # detect command
    detect_parser = subparsers.add_parser(
        "detect", help="Detect sensitive information in text"
    )
    detect_parser.add_argument(
        "text", nargs="?", help="Text to analyze (or read from stdin)"
    )
    detect_parser.add_argument(
        "--format", choices=["json", "table"], default="table", help="Output format"
    )

    # redact command
    redact_parser = subparsers.add_parser(
        "redact", help="Redact sensitive information from text"
    )
    redact_parser.add_argument(
        "text", nargs="?", help="Text to redact (or read from stdin)"
    )
    redact_parser.add_argument(
        "--strategy",
        choices=["placeholder", "mask", "remove", "hash"],
        default="placeholder",
        help="Redaction strategy",
    )
    redact_parser.add_argument(
        "--format", choices=["json", "text"], default="json", help="Output format"
    )

    # restore command
    restore_parser = subparsers.add_parser("restore", help="Restore redacted text")
    restore_parser.add_argument("text", help="Redacted text")
    restore_parser.add_argument(
        "mapping", help="JSON mapping of placeholders to originals"
    )

    # demo command
    demo_parser = subparsers.add_parser("demo", help="Run a demo of GhostGuard")

    # list-types command
    subparsers.add_parser("list-types", help="List all detectable sensitive types")

    # mcp command
    subparsers.add_parser("mcp", help="Run as MCP server")

    # global command - system-wide privacy service
    global_parser = subparsers.add_parser(
        "global", help="Start system-wide privacy service"
    )
    global_parser.add_argument(
        "--no-auto",
        action="store_true",
        help="Disable automatic clipboard redaction",
    )
    global_parser.add_argument(
        "--no-hotkeys",
        action="store_true",
        help="Disable hotkey listeners",
    )
    global_parser.add_argument(
        "--strategy",
        choices=["placeholder", "mask", "remove", "hash"],
        default="placeholder",
        help="Redaction strategy",
    )

    # proxy command - AI API privacy proxy
    proxy_parser = subparsers.add_parser(
        "proxy", help="Start AI API privacy proxy server"
    )
    proxy_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind (default: 127.0.0.1)",
    )
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=8888,
        help="Port to bind (default: 8888)",
    )
    proxy_parser.add_argument(
        "--strategy",
        choices=["placeholder", "mask", "remove", "hash"],
        default="placeholder",
        help="Redaction strategy",
    )

    # secrets command - code secrets scanning
    secrets_parser = subparsers.add_parser(
        "secrets", help="Scan code for secrets and sensitive information"
    )
    secrets_subparsers = secrets_parser.add_subparsers(
        dest="secrets_command", help="Secrets commands"
    )

    # secrets check
    check_parser = secrets_subparsers.add_parser(
        "check", help="Check files for secrets"
    )
    check_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    check_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    check_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity",
    )

    # secrets check-staged
    staged_parser = secrets_subparsers.add_parser(
        "check-staged", help="Check staged git files"
    )
    staged_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    staged_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Fail on severity level",
    )

    # secrets scan-repo
    repo_parser = secrets_subparsers.add_parser(
        "scan-repo", help="Scan entire repository"
    )
    repo_parser.add_argument("--path", default=".", help="Repository path")
    repo_parser.add_argument(
        "--include-history", action="store_true", help="Scan git history"
    )
    repo_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )

    # secrets install-hook
    secrets_subparsers.add_parser("install-hook", help="Install git pre-commit hook")

    # secrets uninstall-hook
    secrets_subparsers.add_parser("uninstall-hook", help="Remove git pre-commit hook")

    # ocr command - image OCR and sensitive info detection
    ocr_parser = subparsers.add_parser(
        "ocr", help="Scan images for sensitive information using OCR"
    )
    ocr_subparsers = ocr_parser.add_subparsers(dest="ocr_command", help="OCR commands")

    # ocr scan
    scan_parser = ocr_subparsers.add_parser(
        "scan", help="Scan image for sensitive info"
    )
    scan_parser.add_argument("image", help="Image file path")
    scan_parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    scan_parser.add_argument(
        "--engine",
        choices=["auto", "tesseract", "easyocr", "paddleocr"],
        default="auto",
        help="OCR engine",
    )

    # ocr redact
    redact_parser = ocr_subparsers.add_parser(
        "redact", help="Redact sensitive info in image"
    )
    redact_parser.add_argument("input", help="Input image path")
    redact_parser.add_argument("output", help="Output image path")
    redact_parser.add_argument(
        "--method",
        choices=["black", "blur", "pixelate", "text"],
        default="black",
        help="Redaction method",
    )
    redact_parser.add_argument(
        "--engine",
        choices=["auto", "tesseract", "easyocr", "paddleocr"],
        default="auto",
        help="OCR engine",
    )

    # ocr batch
    batch_parser = ocr_subparsers.add_parser("batch", help="Batch process images")
    batch_parser.add_argument("input_dir", help="Input directory")
    batch_parser.add_argument("output_dir", help="Output directory")
    batch_parser.add_argument(
        "--method",
        choices=["redact", "blur", "pixelate", "overlay"],
        default="redact",
        help="Redaction method",
    )
    batch_parser.add_argument(
        "--engine",
        choices=["auto", "tesseract", "easyocr", "paddleocr"],
        default="auto",
        help="OCR engine",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    guard = GhostGuard()

    if args.command == "detect":
        text = args.text or sys.stdin.read().strip()
        if not text:
            print("Error: No text provided", file=sys.stderr)
            sys.exit(1)

        results = guard.detect(text)

        if args.format == "table":
            if not results:
                print("No sensitive information detected.")
            else:
                print(f"{'Type':<20} {'Value':<30} {'Risk Level':<10}")
                print("-" * 62)
                for r in results:
                    value = r.original_value
                    if len(value) > 27:
                        value = value[:24] + "..."
                    print(f"{r.info_type:<20} {value:<30} {r.risk_level.value:<10}")
        else:
            print(
                json.dumps(
                    [
                        {
                            "type": r.info_type,
                            "value": r.original_value,
                            "placeholder": r.placeholder,
                            "risk_level": r.risk_level.value,
                        }
                        for r in results
                    ],
                    ensure_ascii=False,
                    indent=2,
                )
            )

    elif args.command == "redact":
        text = args.text or sys.stdin.read().strip()
        if not text:
            print("Error: No text provided", file=sys.stderr)
            sys.exit(1)

        strategy = RedactionStrategy(args.strategy)
        result = guard.redact(text, strategy)

        if args.format == "text":
            print(result.text)
        else:
            print(
                json.dumps(
                    {
                        "text": result.text,
                        "mapping": result.mapping,
                        "detected_count": len(result.detections),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )

    elif args.command == "restore":
        mapping = json.loads(args.mapping)
        restored = guard.restore(args.text, mapping)
        print(restored)

    elif args.command == "demo":
        run_demo(guard)

    elif args.command == "list-types":
        print("Supported sensitive types:")
        for name in guard.get_detector_names():
            print(f"  - {name}")

    elif args.command == "mcp":
        import asyncio

        asyncio.run(run_mcp_server())

    elif args.command == "global":
        from ghostguard.global_listener import GlobalPrivacyService
        from ghostguard.types import RedactionStrategy

        strategy = RedactionStrategy(args.strategy)
        service = GlobalPrivacyService(guard)

        def on_redact(result):
            print(f"[Redacted] {result.info_type}: {result.original_value}")

        service.on_redact(on_redact)

        service.start(
            auto_redact=not args.no_auto,
            hotkeys=not args.no_hotkeys,
            strategy=strategy,
        )

        service.wait()

    elif args.command == "proxy":
        import asyncio
        from ghostguard.agents import AIProxyServer
        from ghostguard.types import RedactionStrategy

        strategy = RedactionStrategy(args.strategy)
        server = AIProxyServer(guard, strategy)

        print(f"\nStarting AI Privacy Proxy on :{args.port}")
        print(f"Strategy: {args.strategy}")
        print(f"\nUsage:")
        print(f"  openai.api_base = 'http://localhost:{args.port}/v1'")
        print(f"  # or")
        print(f"  export OPENAI_BASE_URL=http://localhost:{args.port}/v1\n")

        asyncio.run(server.start(args.host, args.port))

    elif args.command == "secrets":
        from ghostguard.secrets import (
            SecretsDetector,
            FileScanner,
            RepoScanner,
            GitHooks,
        )
        from ghostguard.secrets.detector import Severity

        if not args.secrets_command:
            secrets_parser.print_help()
            sys.exit(1)

        if args.secrets_command == "check":
            scanner = FileScanner()
            detector = SecretsDetector()

            severity_map = {
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }

            findings = scanner.scan(args.path)
            real_findings = detector.get_real_findings(findings)
            filtered = detector.filter_by_severity(
                real_findings, severity_map[args.severity]
            )

            if args.format == "json":
                print(
                    json.dumps(
                        [
                            {
                                "type": f.secret_type.value,
                                "severity": f.severity.value,
                                "file": f.file_path,
                                "line": f.line_number,
                                "message": f.message,
                                "content": f.line_content[:100],
                            }
                            for f in filtered
                        ],
                        indent=2,
                    )
                )
            else:
                repo_scanner = RepoScanner()
                print(repo_scanner.generate_report(findings))

            if filtered:
                sys.exit(1)

        elif args.secrets_command == "check-staged":
            from ghostguard.secrets.hooks import GitHooks

            hooks = GitHooks()
            severity_map = {
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }

            result = hooks.check_staged_files(severity_map[args.fail_on])

            if args.format == "json":
                print(
                    json.dumps(
                        {
                            "has_findings": result["has_findings"],
                            "count": result["count"],
                        },
                        indent=2,
                    )
                )
            else:
                if result["has_findings"]:
                    print(
                        f"Found {result['count']} potential secret(s) in staged files:"
                    )
                    for f in result["findings"]:
                        print(
                            f"  [{f.severity.value.upper()}] {f.file_path}:{f.line_number} - {f.message}"
                        )
                else:
                    print("No secrets found in staged files.")

            if result["has_findings"]:
                sys.exit(1)

        elif args.secrets_command == "scan-repo":
            scanner = RepoScanner(include_history=args.include_history)
            report = scanner.scan_repo(args.path)

            if args.format == "json":
                print(json.dumps(report, indent=2, default=str))
            else:
                print(f"Repository: {report['repo_path']}")
                print(f"Files scanned: {report['files_scanned']}")
                print(f"\nSummary:")
                print(json.dumps(report["summary"], indent=2))

        elif args.secrets_command == "install-hook":
            hooks = GitHooks()
            result = hooks.install()
            if result["success"]:
                print(f"✓ {result['message']}")
            else:
                print(f"✗ {result.get('error', 'Unknown error')}")
                sys.exit(1)

        elif args.secrets_command == "uninstall-hook":
            hooks = GitHooks()
            result = hooks.uninstall()
            if result["success"]:
                print(f"✓ {result['message']}")
            else:
                print(f"✗ {result.get('error', 'Unknown error')}")
                sys.exit(1)

    elif args.command == "ocr":
        from ghostguard.ocr import ImageDetector, ImageProcessor

        if not args.ocr_command:
            ocr_parser.print_help()
            sys.exit(1)

        detector = ImageDetector(ocr_engine=args.engine)
        processor = ImageProcessor(detector)

        if args.ocr_command == "scan":
            try:
                result = detector.scan(args.image)
                summary = detector.get_summary(result)

                if args.format == "json":
                    print(
                        json.dumps(
                            {
                                "image": result.image_path,
                                "text_regions": len(result.findings),
                                "total_detections": result.total_detections,
                                "summary": summary,
                                "ocr_text": result.ocr_text[:500] + "..."
                                if len(result.ocr_text) > 500
                                else result.ocr_text,
                            },
                            indent=2,
                        )
                    )
                else:
                    print(f"Image: {result.image_path}")
                    print(f"Text regions: {len(result.findings)}")
                    print(f"Sensitive items: {result.total_detections}")

                    if result.sensitive_items:
                        print("\nFindings:")
                        for det in result.sensitive_items:
                            print(
                                f"  [{det.risk_level.value}] {det.info_type}: {det.original_value}"
                            )

                    if result.ocr_text:
                        print(f"\nOCR Text:\n{result.ocr_text[:500]}...")

                if result.has_sensitive_info:
                    sys.exit(1)

            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.ocr_command == "redact":
            try:
                if args.method == "black":
                    result = processor.redact(args.input, args.output)
                elif args.method == "blur":
                    result = processor.blur(args.input, args.output)
                elif args.method == "pixelate":
                    result = processor.pixelate(args.input, args.output)
                elif args.method == "text":
                    result = processor.add_text_overlay(args.input, args.output)

                count = (
                    result.get("redacted")
                    or result.get("blurred")
                    or result.get("pixelated")
                    or result.get("overlaid", 0)
                )
                print(f"Redacted {count} sensitive areas")
                print(f"Output: {result['output']}")

            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

        elif args.ocr_command == "batch":
            import glob

            # Find all images
            extensions = ["*.png", "*.jpg", "*.jpeg", "*.bmp", "*.tiff", "*.webp"]
            images = []
            for ext in extensions:
                images.extend(glob.glob(f"{args.input_dir}/{ext}"))
                images.extend(glob.glob(f"{args.input_dir}/{ext.upper()}"))

            if not images:
                print(f"No images found in {args.input_dir}")
                sys.exit(1)

            print(f"Processing {len(images)} images...")
            results = processor.batch_redact(
                images, args.output_dir, method=args.method
            )

            total_redacted = sum(
                r.get("redacted")
                or r.get("blurred")
                or r.get("pixelated")
                or r.get("overlaid", 0)
                for r in results
            )
            print(f"Done! Redacted {total_redacted} areas across {len(images)} images.")


def run_demo(guard: GhostGuard):
    """Run an interactive demo"""
    print("GhostGuard Privacy Middleware Demo")
    print("=" * 40)

    test_cases = [
        "My phone number is 13812345678",
        "Email me at user@example.com",
        "ID card: 110101199003074562",
        "Bank card: 6228480402564890018",
        "SSN: 123-45-6789",
        "Server IP: 192.168.1.100",
        "Visit https://example.com/api?token=secret",
    ]

    print("\n1. Detection Demo:")
    print("-" * 40)
    for text in test_cases:
        print(f"\nInput: {text}")
        results = guard.detect(text)
        if results:
            for r in results:
                print(f"  Found: {r.info_type} ({r.risk_level.value})")

    print("\n\n2. Redaction & Restore Demo:")
    print("-" * 40)
    text = "Contact 张三 at 13812345678 or zhangsan@company.com"
    print(f"\nOriginal: {text}")

    result = guard.redact(text)
    print(f"Redacted: {result.text}")
    print(f"Mapping: {result.mapping}")

    restored = guard.restore(result.text, result.mapping)
    print(f"Restored: {restored}")

    print("\n\n3. Middleware Demo:")
    print("-" * 40)
    user_input = "用户李四的电话是13912345678，身份证110101199003074562"
    print(f"\nUser input: {user_input}")

    clean_input, mapping = guard.process_input(user_input)
    print(f"Clean input for AI: {clean_input}")

    # Simulate AI response
    ai_response = "好的李四，我已经记录了您的电话13912345678和身份证110101199003074562"
    print(f"AI response: {ai_response}")

    final_response = guard.process_output(ai_response, mapping)
    print(f"Final response to user: {final_response}")


async def run_mcp_server():
    """Run as MCP server"""
    try:
        from mcp.server import Server
        from mcp.types import Tool, TextContent
        from mcp.server.stdio import stdio_server

        server = Server("ghostguard")
        guard = GhostGuard()

        @server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="detect",
                    description="Detect sensitive information in text",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text to analyze",
                            },
                        },
                        "required": ["text"],
                    },
                ),
                Tool(
                    name="redact",
                    description="Redact sensitive information from text",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {"type": "string", "description": "Text to redact"},
                            "strategy": {
                                "type": "string",
                                "enum": ["placeholder", "mask", "remove", "hash"],
                                "default": "placeholder",
                            },
                        },
                        "required": ["text"],
                    },
                ),
                Tool(
                    name="restore",
                    description="Restore redacted text to original",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {"type": "string", "description": "Redacted text"},
                            "mapping": {
                                "type": "object",
                                "description": "Placeholder to original mapping",
                            },
                        },
                        "required": ["text", "mapping"],
                    },
                ),
                Tool(
                    name="list_types",
                    description="List all supported sensitive information types",
                    inputSchema={"type": "object", "properties": {}},
                ),
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict):
            if name == "detect":
                results = guard.detect(arguments["text"])
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            [
                                {
                                    "type": r.info_type,
                                    "value": r.original_value,
                                    "placeholder": r.placeholder,
                                    "risk_level": r.risk_level.value,
                                }
                                for r in results
                            ],
                            ensure_ascii=False,
                            indent=2,
                        ),
                    )
                ]

            elif name == "redact":
                strategy = RedactionStrategy(arguments.get("strategy", "placeholder"))
                result = guard.redact(arguments["text"], strategy)
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "text": result.text,
                                "mapping": result.mapping,
                                "count": len(result.detections),
                            },
                            ensure_ascii=False,
                            indent=2,
                        ),
                    )
                ]

            elif name == "restore":
                restored = guard.restore(arguments["text"], arguments["mapping"])
                return [TextContent(type="text", text=restored)]

            elif name == "list_types":
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(guard.get_detector_names(), indent=2),
                    )
                ]

            raise ValueError(f"Unknown tool: {name}")

        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream, server.create_initialization_options()
            )

    except ImportError:
        print(
            "Error: MCP dependencies not installed. Run: pip install ghostguard[mcp]",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
