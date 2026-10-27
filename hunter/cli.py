"""Command line: serve, scan --once, score, train, and model settings."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from hunter.archives import extract_archive
from hunter.config import Config
from hunter.db import Database
from hunter.evaluate import evaluate_fixtures, format_report
from hunter.inventory.parsers import FORMATS
from hunter.investigate import warn_smart_config
from hunter.jev import JevClient
from hunter.logging_setup import configure_logging
from hunter.models import ReleaseMeta
from hunter.registry import PypiSerialFeed, http_get
from hunter.scout_mine import mine_report_from_path, teach_scout
from hunter.scout_model import make_scout_model, require_scoring_layer
from hunter.llm import ModelCallError
from hunter.openrouter import list_openrouter_models
from hunter.spend import SpendMeter
from hunter.teach import TeachRefused, discover_fixture, run_teach, write_axios_distillation, write_teach_report
from hunter.rubygems.review import score_versions
from hunter.service import FeedStart, ReleaseLoader, apply_feed_start, classify_observed, run_cycle, serve
from hunter.train import train_live


def _print_result(result) -> None:
    payload = {
        "ecosystem": result.ecosystem,
        "package": result.name,
        "old_version": result.old_version,
        "new_version": result.new_version,
        "band": result.band,
        "malice_probability": result.malice_probability,
        "attack_family": result.attack_family,
        "subtype": result.subtype,
        "suspected_cause": result.cause,
        "blast_radius_score": result.blast_radius_score,
        "pass_d_agreed": result.pass_d_agreed,
        "signals": result.signals,
        "child_findings": result.child_findings,
        "jev_model_id": result.jev_model_id,
    }
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _non_negative_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return value


def _non_negative_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return value


def _npm_seq(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        raise argparse.ArgumentTypeError("must not be empty")
    if stripped[0] == "-":
        raise argparse.ArgumentTypeError("must be zero or greater")
    return stripped


def _add_feed_start(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--pypi-serial",
        type=_non_negative_int,
        default=None,
        help="set the PyPI checkpoint to this serial before polling; the next poll reads events after it",
    )
    parser.add_argument(
        "--npm-seq",
        type=_npm_seq,
        default=None,
        help="set the npm changes checkpoint to this sequence before polling; the next poll reads events after it",
    )
    parser.add_argument(
        "--since-hours",
        type=_non_negative_float,
        default=None,
        help="replay from this many hours ago; a checkpoint already older than that is left in place",
    )


def _feed_start(args) -> FeedStart:
    return FeedStart(
        pypi_serial=args.pypi_serial,
        npm_seq=args.npm_seq,
        since_hours=args.since_hours,
    )


def _cmd_serve(args, config: Config) -> int:
    serve(config, start=_feed_start(args))
    return 0


def _cmd_scan(args, config: Config) -> int:
    if not args.once:
        print("scan requires --once", file=sys.stderr)
        return 2
    require_scoring_layer(config)
    warn_smart_config(config)
    db = Database(config.db_path)
    feed = PypiSerialFeed(config.pypi_base)
    try:
        apply_feed_start(db, config, feed, http_get, _feed_start(args))
        run_cycle(
            db,
            config,
            jev=make_scout_model(
                config,
                meter=SpendMeter(db, cap_usd=config.scout_daily_usd_cap, prices=config.scout_prices),
            ),
            loader=ReleaseLoader(config),
            feed=feed,
        )
    finally:
        db.close()
    return 0


def _cmd_score(args, config: Config) -> int:
    if args.ecosystem == "rubygems" and not (args.old_archive or args.new_archive):
        if not (args.name and args.old and args.new):
            print("score needs --ecosystem, --name, --old, and --new, or two archives", file=sys.stderr)
            return 2
        scout = None
        if config.rubygems_scout:
            require_scoring_layer(config)
            scout = make_scout_model(config)
        _print_result(score_versions(config, args.name, args.old, args.new, jev=scout))
        return 0
    require_scoring_layer(config)
    jev = make_scout_model(config)
    if args.old_archive or args.new_archive:
        if not (args.old_archive and args.new_archive):
            print("score with archives needs both --old-archive and --new-archive", file=sys.stderr)
            return 2
        old_files = extract_archive(Path(args.old_archive))
        new_files = extract_archive(Path(args.new_archive))
        meta = ReleaseMeta(
            ecosystem=args.ecosystem or "npm",
            name=args.name or Path(args.new_archive).stem,
            new_version=args.new or "new",
            old_version=args.old or "old",
        )
    else:
        if not (args.ecosystem and args.name and args.old and args.new):
            print("score needs --ecosystem, --name, --old, and --new, or two archives", file=sys.stderr)
            return 2
        loader = ReleaseLoader(config)
        old_files, new_files, meta = loader.load_versions(args.ecosystem, args.name, args.old, args.new)
    result, _excerpt = classify_observed(
        meta, old_files, new_files, jev=jev, config=config, transport=http_get
    )
    _print_result(result)
    return 0


def _cmd_report(args, config: Config) -> int:
    db = Database(config.db_path)
    try:
        rows = db.human_review_queue(limit=args.limit)
    finally:
        db.close()
    json.dump(rows, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def default_fixtures_dir() -> Path:
    """The labeled fixtures shipped at the repo root, found from the package, not the cwd."""
    return Path(__file__).resolve().parent.parent / "fixtures"


def _cmd_eval(args, _config: Config) -> int:
    from hunter.fake_jev import KeywordJev

    fixtures = Path(args.fixtures) if args.fixtures else default_fixtures_dir()
    if not fixtures.is_dir():
        print(f"fixtures directory not found: {fixtures}. Pass --fixtures DIR.", file=sys.stderr)
        return 2
    report = evaluate_fixtures(str(fixtures), jev=KeywordJev())
    text = format_report(report)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    confusion = report["confusion"]
    if report["labeled_binary"] == 0:
        return 0
    if confusion["fp"] or confusion["fn"]:
        return 1
    return 0


def _cmd_mine_scout(_args, config: Config) -> int:
    report = mine_report_from_path(Path(config.db_path))
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _cmd_teach_scout(_args, config: Config) -> int:
    db = Database(config.db_path)
    try:
        result = teach_scout(db, config)
    finally:
        db.close()
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    if result.get("refused"):
        print(result["refused"], file=sys.stderr)
        return 2
    return 0


def _cmd_teach_until_catch(args, _config: Config) -> int:
    """Offline loop. Ignores any webhook in the environment and does not post."""
    os.environ.pop("ALERT_WEBHOOK_URL", None)
    os.environ.pop("ALERT_WEBHOOK_SECRET", None)
    fixture = discover_fixture(args.fixture)
    out = Path(args.out)
    if fixture is None or not fixture.exists():
        if not args.allow_distill:
            print(
                "fixture not found. Pass --fixture, set HUNTER_TEACH_FIXTURE, "
                "or add a fixture: line to teach-fixture.md. "
                "--allow-distill writes an inert synthetic tree outside the lesson files.",
                file=sys.stderr,
            )
            return 2
        dest = Path(args.distill_dir) if args.distill_dir else out / "trees"
        fixture = write_axios_distillation(dest)
        print(f"wrote synthetic distillation at {fixture}", file=sys.stderr)
    try:
        result = run_teach(
            fixture,
            max_rounds=args.max_rounds,
            out_dir=out,
            sandbox=Path(args.sandbox) if args.sandbox else out / "sandbox",
            mode=args.mode,
            strip_sections=["Compromised library"] if args.ablate else None,
        )
    except TeachRefused as exc:
        print(str(exc), file=sys.stderr)
        return 2
    write_teach_report(out, result)
    json.dump(
        {
            "success": result["success"],
            "mode": result["mode"],
            "would_alert": result["would_alert"],
            "alert_sent": result["alert_sent"],
            "rounds": len(result["rounds"]),
            "lessons_proposed": [item.get("pattern") for item in result["lessons_proposed"]],
        },
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    if args.with_ablation and not args.ablate:
        ablation_out = out / "ablation"
        try:
            ablation = run_teach(
                fixture,
                max_rounds=args.max_rounds,
                out_dir=ablation_out,
                sandbox=ablation_out / "sandbox",
                mode=args.mode,
                strip_sections=["Compromised library"],
            )
        except TeachRefused as exc:
            print(str(exc), file=sys.stderr)
            return 2
        write_teach_report(ablation_out, ablation)
        extra = out / "REPORT.md"
        extra.write_text(
            extra.read_text(encoding="utf-8")
            + "\n## Ablation without the compromised-library section\n\n"
            + f"- Success: {ablation['success']}\n"
            + f"- Rounds: {len(ablation['rounds'])}\n"
            + "- Lessons: "
            + ", ".join(item.get("pattern") or "" for item in ablation["lessons_proposed"])
            + "\n",
            encoding="utf-8",
        )
    return 0 if result["success"] else 1


def _cmd_train(args, config: Config) -> int:
    client = JevClient(model=config.jev_model, retries=config.jev_retries, base_url=config.jev_base_url)
    if not client.api_key:
        print("TYPESAFE_API_KEY is not set; shipped prior weights were left in place.", file=sys.stderr)
        return 0
    db = Database(config.db_path)
    try:
        payload = train_live(args.fixtures, db, client)
    finally:
        db.close()
    holdout = payload.get("holdout") or {}
    print(
        f"fitted {payload['model_id']} precision={holdout.get('precision')} recall={holdout.get('recall')}"
    )
    return 0


def _cmd_models(args, config: Config) -> int:
    """Show the three roles, or list every OpenRouter model id."""
    from hunter.config import active_role_models

    if args.list:
        try:
            models = list_openrouter_models()
        except (ModelCallError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        for item in models:
            name = item["name"]
            print(f"{item['id']}\t{name}" if name else item["id"])
        return 0
    payload = active_role_models(config)
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _cmd_mcp(args, config: Config) -> int:
    """MCP registry by hand: poll once and catch up new names, or print the checkpoint."""
    from hunter.service import mcp_registry_health, poll_mcp_and_catchup

    db = Database(config.db_path)
    try:
        if args.mcp_command == "poll":
            stats = poll_mcp_and_catchup(db, config, http_get)
            print(
                f"pages {stats['pages']} added {stats['added']} "
                f"npm {stats['npm']} pypi {stats['pypi']} checkpoint {stats['checkpoint']}"
            )
        payload = mcp_registry_health(db)
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    except Exception as exc:
        db.mark_poll_error("mcp", str(exc))
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


def _cmd_actions(args, config: Config) -> int:
    """GitHub Actions watcher by hand: rebuild the watchlist, poll tags once, or show counts."""
    from hunter.actions import ECOSYSTEM
    from hunter.actions.github import GitHubClient
    from hunter.actions.poller import poll_actions
    from hunter.actions.watchlist import refresh_actions_watchlist

    db = Database(config.db_path)
    client = GitHubClient(config.github_token)
    try:
        if args.actions_command == "refresh":
            count = refresh_actions_watchlist(db, config, http_get, client)
            print(f"watching {count} actions")
        elif args.actions_command == "poll":
            queued = poll_actions(db, config, client)
            db.mark_poll_success(ECOSYSTEM)
            print(f"queued {queued} tag events")
        payload = {**db.action_counts(), "token": client.has_token}
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    finally:
        db.close()
    return 0


def watchlist_warnings(db: Database, config: Config) -> list[str]:
    """Plain-language problems with the user watchlist setup, for ``watchlist status``."""
    from hunter.inventory.scope import is_stale

    counts = db.user_watch_counts()
    found: list[str] = []
    if config.watch_mode == "watched" and not counts["total"]:
        found.append("HUNTER_WATCH_MODE=watched but the watchlist is empty: the polls run and queue nothing.")
    if config.watch_mode == "all" and counts["total"]:
        found.append(
            "HUNTER_WATCH_MODE=all: Hunter watches the popular lists as well as your "
            f"{counts['total']} names, and alert scope is {config.alert_scope}. "
            "Set HUNTER_WATCH_MODE=watched to poll and alert only on your names."
        )
    if counts["github-actions"] and not config.actions:
        found.append(f"{counts['github-actions']} GitHub Actions are listed but HUNTER_ACTIONS is off; their tags are not polled.")
    if counts["openvsx"] and not config.openvsx:
        found.append(f"{counts['openvsx']} Open VSX extensions are listed but HUNTER_OPENVSX is off; they are not polled.")
    for row in db.user_watch_sources():
        if is_stale(row["imported_at"]):
            found.append(f"source {row['source']} was imported more than 7 days ago ({row['imported_at']}); import it again.")
    return found


def _print_import_report(report) -> None:
    for item in report.files:
        if item.error:
            print(f"{item.source}\t-\tnot imported: {item.error}")
            continue
        print(f"{item.source}\t{item.format}\t{item.components} components\t{item.skipped} skipped")
        for warning in item.warnings:
            print(f"  warning: {warning}")
    for warning in report.warnings:
        print(f"warning: {warning}")
    stored = "nothing stored (dry run)" if report.dry_run else f"{len(report.new_names)} names new to the poll set"
    partial = "; partial" if report.partial else ""
    print(f"{report.components} components from {len([f for f in report.files if not f.error])} files; {stored}{partial}")


def _cmd_watchlist(args, config: Config) -> int:
    """User watchlist: import lockfiles, SBOMs, manifests and workflows, or edit the list by hand."""
    from hunter.inventory import ECOSYSTEMS, component, ecosystem_alias, normalize
    from hunter.inventory.load import import_paths, prime_new_names
    from hunter.inventory.parsers import FORMAT_HELP
    from hunter.inventory.scope import is_stale

    command = args.watchlist_command
    if command == "formats":
        for fmt, text in FORMAT_HELP.items():
            print(f"{fmt}\t{text}")
        return 0
    if command == "import" and "-" in args.paths and not args.format:
        print("reading stdin (-) needs --format; see 'hunter watchlist formats'", file=sys.stderr)
        return 2
    eco = None
    if getattr(args, "ecosystem", None):
        eco = ecosystem_alias(args.ecosystem)
        if eco is None:
            print(f"unknown ecosystem {args.ecosystem!r}; use one of {', '.join(ECOSYSTEMS)}", file=sys.stderr)
            return 2
    db = Database(config.db_path)
    try:
        if command == "import":
            report = import_paths(
                db,
                args.paths,
                source=args.source,
                fmt=args.format,
                dry_run=args.dry_run,
                max_bytes=config.watchlist_max_file_bytes,
                max_files=config.watchlist_max_files,
            )
            if args.json:
                json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            else:
                _print_import_report(report)
            return 0 if any(not item.error for item in report.files) else 1
        if command == "add":
            found = component(eco, args.name, args.version or "", 1)
            if found is None:
                print(f"{args.name!r} is not a valid {eco} name", file=sys.stderr)
                return 2
            if db.add_user_watch(found.ecosystem, found.name, found.version, source="manual"):
                prime_new_names(db, [(found.ecosystem, found.name)])
            print(f"added {found.ecosystem} {found.name} {found.version or '(any version)'} to source manual")
            return 0
        if command == "remove":
            if args.source and not args.target:
                removed = db.remove_user_watch_source(args.source)
            elif len(args.target) == 2 and not args.source:
                target_eco = ecosystem_alias(args.target[0])
                name = normalize(target_eco, args.target[1]) if target_eco else None
                if name is None:
                    print("remove needs a known ecosystem and a valid name", file=sys.stderr)
                    return 2
                removed = db.remove_user_watch_name(target_eco, name)
            else:
                print("remove needs --source LABEL, or ECOSYSTEM NAME", file=sys.stderr)
                return 2
            print(f"removed {removed} rows")
            return 0
        if command == "list":
            rows = db.user_watch_rows(eco)
            if args.json:
                json.dump(rows, sys.stdout, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            else:
                for row in rows:
                    direct = {1: "direct", 0: "indirect"}.get(row["direct"], "-")
                    print(f"{row['ecosystem']}\t{row['name']}\t{row['version'] or '-'}\t{direct}\t{row['source']}")
            return 0
        counts = db.user_watch_counts()
        print(f"mode {config.watch_mode}, alert scope {config.alert_scope}")
        print(" ".join(f"{key} {counts[key]}" for key in (*ECOSYSTEMS, "total")))
        for row in db.user_watch_sources():
            stale = " (stale)" if is_stale(row["imported_at"]) else ""
            print(f"{row['source']}\t{row['format']}\t{row['components']} components\t{row['imported_at']}{stale}")
        for warning in watchlist_warnings(db, config):
            print(f"warning: {warning}")
    finally:
        db.close()
    return 0


def _cmd_ground_truth(args, config: Config) -> int:
    """Compare scored releases with OSV MAL- records and npm takedowns. Reads JSON only."""
    from hunter.ground_truth import make_source, run_ground_truth

    try:
        source = make_source(config, args.source)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    db = Database(config.db_path)
    try:
        report = run_ground_truth(
            db,
            config,
            source=source,
            days=args.days,
            fetch=not args.offline,
            out=Path(args.out) if args.out else None,
        )
    finally:
        db.close()
    hidden = {"items", "openvsx_items"}
    payload = report if args.full else {key: value for key, value in report.items() if key not in hidden}
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunter",
        description=(
            "Watch package releases. The decision model (Scout) scores each release. "
            "The mid-tier, balanced model (Triage) reviews the ones that need it. "
            "The Frontier model (Analyst) confirms before an alert."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve_parser = sub.add_parser(
        "serve",
        help="poll both ecosystems until SIGTERM; decision model, mid-tier model, then Frontier model",
    )
    _add_feed_start(serve_parser)
    serve_parser.set_defaults(func=_cmd_serve)

    scan = sub.add_parser("scan", help="poll once, classify, and drain the outbox")
    scan.add_argument("--once", action="store_true")
    _add_feed_start(scan)
    scan.set_defaults(func=_cmd_scan)

    score = sub.add_parser("score", help="classify two versions or two local archives")
    score.add_argument("--ecosystem", choices=("pypi", "npm", "rubygems", "crates"))
    score.add_argument("--name")
    score.add_argument("--old")
    score.add_argument("--new")
    score.add_argument("--old-archive")
    score.add_argument("--new-archive")
    score.set_defaults(func=_cmd_score)

    train = sub.add_parser("train", help="run Pass B on fixtures and refit the logistic head")
    train.add_argument("--fixtures", default="fixtures")
    train.set_defaults(func=_cmd_train)

    mine = sub.add_parser(
        "mine-scout",
        help="print counts the mid-tier, balanced model (Triage) called benign; does not write lessons",
    )
    mine.set_defaults(func=_cmd_mine_scout)

    teach = sub.add_parser(
        "teach-scout",
        help="ask the Frontier model (Analyst) for decision-model (Scout) suppression lessons; not started by serve",
    )
    teach.set_defaults(func=_cmd_teach_scout)

    catch = sub.add_parser(
        "teach-until-catch",
        help=(
            "offline teach loop until the decision model (Scout), the mid-tier, balanced model (Triage), "
            "and the Frontier model (Analyst) would alert; does not post"
        ),
    )
    catch.add_argument("--fixture", default="", help="JSON fixture or a directory with old/ and new/ trees")
    catch.add_argument("--max-rounds", type=int, default=5)
    catch.add_argument("--out", default="teach-out")
    catch.add_argument("--sandbox", default="", help="lesson sandbox; default is OUT/sandbox")
    catch.add_argument("--mode", choices=("auto", "mock", "live"), default="auto")
    catch.add_argument(
        "--allow-distill",
        action="store_true",
        help="if the fixture is missing, write an inert synthetic tree and run that",
    )
    catch.add_argument("--distill-dir", default="", help="where --allow-distill writes trees")
    catch.add_argument(
        "--ablate",
        action="store_true",
        help="drop the compromised-library SOP section in the sandbox before teaching",
    )
    catch.add_argument(
        "--with-ablation",
        action="store_true",
        help="after the main run, repeat once with that section removed",
    )
    catch.set_defaults(func=_cmd_teach_until_catch)

    report = sub.add_parser("report", help="print the human review queue")
    report_sub = report.add_subparsers(dest="report_command", required=True)
    exhausted = report_sub.add_parser("exhausted", help="releases whose AI retries are exhausted")
    exhausted.add_argument("--limit", type=int, default=100)
    exhausted.set_defaults(func=_cmd_report)

    evaluate = sub.add_parser("eval", help="score labeled fixtures and print precision and recall")
    evaluate.add_argument(
        "--fixtures",
        default=None,
        help="labeled fixtures directory (default: the repo's fixtures/, found from the package)",
    )
    evaluate.add_argument("--output")
    evaluate.set_defaults(func=_cmd_eval)

    mcp = sub.add_parser("mcp", help="MCP registry watchlist: poll the registry once, or show the checkpoint")
    mcp_sub = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_sub.add_parser("poll", help="read the registry once and catch up new npm and PyPI names").set_defaults(
        func=_cmd_mcp
    )
    mcp_sub.add_parser("status", help="print package counts, the checkpoint, last success, and last error").set_defaults(
        func=_cmd_mcp
    )

    actions = sub.add_parser("actions", help="GitHub Actions watcher: refresh the watchlist, poll tags once, or show counts")
    actions_sub = actions.add_subparsers(dest="actions_command", required=True)
    actions_sub.add_parser("refresh", help="rebuild the GitHub Actions watchlist now").set_defaults(func=_cmd_actions)
    actions_sub.add_parser("poll", help="read every watched action's tags once and queue tag events").set_defaults(
        func=_cmd_actions
    )
    actions_sub.add_parser("status", help="print watched actions, recorded tags, and tag events today").set_defaults(
        func=_cmd_actions
    )

    watchlist = sub.add_parser(
        "watchlist",
        help="your watchlist: import lockfiles, SBOMs, manifests and workflows; add, remove, list, status",
    )
    watchlist_sub = watchlist.add_subparsers(dest="watchlist_command", required=True)
    wl_import = watchlist_sub.add_parser(
        "import", help="read files or directories (walked) and store the packages they list; nothing is run"
    )
    wl_import.add_argument("paths", nargs="+", metavar="PATH", help="file, directory, or - for stdin (needs --format)")
    wl_import.add_argument("--source", default=None, help="label prefix; each file is stored as LABEL/<relative path>")
    wl_import.add_argument("--format", choices=FORMATS, default=None, help="skip detection and read every file as this format")
    wl_import.add_argument("--dry-run", action="store_true", help="report what would be stored; write nothing")
    wl_import.add_argument("--json", action="store_true")
    wl_import.set_defaults(func=_cmd_watchlist)
    wl_add = watchlist_sub.add_parser("add", help="add one package by hand (source 'manual')")
    wl_add.add_argument("ecosystem", help="npm, pypi, github-actions or openvsx")
    wl_add.add_argument("name")
    wl_add.add_argument("version", nargs="?", default="")
    wl_add.set_defaults(func=_cmd_watchlist)
    wl_remove = watchlist_sub.add_parser("remove", help="remove a whole source, or one package from every source")
    wl_remove.add_argument("--source", default=None)
    wl_remove.add_argument("target", nargs="*", metavar="ECOSYSTEM NAME")
    wl_remove.set_defaults(func=_cmd_watchlist)
    wl_list = watchlist_sub.add_parser("list", help="print every listed package")
    wl_list.add_argument("--ecosystem", default=None)
    wl_list.add_argument("--json", action="store_true")
    wl_list.set_defaults(func=_cmd_watchlist)
    watchlist_sub.add_parser("status", help="print the mode, alert scope, counts, sources and warnings").set_defaults(
        func=_cmd_watchlist
    )
    watchlist_sub.add_parser("formats", help="print the formats import understands").set_defaults(func=_cmd_watchlist)

    truth = sub.add_parser(
        "ground-truth",
        help="compare scored npm and PyPI releases with OSV MAL- records and npm takedowns; print recall and time-to-detect",
    )
    truth.add_argument("--source", choices=("api", "git"), default=None, help="OSV source (default: HUNTER_GROUND_TRUTH_SOURCE or api)")
    truth.add_argument("--days", type=_non_negative_int, default=None, help="look back this many days; 0 means all releases")
    truth.add_argument("--out", default="", help="report path (default: ground-truth-report.json in the data dir)")
    truth.add_argument("--offline", action="store_true", help="use cached OSV records and takedowns; no network")
    truth.add_argument("--full", action="store_true", help="print every labeled release, not only the summary")
    truth.set_defaults(func=_cmd_ground_truth)

    models = sub.add_parser(
        "models",
        help=(
            "show the decision model (Scout), the mid-tier, balanced model (Triage), "
            "and the Frontier model (Analyst)"
        ),
    )
    models.add_argument(
        "--list",
        action="store_true",
        help="list every model id from the OpenRouter API so any of them can be selected",
    )
    models.set_defaults(func=_cmd_models)
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args, Config.from_env())
