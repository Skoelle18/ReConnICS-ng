#!/usr/bin/env python3
"""Publish docs/ to the GitHub wiki (https://github.com/Skoelle18/ReConnICS-ng/wiki).

    python3 scripts/publish-wiki.py            # clone the wiki, replace its pages, commit, push
    python3 scripts/publish-wiki.py --dry-run  # write the pages to a temp folder and print it; no push

Every top-level docs/*.md becomes a page. Links between pages lose ".md" (the wiki addresses pages by name),
images the pages show are copied alongside, and any other link (plans/, examples/, ../NOTICE) points at the file on main.
GitHub creates the wiki repository only after the first page is saved in the web UI: do that once, then run this.
"""
import pathlib, re, shutil, subprocess, sys, tempfile

REPO = "https://github.com/Skoelle18/ReConnICS-ng"
DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"
LINK = re.compile(r"(!?)\[([^\]]*)\]\(([^)\s]+)\)")


def rewrite(text, out):
    pages = {p.name for p in DOCS.glob("*.md")}

    def fix(m):
        bang, label, target = m.groups()
        if re.match(r"[a-z]+:|#", target):
            return m.group(0)
        path, _, anchor = target.partition("#")
        anchor = "#" + anchor if anchor else ""
        if path in pages:
            return f"{bang}[{label}]({path[:-3]}{anchor})"
        src = (DOCS / path).resolve()
        if bang and src.is_file() and DOCS in src.parents:
            (out / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, out / path)
            return m.group(0)
        rel = src.relative_to(DOCS.parent).as_posix()
        return f"{bang}[{label}]({REPO}/blob/main/{rel}{anchor})"

    return LINK.sub(fix, text)


def main():
    dry = "--dry-run" in sys.argv
    out = pathlib.Path(tempfile.mkdtemp(prefix="wiki-"))
    if not dry:
        subprocess.run(["git", "clone", "-q", REPO + ".wiki.git", str(out)], check=True)
        for p in out.iterdir():
            if p.name != ".git":
                shutil.rmtree(p) if p.is_dir() else p.unlink()
    for page in sorted(DOCS.glob("*.md")):
        (out / page.name).write_text(rewrite(page.read_text(encoding="utf-8"), out), encoding="utf-8")
    if dry:
        print(out)
        return
    subprocess.run(["git", "-C", str(out), "add", "-A"], check=True)
    if subprocess.run(["git", "-C", str(out), "diff", "--cached", "--quiet"]).returncode == 0:
        print("wiki already up to date")
        return
    subprocess.run(["git", "-C", str(out), "commit", "-qm", "Publish docs/ from main"], check=True)
    subprocess.run(["git", "-C", str(out), "push", "-q"], check=True)
    print(f"published {REPO}/wiki")


if __name__ == "__main__":
    main()
