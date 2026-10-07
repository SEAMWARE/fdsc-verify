"""Every `doc=` anchor a check prints must resolve to a heading in docs/troubleshooting.md.

A `see:` line that lands nowhere is worse than no line at all: the operator follows it,
finds nothing, and stops trusting the rest of the output. This is a static scan of the
check sources rather than a run of the checks, because the anchors are literals and the
checks need a cluster.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "troubleshooting.md")
CHECKS = os.path.join(ROOT, "fdsc_verify", "checks")

# GitHub/GitLab heading slugs: lowercase, drop punctuation (keeping `-` and `_`),
# spaces to dashes. `` ` `` and `*` go first so `x509_san_dns` survives intact.
def slugify(heading):
    text = re.sub(r"[`*]", "", heading).strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text).strip("-")


def doc_anchors():
    anchors = set()
    with open(DOC, encoding="utf-8") as handle:
        for line in handle:
            match = re.match(r"^#{2,4}\s+(.*)", line)
            if match:
                anchors.add(slugify(match.group(1)))
    return anchors


def referenced_anchors():
    """(anchor, source file) for every literal passed as doc= or held in a DOC_* constant."""
    found = set()
    for name in sorted(os.listdir(CHECKS)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(CHECKS, name), encoding="utf-8") as handle:
            source = handle.read()
        for anchor in re.findall(r'doc\s*=\s*"([^"]+)"', source):
            found.add((anchor, name))
        for anchor in re.findall(r'^DOC[A-Z_]*\s*=\s*"([^"]+)"', source, re.M):
            found.add((anchor, name))
    return found


class TestDocAnchors(unittest.TestCase):
    def test_doc_is_present(self):
        self.assertTrue(os.path.exists(DOC), "docs/troubleshooting.md is missing")

    def test_every_anchor_resolves(self):
        known = doc_anchors()
        dangling = sorted((a, f) for a, f in referenced_anchors() if a not in known)
        self.assertEqual(dangling, [], "anchors with no heading in docs/troubleshooting.md: %s"
                         % ", ".join("%s (%s)" % (a, f) for a, f in dangling))

    def test_index_table_covers_every_anchor(self):
        """The doc's own 'Which check points here' table is the reverse index; keep it honest."""
        with open(DOC, encoding="utf-8") as handle:
            body = handle.read()
        table = body.split("## Which check points here", 1)[1].split("\n---", 1)[0]
        linked = set(re.findall(r"\(#([a-z0-9][a-z0-9\-_]*)\)", table))
        missing = sorted(a for a, _ in referenced_anchors() if a not in linked)
        self.assertEqual(missing, [], "sections a check points at but the index omits: %s"
                         % ", ".join(missing))

    def test_no_doc_links_to_a_heading_that_is_not_there(self):
        """Cross-links between the docs rot the same way `doc=` anchors do.

        The fault-injection runbook is mostly links into troubleshooting.md, and a
        runbook that sends you to a section that no longer exists is worse than one
        that says nothing.

        The README counts too, and used not to: it reaches the doc with a different
        relative path (`docs/troubleshooting.md#...`), so the pattern that covered
        the runbook missed it entirely and its first anchored link went unchecked.
        """
        known = doc_anchors()
        dangling = []
        targets = [(path, os.path.join(os.path.dirname(DOC), path))
                   for path in sorted(os.listdir(os.path.dirname(DOC)))
                   if path.endswith(".md")]
        targets.append(("README.md", os.path.join(ROOT, "README.md")))
        for path, full in targets:
            with open(full, encoding="utf-8") as handle:
                body = handle.read()
            for anchor in re.findall(
                    r"\]\((?:docs/)?troubleshooting\.md#([a-z0-9\-_]+)\)", body):
                if anchor not in known:
                    dangling.append("%s -> #%s" % (path, anchor))
            if path == os.path.basename(DOC):
                for anchor in re.findall(r"\]\(#([a-z0-9\-_]+)\)", body):
                    if anchor not in known:
                        dangling.append("%s -> #%s" % (path, anchor))
        self.assertEqual(sorted(dangling), [], "links into a heading that is not there: %s"
                         % ", ".join(sorted(dangling)))

    def test_default_doc_base_points_at_the_copy_in_this_repo(self):
        from fdsc_verify import report
        self.assertTrue(report.DOC_BASE.endswith("docs/troubleshooting.md"), report.DOC_BASE)


if __name__ == "__main__":
    unittest.main()
