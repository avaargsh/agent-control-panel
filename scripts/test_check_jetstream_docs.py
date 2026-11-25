import unittest

from check_jetstream_docs import check_document


class GuideCheckTests(unittest.TestCase):
    def test_valid_shell_and_non_shell(self):
        doc = "## Example\n```sh\nprintf '%s\\n' ok\n```\n```json\n{}\n```\n"
        self.assertEqual(check_document(doc, "guide.md"), [])

    def test_unclosed_shell_quote(self):
        doc = "```sh\ngo test -run '^TestRealDispositionInspector\n```\n"
        self.assertTrue(any("shell syntax" in e for e in check_document(doc, "guide.md")))

    def test_unclosed_fence(self):
        self.assertTrue(any("unclosed fence" in e for e in check_document("```sh\ntrue\n", "guide.md")))

    def test_duplicate_section(self):
        doc = "## Local command (disposable fixtures only)\nA\n## Local command (disposable fixtures only)\nB\n"
        self.assertTrue(any("duplicate section" in e for e in check_document(doc, "guide.md")))

    def test_required_command_must_be_in_shell_block(self):
        command = "go test -run '^TestExample$' ."
        self.assertTrue(check_document(command + "\n", "guide.md", (command,)))
        self.assertEqual(check_document("```sh\n" + command + "\n```\n", "guide.md", (command,)), [])
        self.assertTrue(check_document("```sh\n" + command + "\n" + command + "\n```\n", "guide.md", (command,)))


if __name__ == "__main__":
    unittest.main()
