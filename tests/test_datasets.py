import unittest

from server.datasets import (
    add_logs_from_content,
    clear_uploaded_logs,
    search_uploaded_logs_best_effort,
)


class DatasetsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        clear_uploaded_logs()

    def tearDown(self) -> None:
        clear_uploaded_logs()

    def test_best_effort_matches_spl_tokens_and_ip(self) -> None:
        add_logs_from_content("x.log", b"failed auth from 10.0.0.1 for corp\\alice")
        rows = search_uploaded_logs_best_effort(
            "search index=main A-001",
            max_results=5,
            alert={"id": "A-001", "ip": "10.0.0.1"},
        )
        self.assertTrue(rows)
        self.assertIn("10.0.0.1", rows[0]["raw"])

    def test_best_effort_falls_back_to_sample(self) -> None:
        add_logs_from_content("y.log", b"only unique line in dataset")
        rows = search_uploaded_logs_best_effort(
            "zzzz_spl_will_never_match_this_full_string_zzzz",
            max_results=3,
        )
        self.assertTrue(rows)
        self.assertIn("only unique", rows[0]["raw"])


if __name__ == "__main__":
    unittest.main()
