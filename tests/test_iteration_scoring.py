"""Protect experiment denominators from silent error/unknown-label inflation."""
import unittest

from evaluation.scripts.run_iteration import score


class IterationScoringTests(unittest.TestCase):
    def manifest(self, labels):
        return {"label_unit": "artifact/rule/function", "artifacts": [{"id": "case", "labels": labels}]}

    def label(self, polarity, function=None):
        return dict(rule_id="MCP05-COMMAND-INJECTION", polarity=polarity, function_name=function)

    def test_failed_negative_is_error_not_true_negative(self):
        result = score(self.manifest([self.label("negative")]), [{"artifact_id": "case", "status": "failed"}])
        self.assertEqual(1, result["micro"]["errors"])
        self.assertEqual(0, result["micro"]["tn"])
        self.assertIsNone(result["micro"]["false_positive_rate"])
        self.assertEqual(0, result["micro"]["label_coverage"])

    def test_function_scopes_and_duplicate_findings(self):
        labels = [self.label("positive", "unsafe"), self.label("negative", "safe")]
        finding = dict(rule_id="MCP05-COMMAND-INJECTION", function_name="unsafe")
        result = score(self.manifest(labels), [dict(artifact_id="case", status="completed", findings=[finding, finding])])
        self.assertEqual(1, result["micro"]["tp"])
        self.assertEqual(1, result["micro"]["tn"])
        self.assertEqual(0, result["micro"]["fp"])

    def test_unlabelled_prediction_is_not_false_positive(self):
        result = score(self.manifest([self.label("positive", "expected")]), [dict(
            artifact_id="case", status="completed", findings=[dict(rule_id="MCP03-TOOL-POISON", function_name="other")])])
        self.assertEqual(1, result["micro"]["fn"])
        self.assertEqual(0, result["micro"]["fp"])
        self.assertEqual(1, len(result["unscored_predictions"]))


if __name__ == "__main__":
    unittest.main()
