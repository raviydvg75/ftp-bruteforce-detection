import unittest

from src.metrics import calculate_metrics


class TestMetrics(unittest.TestCase):
    def test_perfect_predictions(self):
        result = calculate_metrics([1, 0, 1, 0], [1, 0, 1, 0])
        self.assertEqual(result["true_positives"], 2)
        self.assertEqual(result["true_negatives"], 2)
        self.assertEqual(result["false_positives"], 0)
        self.assertEqual(result["false_negatives"], 0)
        self.assertEqual(result["f1_score"], 1.0)

    def test_false_positive_and_false_negative(self):
        result = calculate_metrics([1, 0], [0, 1])
        self.assertEqual(result["false_positives"], 1)
        self.assertEqual(result["false_negatives"], 1)
        self.assertEqual(result["precision"], 0.0)
        self.assertEqual(result["recall"], 0.0)

    def test_mismatched_lengths_rejected(self):
        with self.assertRaises(ValueError):
            calculate_metrics([1, 0], [1])

    def test_empty_data_rejected(self):
        with self.assertRaises(ValueError):
            calculate_metrics([], [])

    def test_non_binary_labels_rejected(self):
        with self.assertRaises(ValueError):
            calculate_metrics([1, 2], [1, 0])


if __name__ == "__main__":
    unittest.main()
