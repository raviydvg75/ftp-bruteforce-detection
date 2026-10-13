"""Classification metrics for source-IP-level detection evaluation."""

def calculate_metrics(actual, predicted):
    if len(actual) != len(predicted):
        raise ValueError("actual and predicted must have equal lengths")

    if not actual:
        raise ValueError("At least one labeled sample is required")

    if any(value not in (0, 1) for value in actual + predicted):
        raise ValueError("Labels must be binary: 0 or 1")

    tp = sum(a == 1 and p == 1 for a, p in zip(actual, predicted))
    tn = sum(a == 0 and p == 0 for a, p in zip(actual, predicted))
    fp = sum(a == 0 and p == 1 for a, p in zip(actual, predicted))
    fn = sum(a == 1 and p == 0 for a, p in zip(actual, predicted))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / len(actual)

    return {
        "samples": len(actual),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
    }
