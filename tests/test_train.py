from hunter.head import LogisticHead
from hunter.train import fit_head, synthetic_rows


def test_training_separates_labeled_rows():
    rows = synthetic_rows()
    model = fit_head(rows)
    head = LogisticHead(model)
    positive = next(row for row in rows if row["label"] == 1)
    negative = next(row for row in rows if row["label"] == 0)
    assert head.model_id == "jev-1.13.0"
    assert head.predict(positive) > head.predict(negative)
    assert head.predict(positive) >= 0.7
    assert head.predict(negative) < 0.4
