"""Validate the shared B change protocol before allowing a cursor to advance."""


def validate_page(page, requested_cursor, expected_epoch=None, through=None):
    if not isinstance(page, dict) or not isinstance(page.get("epoch"), str) or not page["epoch"]:
        raise ValueError("B change feed has no database identity")
    for field in ("cursor", "next_cursor", "through"):
        if type(page.get(field)) is not int or page[field] < 0:
            raise ValueError("B change feed has an invalid cursor")
    if type(page.get("reset")) is not bool or type(page.get("has_more")) is not bool:
        raise ValueError("B change feed has invalid flags")
    if not isinstance(page.get("changes"), list):
        raise ValueError("B change feed has invalid changes")
    if page["reset"]:
        if page["cursor"] != 0:
            raise ValueError("B reset must start at zero")
    elif page["cursor"] != requested_cursor:
        raise ValueError("B change feed skipped the requested cursor")
    if expected_epoch is not None and page["epoch"] != expected_epoch:
        raise ValueError("B database changed during pagination; retry from the stored cursor")
    if through is not None and page["through"] != through:
        raise ValueError("B change feed high-water mark changed during pagination")
    if not page["cursor"] <= page["next_cursor"] <= page["through"]:
        raise ValueError("B change feed cursor is out of range")
    previous = page["cursor"]
    for row in page["changes"]:
        if (not isinstance(row, dict) or type(row.get("seq")) is not int
                or not previous < row["seq"] <= page["next_cursor"]
                or not isinstance(row.get("entity_id"), str) or not row["entity_id"]
                or row.get("operation") not in {"upsert", "retract"}):
            raise ValueError("B change feed contains an invalid or unordered event")
        if row["operation"] == "upsert" and not isinstance(row.get("item"), dict):
            raise ValueError("B change feed upsert has no item")
        previous = row["seq"]
    if page["has_more"] and (not page["changes"] or page["next_cursor"] <= page["cursor"]):
        raise ValueError("B change feed pagination made no progress")
    if not page["has_more"] and page["next_cursor"] != page["through"]:
        raise ValueError("B change feed ended before its high-water mark")
    return page
