from sqlalchemy import inspect, text


# 기존 SQLite DB를 삭제하지 않고 공통 이벤트 필드만 추가한다.
# Base.metadata.create_all()은 이미 존재하는 테이블의 컬럼을 추가하지 않기 때문에
# 개발 단계에서 필요한 최소 마이그레이션을 명시적으로 수행한다.
SECURITY_EVENT_COLUMNS = {
    "host": "VARCHAR",
    "source": "VARCHAR",
    "raw_event_id": "VARCHAR",
    "file_path": "VARCHAR",
    "device_name": "VARCHAR",
    "device_id": "VARCHAR",
}


def migrate_security_event_schema(engine):
    inspector = inspect(engine)

    if "security_events" not in inspector.get_table_names():
        return []

    existing_columns = {
        column["name"]
        for column in inspector.get_columns("security_events")
    }

    added_columns = []

    with engine.begin() as connection:
        for column_name, column_type in SECURITY_EVENT_COLUMNS.items():
            if column_name in existing_columns:
                continue

            connection.execute(
                text(
                    f"ALTER TABLE security_events "
                    f"ADD COLUMN {column_name} {column_type}"
                )
            )
            added_columns.append(column_name)

    return added_columns
