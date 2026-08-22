import pytest

from core.database import get_connection


@pytest.fixture(autouse=True)
def clean_database():
    connection = get_connection()

    connection.execute("DELETE FROM attacks")
    connection.commit()
    connection.close()

    yield

    connection = get_connection()
    connection.execute("DELETE FROM attacks")
    connection.commit()
    connection.close()