from src.detection.analyzer import detect_new_processes


def test_detect_new_process():
    previous = [
        {
            "pid": 100,
            "name": "bash"
        }
    ]

    current = [
        {
            "pid": 100,
            "name": "bash"
        },
        {
            "pid": 200,
            "name": "python"
        }
    ]

    result = detect_new_processes(previous, current)

    assert len(result) == 1
    assert result[0]["pid"] == 200
    assert result[0]["name"] == "python"