import os
from typing import Any

class ConfigLoader:
    _config = {
        "ELASTICSEARCH_HOSTS": ["http://localhost:9200"],
        "API_LOGS_INDEX": "api-logs",
        "DETECTION_RESULTS_INDEX": "detection-results",
        "MODEL_PATH": "models/",
        "ATTACK_DENSITY": 0.05,
        "NORMAL_HOURS": 24
    }

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        return os.getenv(key, cls._config.get(key, default))
