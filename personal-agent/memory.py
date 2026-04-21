import json
import os
from datetime import datetime

DATA_DIR = os.getenv("DATA_DIR", "/data")
MEMORY_FILE = os.path.join(DATA_DIR, "memory.json")


class Memory:
    def __init__(self):
        self.data = self._load()

    def _load(self) -> dict:
        if os.path.exists(MEMORY_FILE):
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"history": [], "facts": []}

    def _save(self):
        os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
        with open(MEMORY_FILE, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

    def add_message(self, role: str, content: str):
        self.data["history"].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
        })
        self._save()

    def add_fact(self, fact: str):
        if fact not in self.data["facts"]:
            self.data["facts"].append(fact)
            self._save()

    def get_history(self, limit: int = 50) -> list:
        return self.data["history"][-limit:]

    def get_facts_summary(self) -> str:
        if not self.data["facts"]:
            return "Sem factos guardados sobre o utilizador."
        return "Factos conhecidos:\n" + "\n".join(
            f"- {f}" for f in self.data["facts"]
        )

    def clear_history(self):
        self.data["history"] = []
        self._save()
