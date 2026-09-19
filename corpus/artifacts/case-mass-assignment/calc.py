from __future__ import annotations


class UserProfile:
    def __init__(self) -> None:
        self.name = ""
        self.email = ""
        self.is_admin = False

    def update(self, fields: dict) -> None:
        """Apply a form submission to the profile."""
        for key, value in fields.items():   # mass assignment: is_admin writable from a form
            setattr(self, key, value)
