from enum import Enum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Status(str, Enum):
    unreviewed = "unreviewed"
    confirmed = "confirmed"
    fixing = "fixing"
    pending_verification = "pending_verification"
    closed = "closed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"


TRANSITIONS = {
    "unreviewed": ["confirmed", "false_positive", "accepted_risk"],
    "confirmed": ["fixing", "false_positive", "accepted_risk"],
    "fixing": ["pending_verification", "confirmed", "accepted_risk"],
    "pending_verification": ["fixing", "closed", "accepted_risk"],
    "closed": ["confirmed"],
    "false_positive": ["unreviewed"],
    "accepted_risk": ["confirmed"],
}


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ImportRun(Input):
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,100}$")


class Note(Input):
    note: str = Field(min_length=3, max_length=4000)

    @field_validator("note")
    @classmethod
    def safe_text(cls, value):
        if any(ord(c) < 32 and c not in "\n\t" for c in value):
            raise ValueError("Control characters forbidden")
        return value


class ChangeStatus(Note):
    status: Status
    version: int = Field(ge=1, strict=True)
    verification_id: int | None = Field(default=None, ge=1)


class Repair(Note):
    reference: str = Field(min_length=3, max_length=300)


class Verify(Note):
    run_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,100}$")
    repair_id: int = Field(ge=1, strict=True)
    evidence_ids: list[int] = Field(min_length=1, max_length=20)
    conclusion: Literal["inconclusive", "still_present", "remediated"]
    scope: str = Field(min_length=10, max_length=2000)


class Associate(Note):
    target_id: int = Field(ge=1, strict=True)
    version: int = Field(ge=1, strict=True)
