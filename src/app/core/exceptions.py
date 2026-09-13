from dataclasses import dataclass


@dataclass
class AppError[T](Exception):
    message: str
    status_code: int = 400
    payload: T | None = None

    def __post_init__(self) -> None:
        super().__init__(self.message)
