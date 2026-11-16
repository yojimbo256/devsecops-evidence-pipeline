"""Small demo API. It exists so the pipeline has something real to build, scan and ship."""

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="evidence-demo", version="0.1.0")

_items: list[dict] = []


class Item(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    quantity: int = Field(ge=0, le=10_000)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/items", status_code=201)
def create_item(item: Item) -> dict:
    record = item.model_dump()
    _items.append(record)
    return record


@app.get("/items")
def list_items() -> list[dict]:
    return _items
