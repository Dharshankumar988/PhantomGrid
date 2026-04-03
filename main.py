from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.routes import router

app = FastAPI(title="PhantomGrid", version="1.0.0")

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(router)


@app.get("/health")
async def health_check():
    return {"status": "ok"}
