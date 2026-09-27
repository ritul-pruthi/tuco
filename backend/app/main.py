from fastapi import FastAPI

app = FastAPI(title="TUCO")


@app.get("/health")
def health_check():
    return {"status": "ok"}
