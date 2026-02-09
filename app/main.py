from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def hello(name: str = "World"):
   """Return a friendly HTTP greeting."""
   return {
      "message": f"Hello {name}!"
   }


@app.get("/health")
def health():
   """Return a HTTP health check."""
   return {
      "status": 200
   }
