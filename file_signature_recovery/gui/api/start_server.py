import uvicorn

if __name__ == "__main__":
    # Access log is set to false as per instructions to only show errors
    uvicorn.run("main:app", host="127.0.0.1", port=7999, access_log=False)
