import uvicorn

if __name__ == "__main__":
    print("=" * 50)
    print("  Starting File Signature Recovery API Server")
    print("  Open http://127.0.0.1:7999 in your browser")
    print("=" * 50)
    uvicorn.run("main:app", host="127.0.0.1", port=7999, access_log=False)
