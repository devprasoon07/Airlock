import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(override=True)
print("BASE:", repr(os.environ.get("NVIDIA_BASE_URL")))
print("MODEL:", repr(os.environ.get("MODEL")))
key = os.environ.get("NVIDIA_API_KEY", "")
print("KEY starts with:", key[:6], "| length:", len(key))
client = OpenAI(
    base_url=os.environ["NVIDIA_BASE_URL"],
    api_key=os.environ["NVIDIA_API_KEY"],
)

tools = [{
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read a file",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
}]

r = client.chat.completions.create(
    model=os.environ["MODEL"],
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Read the file notes.txt"},
    ],
    tools=tools,
    tool_choice="auto",
    temperature=0.2,
    max_tokens=1024,
    stream=False,
)
print(r.choices[0].message)