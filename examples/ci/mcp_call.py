#!/usr/bin/env python3
"""Call one tool on an MCP server over stdio and print the result as JSON.

    mcp_call.py TOOL ARGUMENTS_JSON -- SERVER_COMMAND [ARGS...]

For example:

    mcp_call.py validate '{"yaml": "..."}' -- ojs-mcp

An agent normally does this. In CI there is no agent, so this script does the
three steps of the protocol itself: initialize, call the tool, read the
answer. It needs only the Python standard library.

Exit codes: 0 the tool answered, 2 the tool reported an error, 3 the server
could not be started or did not answer.
"""

import json
import subprocess
import sys
import tempfile


class ToolError(Exception):
    """The tool ran and reported an error."""


class ServerError(Exception):
    """The server could not be started or did not answer."""


def call(tool, arguments, command):
    """Call one tool on a stdio MCP server and return its structured result."""
    # The server's own messages go to a file. They are only worth showing
    # when it fails, for example because its config file is wrong.
    log = tempfile.TemporaryFile(mode="w+")
    try:
        server = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
    except OSError as err:
        raise ServerError(f"cannot start {command[0]}: {err}") from err

    def said():
        log.seek(0)
        text = log.read().strip()
        return f"\n{command[0]} said:\n{text}" if text else ""

    def send(message):
        server.stdin.write(json.dumps(message) + "\n")
        server.stdin.flush()

    def answer(request_id):
        # The server may send notifications in between; skip to our answer.
        for line in server.stdout:
            message = json.loads(line)
            if message.get("id") == request_id:
                return message
        return None

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "ci", "version": "1"}}})
        if answer(1) is None:
            raise ServerError(f"{command[0]} did not answer initialize{said()}")
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": tool, "arguments": arguments}})
        reply = answer(2)
    finally:
        server.stdin.close()
        server.wait(timeout=30)

    if reply is None:
        raise ServerError(f"{command[0]} did not answer the call to {tool}{said()}")
    if "error" in reply:
        raise ToolError(str(reply["error"].get("message", reply["error"])))
    result = reply["result"]
    if result.get("isError"):
        raise ToolError("\n".join(part.get("text", "") for part in result.get("content", [])))
    return result.get("structuredContent", result)


def main() -> int:
    if "--" not in sys.argv or sys.argv.index("--") != 3:
        print(__doc__, file=sys.stderr)
        return 3
    try:
        result = call(sys.argv[1], json.loads(sys.argv[2]), sys.argv[4:])
    except ToolError as err:
        print(err, file=sys.stderr)
        return 2
    except ServerError as err:
        print(err, file=sys.stderr)
        return 3
    json.dump(result, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
