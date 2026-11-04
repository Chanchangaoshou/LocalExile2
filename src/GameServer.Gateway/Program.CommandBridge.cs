using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

/// <summary>
/// The command bridge for external tools (the PoE2 command deck): a TCP listener on this machine only
/// (Game_CMD_BIND, default 127.0.0.1; Game_CMD_PORT, default 7010; a port of 0 disables it). One UTF-8 line
/// per request: a slash-command line ("/item Mageblood") runs on the live connection through the very
/// ChatCommands the chat box uses (Program.Commands.cs), so its effect and its reply land in the game
/// exactly like a typed command; the sends go through the connection's own send gate. A line of
/// {"command": "/item ..."} is the same request in JSON. {"op":"who"} answers the connected characters.
/// Every answer is one JSON line: {"ok":true,...} or {"ok":false,"error":"..."}. Local play has one player;
/// with several connections the longest-connected one is used.
/// </summary>
static class CommandBridge
{
    private static readonly ConcurrentDictionary<ClientState, DateTime> Live = new();
    private static TcpListener? _listener;

    public static void Register(ClientState conn) => Live[conn] = DateTime.UtcNow;

    public static void Unregister(ClientState conn) => Live.TryRemove(conn, out _);

    public static void Start()
    {
        int port = int.TryParse(Environment.GetEnvironmentVariable("Game_CMD_PORT"), out var p) ? p : 7010;
        if (port <= 0) return;
        var bind = IPAddress.Parse(Environment.GetEnvironmentVariable("Game_CMD_BIND") ?? "127.0.0.1");
        _listener = new TcpListener(bind, port);
        _listener.Start();
        Console.WriteLine($"[gateway] command bridge on {bind}:{port} (Game_CMD_PORT=0 disables)");
        _ = AcceptLoop();
    }

    private static async Task AcceptLoop()
    {
        while (true)
        {
            TcpClient client;
            try { client = await _listener!.AcceptTcpClientAsync(); }
            catch (Exception) { return; } // the listener stopped
            _ = Serve(client);
        }
    }

    private static async Task Serve(TcpClient client)
    {
        try
        {
            using (client)
            {
                var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, false, 4096, leaveOpen: true);
                await using var writer = new StreamWriter(stream, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true, NewLine = "\n" };
                while (await reader.ReadLineAsync() is { } line)
                {
                    if (line.Length > 8192) break;
                    await writer.WriteLineAsync(await Handle(line.Trim()));
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
    }

    private static async Task<string> Handle(string line)
    {
        try
        {
            string? command = line;
            if (line.StartsWith('{'))
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                if (root.TryGetProperty("op", out var op) && op.GetString() == "who")
                    return Json(new { ok = true, characters = Live.Keys.Select(c => c.Character).Where(n => n is { Length: > 0 }).ToArray() });
                command = root.TryGetProperty("command", out var c) ? c.GetString() : null;
            }
            if (command is not { Length: > 0 } || !command.StartsWith('/'))
                return Json(new { ok = false, error = "expected a slash command, e.g. /item Mageblood" });
            var target = Live.OrderBy(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault(c => c.Commands is not null);
            if (target is null)
                return Json(new { ok = false, error = "no live connection (nobody is in the world)" });
            bool ran = await target.Commands!.RunAsync(command);
            return Json(new { ok = true, ran, character = target.Character });
        }
        catch (Exception ex)
        {
            return Json(new { ok = false, error = ex.Message });
        }
    }

    private static string Json(object value) => JsonSerializer.Serialize(value);
}
