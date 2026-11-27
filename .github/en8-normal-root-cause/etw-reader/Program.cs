using System.Globalization;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;

if (args.Length != 5)
    throw new ArgumentException("Expected ETL, sender PID, receiver PID, body start Unix ns, endpoint Unix ns");

int sender = int.Parse(args[1], CultureInfo.InvariantCulture);
int receiver = int.Parse(args[2], CultureInfo.InvariantCulture);
DateTime begin = DateTime.UnixEpoch.AddTicks(long.Parse(args[3], CultureInfo.InvariantCulture) / 100);
DateTime end = DateTime.UnixEpoch.AddTicks(long.Parse(args[4], CultureInfo.InvariantCulture) / 100);
if (sender <= 0 || receiver <= 0 || sender == receiver || end <= begin || (end - begin).TotalSeconds > 40)
    throw new ArgumentException("Invalid owned process identities or elapsed trace window");

var pids = new Dictionary<int, Role> { [sender] = new(), [receiver] = new() };
var irps = new Dictionary<ulong, IoRequest>();
int collisions = 0;
int invalidDurations = 0;

using var trace = new ETWTraceEventSource(args[0]);
var kernel = new KernelTraceEventParser(trace);

bool InWindow(DateTime stamp) => stamp >= begin && stamp <= end;

void NoteImage(int pid, ulong address, int size, string path)
{
    if (!pids.TryGetValue(pid, out var role) || size <= 0 || role.Images.ContainsKey(address)) return;
    string name = Path.GetFileName(path.Replace('/', '\\'));
    if (!string.IsNullOrWhiteSpace(name)) role.Images.Add(address, new Module(name.ToLowerInvariant(), address, size));
}

void Issue(int pid, ulong irp, DateTime stamp, string operation, string filename, int size)
{
    if (!pids.TryGetValue(pid, out var role) || !InWindow(stamp)) return;
    string category = Classify(filename);
    var key = (operation, category);
    if (!role.Files.TryGetValue(key, out var summary)) role.Files.Add(key, summary = new FileSummary());
    summary.Requests++;
    summary.RequestedBytes += Math.Max(0, size);
    if (irp == 0) return;
    if (irps.ContainsKey(irp))
    {
        collisions++;
        irps.Remove(irp);
        return;
    }
    if (irps.Count >= 32768) throw new InvalidDataException("In-flight FileIO correlation budget exceeded");
    irps.Add(irp, new IoRequest(stamp, summary));
}

kernel.ImageLoad += data => NoteImage(data.ProcessID, data.ImageBase, data.ImageSize, data.FileName);
kernel.ImageDCStart += data => NoteImage(data.ProcessID, data.ImageBase, data.ImageSize, data.FileName);
kernel.ImageDCStop += data => NoteImage(data.ProcessID, data.ImageBase, data.ImageSize, data.FileName);
kernel.PerfInfoSample += data =>
{
    if (!pids.TryGetValue(data.ProcessID, out var role) || data.NonProcess || !InWindow(data.TimeStamp.ToUniversalTime())) return;
    ulong ip = data.InstructionPointer;
    if (role.Samples.Count >= 262144 && !role.Samples.ContainsKey(ip))
        throw new InvalidDataException("CPU sample address budget exceeded");
    role.Samples[ip] = role.Samples.GetValueOrDefault(ip) + 1;
};
kernel.FileIOCreate += data => Issue(data.ProcessID, data.IrpPtr, data.TimeStamp.ToUniversalTime(), "create", data.FileName, 0);
kernel.FileIORead += data => Issue(data.ProcessID, data.IrpPtr, data.TimeStamp.ToUniversalTime(), "read", data.FileName, data.IoSize);
kernel.FileIOWrite += data => Issue(data.ProcessID, data.IrpPtr, data.TimeStamp.ToUniversalTime(), "write", data.FileName, data.IoSize);
kernel.FileIOCleanup += data => Issue(data.ProcessID, data.IrpPtr, data.TimeStamp.ToUniversalTime(), "cleanup", data.FileName, 0);
kernel.FileIOClose += data => Issue(data.ProcessID, data.IrpPtr, data.TimeStamp.ToUniversalTime(), "close", data.FileName, 0);
kernel.FileIOFlush += data => Issue(data.ProcessID, data.IrpPtr, data.TimeStamp.ToUniversalTime(), "flush", data.FileName, 0);
kernel.FileIOOperationEnd += data =>
{
    if (!irps.Remove(data.IrpPtr, out var pending)) return;
    DateTime stamp = data.TimeStamp.ToUniversalTime();
    if (!InWindow(stamp)) return;
    double elapsed = (stamp - pending.Started).TotalMilliseconds;
    if (elapsed < 0)
    {
        invalidDurations++;
        return;
    }
    pending.Summary.Matched++;
    if (data.NtStatus < 0) pending.Summary.Failed++;
    pending.Summary.MatchedElapsedMilliseconds += elapsed;
    pending.Summary.MaxMatchedMilliseconds = Math.Max(pending.Summary.MaxMatchedMilliseconds, elapsed);
};
trace.Process();

object Summarize(int pid)
{
    Role role = pids[pid];
    var frames = role.Samples.Select(pair =>
    {
        Module? image = role.Images.Values.FirstOrDefault(img => pair.Key >= img.Address && pair.Key - img.Address < (ulong)img.Size);
        return (Name: image?.Name ?? (pair.Key >> 63 == 1 ? "kernel-unresolved" : "user-unresolved"),
                Offset: image is null ? 0UL : pair.Key - image.Address, Count: pair.Value);
    });
    var modules = frames.GroupBy(frame => frame.Name).Select(g => new { module = g.Key, count = g.Sum(f => f.Count) })
        .OrderByDescending(f => f.count).Take(20).ToArray();
    var offsets = frames.Where(f => f.Name is not ("kernel-unresolved" or "user-unresolved"))
        .GroupBy(f => (f.Name, f.Offset)).Select(g => new { module = g.Key.Name, rva = $"0x{g.Key.Offset:x}", count = g.Sum(f => f.Count) })
        .OrderByDescending(f => f.count).Take(30).ToArray();
    var fileGroups = role.Files.OrderBy(x => x.Key.Operation).ThenBy(x => x.Key.Category).Select(x => new
    {
        operation = x.Key.Operation, category = x.Key.Category, requests = x.Value.Requests,
        requested_bytes = x.Value.RequestedBytes, matched_completions = x.Value.Matched, failed_completions = x.Value.Failed,
        matched_request_milliseconds_sum = x.Value.MatchedElapsedMilliseconds,
        matched_request_milliseconds_max = x.Value.MaxMatchedMilliseconds,
    }).ToArray();
    return new { pid, cpu_samples = role.Samples.Values.Sum(), cpu_by_module = modules, cpu_top_module_offsets = offsets, file_groups = fileGroups };
}

bool hasCoverage = pids.Values.All(role => role.Samples.Values.Sum() >= 10 && role.Files.Values.Sum(o => o.Requests) > 0);
var result = new
{
    schema = 1, status = trace.EventsLost == 0 && hasCoverage ? "passed" : "inconclusive",
    provider = "Microsoft TraceEvent Windows kernel WPR CPU + FileIO",
    traceevent_version = typeof(TraceEvent).Assembly.GetName().Version?.ToString(),
    start_utc = begin, end_utc = end, wall_seconds = (end - begin).TotalSeconds,
    trace_events_lost = trace.EventsLost, coverage_both_processes = hasCoverage, irp_identity_collisions = collisions,
    matched_negative_durations = invalidDurations, unmatched_requests_at_end = irps.Count,
    sender = Summarize(sender), receiver = Summarize(receiver),
};
Console.WriteLine(JsonSerializer.Serialize(result));

static string Classify(string path)
{
    if (string.IsNullOrEmpty(path)) return "unresolved";
    string value = path.Replace('/', '\\').ToLowerInvariant();
    string name = value[(value.LastIndexOf('\\') + 1)..];
    if (value.Contains("\\blocks\\index\\")) return "block_index";
    if (value.Contains("\\chainstate\\")) return "chainstate";
    if (name.StartsWith("blk", StringComparison.Ordinal) && name.EndsWith(".dat", StringComparison.Ordinal)) return "raw_blocks";
    if (name.StartsWith("rev", StringComparison.Ordinal) && name.EndsWith(".dat", StringComparison.Ordinal)) return "undo";
    if (name == "debug.log") return "debug_log";
    return "other_known_file";
}

sealed record Module(string Name, ulong Address, int Size);
sealed record IoRequest(DateTime Started, FileSummary Summary);
sealed class Role
{
    public Dictionary<ulong, Module> Images { get; } = new();
    public Dictionary<ulong, int> Samples { get; } = new();
    public Dictionary<(string Operation, string Category), FileSummary> Files { get; } = new();
}
sealed class FileSummary
{
    public long Requests, RequestedBytes, Matched, Failed;
    public double MatchedElapsedMilliseconds, MaxMatchedMilliseconds;
}
