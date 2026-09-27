using TCP.L2.Link.Bridge;
using TCP.L2.Link.Ethernet;

namespace TCP.Tests;

internal static class SpanningTreeTests
{
    public static int Run()
    {
        var time = new FakeTime();
        var queue = new Queue<(int Bridge, int Port, byte[] Frame)>();
        var links = new Dictionary<(int, int), (int, int)>
        {
            [(0, 0)] = (1, 0), [(1, 0)] = (0, 0), [(1, 1)] = (2, 0),
            [(2, 0)] = (1, 1), [(2, 1)] = (0, 1), [(0, 1)] = (2, 1)
        };
        var bridges = Enumerable.Range(0, 3).Select(b => new SpanningTree(Mac(b), [Mac(b, 0), Mac(b, 1)],
            (p, frame) => { if (links.TryGetValue((b, p), out var target)) queue.Enqueue((target.Item1, target.Item2, frame)); }, time)).ToArray();
        Check(bridges.All(b => b.State(0) != BridgePortState.Forwarding && b.State(1) != BridgePortState.Forwarding), "STP forwarded before convergence");
        Advance(60);
        Check(bridges.All(b => b.RootId == bridges[0].RootId), "Bridge root election disagrees");
        Check(bridges[0].RootPort == -1, "Lowest bridge ID did not become root");
        Check(bridges.Sum(b => Enumerable.Range(0, 2).Count(p => b.State(p) == BridgePortState.Blocking)) == 1, "Triangle didn't block exactly one endpoint");
        Console.WriteLine("PASS: STP triangle elects a root and blocks its redundant path");
        links.Remove((0, 1)); links.Remove((2, 1));
        bridges[0].SetLink(1, false); bridges[2].SetLink(1, false);
        Advance(60);
        Check(bridges[2].RootPort == 0 && bridges[2].State(0) == BridgePortState.Forwarding, "Alternate path did not recover");
        Check(bridges[0].State(1) == BridgePortState.Blocking && bridges[2].State(1) == BridgePortState.Blocking, "Down link forwarded");
        Console.WriteLine("PASS: STP activates the alternate path after a link failure");
        // Silent peer disappearance exercises MaxAge rather than explicit link notification.
        links.Remove((0, 0)); links.Remove((1, 0));
        Advance(80);
        Check(bridges[1].RootPort == -1 && bridges[1].RootId == bridges[2].RootId, "Expired root wasn't replaced");
        Console.WriteLine("PASS: STP expires lost root information and re-elects");
        return 3;

        void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
        MacAddress Mac(int bridge, int port = 0) => MacAddress.FromBytes([2, 0, 0, (byte)bridge, 0, (byte)(port + 1)]);

        void Advance(int seconds)
        {
            for (var t = 0; t < seconds; t++)
            {
                foreach (var bridge in bridges) bridge.Tick();
                var budget = 100;
                while (queue.TryDequeue(out var received))
                {
                    if (--budget == 0) throw new Exception("BPDU transmission storm");
                    bridges[received.Bridge].Receive(received.Port, received.Frame);
                }
                time.Advance(TimeSpan.FromSeconds(1));
            }
        }
    }
}