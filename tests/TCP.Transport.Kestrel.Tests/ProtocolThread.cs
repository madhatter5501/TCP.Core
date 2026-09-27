using TCP.Stack;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>Runs test code on an EthernetStack's protocol thread, where TCP objects may be touched.</summary>
internal static class ProtocolThread
{
    public static async Task<T> RunAsync<T>(EthernetStack stack, Func<T> action)
    {
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!stack.TrySchedule(() =>
        {
            try { completion.TrySetResult(action()); }
            catch (Exception error) { completion.TrySetException(error); }
        }))
            throw new InvalidOperationException("The stack's command queue is full.");
        return await completion.Task.WaitAsync(TimeSpan.FromSeconds(10));
    }

    public static Task RunAsync(EthernetStack stack, Action action) =>
        RunAsync(stack, () => { action(); return true; });
}
