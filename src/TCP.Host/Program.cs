using TCP.Host;

return args.Length == 0
    ? ProtocolDiagnostics.Run()
    : HostCommand.Run(args);
