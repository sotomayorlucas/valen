using System;
using System.Diagnostics;

class Program
{
    // CWE-78: command injection via args -> Process.Start
    static void Main(string[] args)
    {
        if (args.Length > 0)
        {
            Process.Start(args[0]);
        }

        var envCmd = Environment.GetEnvironmentVariable("CMD");
        if (!string.IsNullOrEmpty(envCmd))
        {
            Process.Start(envCmd);
        }
    }
}
