namespace RevokeHookUI;

public sealed class CliOptions
{
    public bool UpdateConfig { get; private set; }

    public string? MessageTitle { get; private set; }

    public string? MessageContent { get; private set; }

    public static CliOptions Parse(IReadOnlyList<string> args)
    {
        var options = new CliOptions();

        for (var index = 0; index < args.Count; index++)
        {
            switch (args[index])
            {
                case "--update-config":
                    options.UpdateConfig = true;
                    break;
                case "--msg-title":
                    if (index + 1 < args.Count)
                    {
                        options.MessageTitle = args[++index];
                    }

                    break;
                case "--msg-content":
                    if (index + 1 < args.Count)
                    {
                        options.MessageContent = args[++index];
                    }

                    break;
            }
        }

        return options;
    }
}
