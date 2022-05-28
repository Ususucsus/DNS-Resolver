namespace DnsResolver;

[Serializable]
public class ResolveFailedException : Exception
{
    public ResolveFailedException()
    {
    }

    public ResolveFailedException(string message) : base(message)
    {
    }

    public ResolveFailedException(string message, Exception inner) : base(message, inner)
    {
    }
}