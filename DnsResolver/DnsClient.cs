using System.Net;
using System.Net.Sockets;
using DNS.Protocol;
using Serilog;

namespace DnsResolver;

public class DnsClient
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static readonly Dictionary<(string, IPAddress), Response> Cache = new();
    private readonly ILogger _logger;
    
    public DnsClient()
    {
        _logger = Log.Logger.ForContext<DnsClient>();
    }

    public int Requests { get; set; }

    public async Task<Response> SendAsync(Request request, IPAddress ipAddress)
    {
        var serializedRequest = SerializeRequest(request);        
        Requests++;
        var timeoutCancellationTokenSource = new CancellationTokenSource(Timeout);

        if (Cache.ContainsKey((serializedRequest, ipAddress)))
        {
            _logger.Debug("Request to {IpAddress} found in cache", ipAddress);
            return Cache[(serializedRequest, ipAddress)];
        }

        _logger.Debug("Requesting {IpAddress}", ipAddress);

        Console.Write('.');

        var endpoint = new IPEndPoint(ipAddress, 53);

        var requestBytes = new byte[2 + request.Size];
        requestBytes[0] = (byte)(request.Size >> 8);
        requestBytes[1] = (byte)request.Size;
        request.ToArray().CopyTo(requestBytes, 2);

        using var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(endpoint, timeoutCancellationTokenSource.Token);
        await using var tcpStream = tcpClient.GetStream();
        await tcpStream.WriteAsync(requestBytes, timeoutCancellationTokenSource.Token);
        await tcpStream.FlushAsync(timeoutCancellationTokenSource.Token);

        var responseSizeBytes = new byte[2];
        await tcpStream.ReadAsync(responseSizeBytes, timeoutCancellationTokenSource.Token);
        var responseSize = (short)(responseSizeBytes[0] << 8 | responseSizeBytes[1]);
        var responseBytes = new byte[responseSize];
        await tcpStream.ReadAsync(responseBytes, timeoutCancellationTokenSource.Token);
        var response = Response.FromArray(responseBytes);

        Cache[(serializedRequest, ipAddress)] = response;
        return response;
    }

    private static string SerializeRequest(IMessage request)
    {
        return string.Join(' ', request.Questions);
    }
}