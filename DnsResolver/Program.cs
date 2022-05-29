using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using DnsResolver;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .CreateLogger();

var logger = Log.Logger.ForContext<Program>();

const string configPath = @"dns.cfg";

Dictionary<string, IPAddress> ParseConfig(string configPath)
{
    var config = new Dictionary<string, IPAddress>();
    var lines = File.ReadAllLines(configPath);
    foreach (var line in lines)
    {
        var tokens = line.Split('=');
        var domain = tokens[0];
        var ipAddress = IPAddress.Parse(tokens[1]);
        config[domain] = ipAddress;
    }

    return config;
}

var config = ParseConfig(configPath);
var resolver = new SafeDnsResolver(config);

async void HandleData(byte[] data, UdpClient udp, IPEndPoint remoteEndpoint)
{
    try
    {
        var request = Request.FromArray(data);
        var response = Response.FromRequest(request);

        foreach (var question in request.Questions)
        {
            var requestedDomain = question.Name;
            var requestedType = question.Type;

            logger.Information("Requested resolve for {Type} {Domain} ", requestedType, requestedDomain);

            if (requestedType != RecordType.A)
            {
                throw new NotSupportedException("Resolving supported only for A records");
            }

            var microCache = new Dictionary<string, IPAddress>();

            try
            {
                var requestedIpAddress = await resolver.Resolve(requestedDomain.ToString(), microCache);
                response.AnswerRecords.Add(new IPAddressResourceRecord(requestedDomain, requestedIpAddress));
                logger.Information("{Type} {Domain} resolved", requestedType, requestedDomain);
            }
            catch (ResolveFailedException e)
            {
                response.ResponseCode = ResponseCode.Refused;
                logger.Warning(e, "{Type} {Domain} resolve failed", requestedType, requestedDomain);
            }
        }

        await udp.SendAsync(response.ToArray(), remoteEndpoint);
    }
    catch (Exception e)
    {
        logger.Fatal(e, "");
    }
}

async Task Listen()
{
    var taskCompletion = new TaskCompletionSource();

    using var udp = new UdpClient(53);

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        udp.Client.IOControl(unchecked((int)0x9800000C), new byte[4], new byte[4]);
    }

    void ReceiveCallback(IAsyncResult result)
    {
        try
        {
            var remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
            var data = udp.EndReceive(result, ref remoteEndpoint);
            HandleData(data, udp, remoteEndpoint);
        }
        catch (Exception e)
        {
            logger.Fatal(e, "");
        }

        udp.BeginReceive(ReceiveCallback, null);
    }

    udp.BeginReceive(ReceiveCallback, null);

    await taskCompletion.Task;
}

await Listen();