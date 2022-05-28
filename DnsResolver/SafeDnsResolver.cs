using System.Net;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using Serilog;

namespace DnsResolver;

public sealed class SafeDnsResolver
{
    private readonly Dictionary<string, IPAddress> _config;

    private static readonly IPAddress[] RootNamespaceServers =
    {
        IPAddress.Parse("198.41.0.4")
    };

    private readonly DnsClient _dnsClient = new();
    private readonly ILogger _logger;

    public SafeDnsResolver(Dictionary<string, IPAddress> config)
    {
        _config = config;
        _logger = Log.Logger.ForContext<SafeDnsResolver>();
    }

    public async Task<IPAddress> Resolve(string domain, Dictionary<string, IPAddress> microCache)
    {
        _dnsClient.Requests = 0;
        if (_config.ContainsKey(domain))
        {
            var configIpAddress = _config[domain];
            _logger.Information("{Domain} found in config, resolved to {IpAddress}", domain, configIpAddress);
            return configIpAddress;
        }

        var (authorityIpAddress, domainIpAddress) = await ResolveAuthorityIpAddress(domain, microCache);

        domainIpAddress ??= await ResolveDomainIpAddress(domain, authorityIpAddress);

        return domainIpAddress;
    }

    private async Task<IPAddress> ResolveDomainIpAddress(string domain, IPAddress authorityIpAddress)
    {
        if (_dnsClient.Requests > 100)
        {
            throw new Exception("Too many requests, maybe infinite loop");
        }

        var request = BuildRequest(domain, RecordType.A);
        var response = await _dnsClient.SendAsync(request, authorityIpAddress);

        var domainIpAddresses = response.AnswerRecords
            .Where(x => x.Type == RecordType.A)
            .OfType<IPAddressResourceRecord>()
            .Select(x => x.IPAddress)
            .ToList();

        if (domainIpAddresses.Count == 0)
        {
            throw new ResolveFailedException("No A records");
        }

        var domainIpAddress = domainIpAddresses.First();

        return domainIpAddress;
    }

    private async Task<(
            IPAddress authorityIpAddress,
            IPAddress? domainIpAddress
            )>
        ResolveAuthorityIpAddress(
            string domain,
            Dictionary<string, IPAddress> microCache
        )
    {
        domain = NormalizeDomain(domain);
        var parts = SplitDomainToParts(domain);

        async Task<(
                List<string> authorityDomains,
                List<IPAddress> authorityIpAddresses,
                List<string> soaDomains,
                List<string> cnameDomains
                )>
            Request(
                string domainPart,
                IPAddress namespaceServer)
        {
            if (_dnsClient.Requests > 100)
            {
                throw new Exception("Too many requests, maybe infinite loop");
            }

            var request = BuildRequest(domainPart, RecordType.NS);
            var response = await _dnsClient.SendAsync(request, namespaceServer);

            var authorityDomainsFromAuthorityRecords = response.AuthorityRecords
                .Where(x => x.Type == RecordType.NS)
                .Where(x => x.Name.ToString() == domainPart)
                .OfType<NameServerResourceRecord>()
                .Select(x => x.NSDomainName.ToString())
                .ToList();

            var authorityDomainsFromAnswers = response.AnswerRecords
                .Where(x => x.Type == RecordType.NS)
                .Where(x => x.Name.ToString() == domainPart)
                .OfType<NameServerResourceRecord>()
                .Select(x => x.NSDomainName.ToString())
                .ToList();

            var authorityDomains = authorityDomainsFromAuthorityRecords
                .Union(authorityDomainsFromAnswers)
                .ToList();

            var authorityIpAddressRecords = response.AdditionalRecords
                .Where(x => x.Type == RecordType.A)
                .Where(x => authorityDomains.Contains(x.Name.ToString()))
                .OfType<IPAddressResourceRecord>()
                .ToList();

            var authorityIpAddresses = authorityIpAddressRecords
                .Select(x => x.IPAddress)
                .ToList();

            var soaDomains = response.AuthorityRecords
                .Where(x => x.Type == RecordType.SOA)
                .OfType<StartOfAuthorityResourceRecord>()
                .Select(x => x.MasterDomainName.ToString())
                .ToList();

            var cnameDomains = response.AnswerRecords
                .Where(x => x.Type == RecordType.CNAME)
                .OfType<CanonicalNameResourceRecord>()
                .Select(x => x.CanonicalDomainName.ToString())
                .ToList();

            foreach (var authorityIpAddressRecord in authorityIpAddressRecords)
            {
                microCache[authorityIpAddressRecord.Name.ToString()] = authorityIpAddressRecord.IPAddress;
            }

            return (authorityDomains, authorityIpAddresses, soaDomains, cnameDomains);
        }

        var currentAuthorityIpAddress = RootNamespaceServers.First();
        foreach (var part in parts)
        {
            var (authorityDomains, authorityIpAddresses, soaDomains, cnameDomains) =
                await Request(part, currentAuthorityIpAddress);

            if (authorityIpAddresses.Count != 0)
            {
                var authorityIpAddress = authorityIpAddresses.First();
                currentAuthorityIpAddress = authorityIpAddress;

                _logger.Debug("[{Domain}] Found authority ip address {AuthorityIpAddress}", domain, authorityIpAddress);
            }
            else
            {
                if (cnameDomains.Count != 0)
                {
                    var cnameDomain = cnameDomains.First();

                    if (soaDomains.Count != 0)
                    {
                        var soaDomain = soaDomains.First();

                        IPAddress authorityIpAddress;

                        if (microCache.ContainsKey(soaDomain))
                        {
                            authorityIpAddress = microCache[soaDomain];
                        }
                        else
                        {
                            if (soaDomain == part)
                            {
                                authorityIpAddress = currentAuthorityIpAddress;
                            }
                            else
                            {
                                authorityIpAddress = await Resolve(soaDomain, microCache);
                            }
                        }


                        var domainIpAddress = await ResolveDomainIpAddress(cnameDomain, authorityIpAddress);

                        _logger.Debug(
                            "[{Domain}] Found cname {CnameDomain} with SOA {SoaDomain}, resolved to authority {AuthorityIpAddress} and domain {DomainIpAddress}",
                            domain, cnameDomain, soaDomain, authorityIpAddress, domainIpAddress);

                        return (authorityIpAddress, domainIpAddress);
                    }
                    else
                    {
                        var (authorityIpAddress, domainIpAddress) =
                            await ResolveAuthorityIpAddress(cnameDomain, microCache);

                        domainIpAddress ??= await ResolveDomainIpAddress(cnameDomain, authorityIpAddress);

                        _logger.Debug(
                            "[{Domain}] Found cname {CnameDomain}, resolved to authority {AuthorityIpAddress} and domain {DomainIpAddress}",
                            domain, cnameDomain, authorityIpAddress, domainIpAddress);

                        return (authorityIpAddress, domainIpAddress);
                    }
                }
                else
                {
                    if (soaDomains.Count != 0)
                    {
                        var soaDomain = soaDomains.First();

                        IPAddress authorityIpAddress;

                        if (microCache.ContainsKey(soaDomain))
                        {
                            authorityIpAddress = microCache[soaDomain];
                        }
                        else
                        {
                            if (soaDomain == part)
                            {
                                authorityIpAddress = currentAuthorityIpAddress;
                            }
                            else
                            {
                                authorityIpAddress = await Resolve(soaDomain, microCache);
                            }
                        }

                        currentAuthorityIpAddress = authorityIpAddress;

                        _logger.Debug("[{Domain}] Found SOA {SoaDomain}, resolved to {AuthorityIpAddress}",
                            domain, soaDomain, authorityIpAddress);
                    }
                    else
                    {
                        if (authorityDomains.Count == 0)
                        {
                            throw new ResolveFailedException();
                        }

                        var authorityDomain = authorityDomains.First();
                        var authorityIpAddress = await Resolve(authorityDomain, microCache);
                        currentAuthorityIpAddress = authorityIpAddress;

                        _logger.Debug(
                            "[{Domain}] Found authority domain {AuthorityDomain}, resolved to {AuthorityIpAddress}",
                            domain, authorityDomain, authorityIpAddress);
                    }
                }
            }
        }

        return (currentAuthorityIpAddress, null);
    }

    private static string NormalizeDomain(string domain)
    {
        return domain.Trim().TrimEnd('.');
    }

    private static List<string> SplitDomainToParts(string domain)
    {
        var parts = new List<string> { domain };

        while (true)
        {
            var lastPart = parts.Last();
            var dotIndex = lastPart.IndexOf('.');

            if (dotIndex == -1)
            {
                break;
            }

            parts.Add(lastPart[(dotIndex + 1)..]);
        }

        parts.Reverse();

        return parts;
    }

    private static Request BuildRequest(string domain, RecordType recordType)
    {
        return new Request(
            new Header(),
            new List<Question> { new(Domain.FromString(domain), recordType) },
            new List<IResourceRecord>()
        );
    }
}