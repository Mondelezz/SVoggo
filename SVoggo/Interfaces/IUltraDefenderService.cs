using SVoggo.Models;

namespace SVoggo.Interfaces;

public interface IUltraDefenderService
{
    public Task<ThreatReport> AnalyzeFileAsync(byte[] file, bool forceRescan = false, CancellationToken ct = default);

    public Task<ThreatReport> AnalyzeFileAsync(string filePath, CancellationToken ct = default);
}
