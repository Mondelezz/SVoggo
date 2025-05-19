using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

using SVoggo.Enums;
using SVoggo.Interfaces;
using SVoggo.Models;

namespace SVoggo.Services;

public class UltraDefenderService : IUltraDefenderService
{
    private static readonly string[] DefenderPaths =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Defender", "MpCmdRun.exe")
    };

    private static bool _isDefenderAvailable;
    private static string _defenderPath = string.Empty;
    private static readonly SemaphoreSlim _scanLock = new(5);
    private static readonly Dictionary<string, ThreatReport> _scanCache = new();
    private static readonly SHA256 _hasher = SHA256.Create();

    public UltraDefenderService()
    {
        InitializeDefender();
    }

    public async Task<ThreatReport> AnalyzeFileAsync(byte[] file, bool forceRescan = false, CancellationToken ct = default)
    {
        if (!_isDefenderAvailable)
            return new ThreatReport(ThreatStatusEnum.DefenderUnavailable);

        var fileHash = BitConverter.ToString(_hasher.ComputeHash(file)).Replace("-", "");

        if (!forceRescan && _scanCache.TryGetValue(fileHash, out var cachedReport))
            return cachedReport;

        var tempPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempPath, file, ct);
            return await AnalyzeFileAsync(tempPath, fileHash, ct);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    /// <summary>
    /// Проверяет напрямую (filePath) файл на вирусность.
    /// </summary>
    /// <param name="filePath">Путь к файлу</param>
    /// <param name="ct">Токен отмены</param>
    /// <returns></returns>
    public async Task<ThreatReport> AnalyzeFileAsync(string filePath, CancellationToken ct = default)
    {
        if (!_isDefenderAvailable)
            return new ThreatReport(ThreatStatusEnum.DefenderUnavailable);

        var fileHash = BitConverter.ToString(_hasher.ComputeHash(await File.ReadAllBytesAsync(filePath, ct))).Replace("-", "");
        return await AnalyzeFileAsync(filePath, fileHash, ct);
    }

    private async Task<ThreatReport> AnalyzeFileAsync(string filePath, string fileHash, CancellationToken ct)
    {
        await _scanLock.WaitAsync(ct);
        try
        {
            var startTime = DateTime.UtcNow;
            var psi = new ProcessStartInfo
            {
                FileName = _defenderPath,
                Arguments = $"-Scan -ScanType 3 -File \"{filePath}\" -DisableRemediation",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = new Process { StartInfo = psi };

            var output = new StringBuilder();
            var error = new StringBuilder();

            process.OutputDataReceived += (_, e) => output.AppendLine(e.Data);
            process.ErrorDataReceived += (_, e) => error.AppendLine(e.Data);

            if (!process.Start())
            {
                _isDefenderAvailable = false;
                return new ThreatReport(ThreatStatusEnum.ScanFailed, "Failed to start Defender process");
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            try
            {
                await process.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(3), ct);
            }
            catch (TimeoutException)
            {
                process.Kill();
                return new ThreatReport(ThreatStatusEnum.Timeout, "Scan timed out");
            }

            var duration = DateTime.UtcNow - startTime;
            var report = new ThreatReport(
                process.ExitCode switch
                {
                    0 => ThreatStatusEnum.Clean,
                    2 => ThreatStatusEnum.Malicious,
                    _ => ThreatStatusEnum.Suspicious
                },
                output.ToString(),
                error.ToString(),
                duration
            );

            _scanCache[fileHash] = report;
            return report;
        }
        finally
        {
            _scanLock.Release();
        }
    }

    public void ClearCache() => _scanCache.Clear();

    private void InitializeDefender()
    {
        if (!OperatingSystem.IsWindows()) return;

        foreach (var path in DefenderPaths)
        {
            if (!File.Exists(path)) continue;

            _defenderPath = path;
            _isDefenderAvailable = true;
            break;
        }
    }
}