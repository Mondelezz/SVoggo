using System.Text;
using SVoggo.Enums;

namespace SVoggo.Models;

public record ThreatReport(
ThreatStatusEnum Status,
string ScanOutput = "",
string ErrorOutput = "",
TimeSpan? ScanDuration = null,
DateTime ScanTime = default
)
{
    public DateTime ScanTime { get; } = ScanTime == default ? DateTime.UtcNow : ScanTime;

    public bool IsThreat => Status is ThreatStatusEnum.Malicious or ThreatStatusEnum.Suspicious;

    public string GetSummary() => Status switch
    {
        ThreatStatusEnum.Clean => "Файл не содержит вирус.",
        ThreatStatusEnum.Malicious => "Вредоносный файл обнаружен!",
        ThreatStatusEnum.Suspicious => "Обнаружена подозрительная деятельность.",
        ThreatStatusEnum.DefenderUnavailable => "Защитник Windows недоступен.",
        ThreatStatusEnum.ScanFailed => "Сканирование не удалось.",
        ThreatStatusEnum.Timeout => "Время ожидания сканирования истекло",
        _ => "Неизвестный статус"
    };

    public string GetFullScanDetails()
    {
        var sb = new StringBuilder();

        sb.AppendLine("═══════════════════════════════════════");
        sb.AppendLine("          РЕЗУЛЬТАТ СКАНИРОВАНИЯ       ");
        sb.AppendLine("═══════════════════════════════════════");
        sb.AppendLine($"Статус:        {GetSummary()}");
        sb.AppendLine($"Длительность:  {ScanDuration?.TotalMilliseconds ?? 0} мс");
        sb.AppendLine($"Время проверки: {ScanTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("───────────────────────────────────────");

        if (!string.IsNullOrWhiteSpace(ScanOutput))
        {
            sb.AppendLine("\n[ДЕТАЛИ СКАНИРОВАНИЯ]");
            sb.AppendLine(ParseDefenderOutput(ScanOutput));
        }

        if (!string.IsNullOrWhiteSpace(ErrorOutput))
        {
            sb.AppendLine("\n[ОШИБКИ ПРОЦЕССА]");
            sb.AppendLine(ErrorOutput.Trim());
        }

        sb.AppendLine("═══════════════════════════════════════");
        return sb.ToString();
    }

    private string ParseDefenderOutput(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return "Нет дополнительной информации";

        var result = new StringBuilder();
        var lines = rawOutput.Split('\n')
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(line => line.Trim());

        foreach (var line in lines)
        {
            if (line.Contains("Threat", StringComparison.OrdinalIgnoreCase))
            {
                result.AppendLine($"Угроза: {ExtractValue(line)}");
            }
            else if (line.Contains("file", StringComparison.OrdinalIgnoreCase))
            {
                result.AppendLine($"Файл: {ExtractValue(line)}");
            }
            else if (line.Contains("detected", StringComparison.OrdinalIgnoreCase))
            {
                result.AppendLine($"Обнаружено: {ExtractValue(line)}");
            }
            else if (line.Contains("result", StringComparison.OrdinalIgnoreCase))
            {
                result.AppendLine($"Результат: {ExtractValue(line)}");
            }
            else if (line.Contains("engine", StringComparison.OrdinalIgnoreCase))
            {
                result.AppendLine($"Антивирусный движок: {ExtractValue(line)}");
            }
        }

        return result.Length > 0 ? result.ToString() : rawOutput;
    }

    private string ExtractValue(string line)
    {
        var parts = line.Split(':');
        return parts.Length > 1 ? parts[1].Trim() : line;
    }
}
