using System.Text;

using SVoggo.Services;
using SVoggo.Interfaces;

public static class Program
{
    public async static Task Main(string[] args)
    {
        IUltraDefenderService ultraDefenderService = new UltraDefenderService();

        var eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var fileBytes = Encoding.ASCII.GetBytes(eicarString);
        var report = await ultraDefenderService.AnalyzeFileAsync(fileBytes);

        Console.WriteLine(report.GetFullScanDetails());
    }
}