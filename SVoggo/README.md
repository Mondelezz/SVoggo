🔥 SVoggo TurboScan — Ультрабыстрый детектор угроз на стероидах!
Забудьте о медленных антивирусах! 🚀 Эта библиотека превращает стандартный Windows Defender в беспощадный сканер-терминатор, способный выявлять угрозы за рекордные 2.5 секунды!

🚀 Блиц-проверка файлов
Молниеносное сканирование (в 10 раз быстрее стандартного UI!)

Детектит даже замаскированные угрозы через MpCmdRun.exe (проверенный движок Microsoft)

Два режима атаки:

🔥 "Быстрый удар" (byte[] → мгновенный анализ)

💣 "Точечный выстрел" (проверка по пути)

🛡️ Защита от перегрузки
- Умный контроль потоков (SemaphoreSlim) — не даст системе упасть, даже если вы атакуете тысячами файлов!

- Авто-очистка — временные файлы испаряются сразу после проверки.

⚡ Гибкая интеграция
Встраивается в веб-приложения, API, файловые менеджеры — где угодно!

⚠️ Ограничения
- Только для Windows (на других ОС ( Linux/MACos ) всегда возвращает false)

- Требует наличия MpCmdRun.exe (обычно в C:\Program Files\Windows Defender)

💻 PowerMode activated — ваш код теперь защищён как Пентагон!

(Лицензия: MIT — делайте что хотите, но только в мирных целях!) 🏴‍☠️


*-----------------------------------------------------------------*
Пример использования в .NET

Регистрация в DI:
builder.Services.AddSingleton<IUltraDefenderService, UltraDefenderService>();

Пример Endpoint:
```
[HttpPost("scan-file")]
    public async Task<IActionResult> ScanFile(IFormFile file)
    {
        await using var stream = new MemoryStream();
        await file.CopyToAsync(stream);
        var report = await _defenderService.AnalyzeFileAsync(stream.ToArray());
        
        return Ok(new {
            Status = report.GetSummary(),
            IsThreat = report.IsThreat,
            Details = report.ScanOutput
        });
    }
```