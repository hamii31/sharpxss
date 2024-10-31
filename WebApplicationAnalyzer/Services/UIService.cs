using static WebApplicationAnalyzer.AppConstants.PathConstants.PayloadConstants;
using static WebApplicationAnalyzer.Services.AppService;

namespace WebApplicationAnalyzer.Services
{
	internal class UIService
	{
		public static async Task StartSharpXSS()
		{
			string ip = await GetLocalIPAddressAsync();

			if (ip == null)
			{
				DisplayMessage("There was an error, ABORTING...", NewLine.Yes, TextColor.Error);
				return;
			}

			DisplayMessage(
					"       .__                                              \r\n" +
					"  _____|  |__ _____ ________________  ___  ______ ______\r\n" +
					" /  ___/  |  \\\\__  \\\\_  __ \\____ \\  \\/  / /  ___//  ___/\r\n" +
					" \\___ \\|   Y  \\/ __ \\|  | \\/  |_> >    <  \\___ \\ \\___ \\ \r\n" +
					"/____  >___|  (____  /__|  |   __/__/\\_ \\/____  >____  >\r\n" +
					"     \\/     \\/     \\/      |__|        \\/     \\/     \\/ ", NewLine.Yes, TextColor.None);

			DisplayMessage("Copyright 2024 Hami Ibriyamov", NewLine.Yes, TextColor.None);
			DisplayMessage($"Chiming in from {await GetLocationAsync(ip)}", NewLine.Yes, TextColor.Warning);
			DisplayMessage("\n-> -h for usage guide and options", NewLine.Yes, TextColor.None);

			// Start Logic
			SharpXSSLogicAsync();
		}
		public static void PrintControls()
		{
			DisplayMessage($"{Environment.NewLine}-> Usage: ", NewLine.Yes, TextColor.None);
			DisplayMessage("-> -p <payload> -t <target>", NewLine.Yes, TextColor.None);
			DisplayMessage("-> -p <payload> -s", NewLine.Yes, TextColor.None);
			DisplayMessage("-> -h", NewLine.Yes, TextColor.None);
			DisplayMessage($"-> -e {Environment.NewLine}", NewLine.Yes, TextColor.None);
			DisplayMessage("-> Information: ", NewLine.Yes, TextColor.None);
			DisplayMessage("-> -p payload type (-p audio, basic, alert, body, cloudflare, div, img, polyglot, svg, waf, custom)", NewLine.Yes, TextColor.None);
			DisplayMessage("-> -t target URL (-t ex.: https://demo.owasp-juice.shop/#/search?q=)", NewLine.Yes, TextColor.None);
			DisplayMessage("-> -s show payloads in a specific list (-p basic -s)", NewLine.Yes, TextColor.None);
			DisplayMessage($"-> -e exit{Environment.NewLine}", NewLine.Yes, TextColor.None);
		}
		public static void PrintPayload(string payload)
		{
			string payloadPath = payload.Equals("basic") ? basicXSSPath
								: payload.Equals("alert") ? alertXSSPath
								: payload.Equals("body") ? bodyXSSPath
								: payload.Equals("cloudflare") ? cloudflareXSSPath
								: payload.Equals("div") ? divXSSPath
								: payload.Equals("img") ? imgXSSPath
								: payload.Equals("polyglot") ? polyglotXSSPath
								: payload.Equals("svg") ? svgXSSPath
								: payload.Equals("waf") ? wafXSSPath
								: payload.Equals("audio") ? audioXSSPath
								: null!;

			if(payloadPath != null)
			{
				try
				{
					DisplayMessage("Printing payload...", NewLine.Yes, TextColor.Formal);
					Thread.Sleep(3000);
					DisplayMessage(string.Join(Environment.NewLine, File.ReadAllLines(payloadPath)), NewLine.Yes, TextColor.None);
					DisplayMessage("Payload printed.", NewLine.Yes, TextColor.Success);
				}
				catch (Exception ex)
				{
					DisplayMessage(ex.Message, NewLine.Yes, TextColor.Error);
				}
            }
			else
			{
				DisplayMessage("Invalid payload!", NewLine.Yes, TextColor.Error);
			}
		}
		public static void DisplayMessage(string message, NewLine newLine, TextColor severity)
		{

			switch (severity)
			{
				case TextColor.Formal:
					Console.ForegroundColor = ConsoleColor.Blue;
					break;
				case TextColor.Success:
					Console.ForegroundColor = ConsoleColor.Green;
					break;
				case TextColor.Warning:
					Console.ForegroundColor = ConsoleColor.Yellow;
					break;
				case TextColor.Error:
					Console.ForegroundColor = ConsoleColor.Red;
					break;
				case TextColor.None:
					Console.ForegroundColor = ConsoleColor.White;
					break;
			}

			switch (newLine)
			{
				case NewLine.Yes:
					Console.WriteLine(message);
					Console.ResetColor(); // Reset to default color
					break;
				case NewLine.No:
					Console.Write(message);
					Console.ResetColor(); // Reset to default color
					break;
			}
		}
		public enum NewLine
		{
			Yes = 0,
			No = 1
		}
		public enum TextColor
		{
			Formal = 0, 
			Success = 1, 
			Warning = 2, 
			Error = 3,
			None = 4
		}
	}
}
