using OpenQA.Selenium;
using OpenQA.Selenium.Firefox;
using OpenQA.Selenium.Support.UI;
using static WebApplicationAnalyzer.Services.UIService;
using static WebApplicationAnalyzer.AppConstants.PathConstants.FirefoxConstants;
using static WebApplicationAnalyzer.AppConstants.PathConstants.OutputConstants;

namespace WebApplicationAnalyzer.Services
{
	internal class DriverService
	{
		public static void CheckInBrowser(string url, string payload)
		{
			var firefoxDriverService = FirefoxDriverService.CreateDefaultService(firefoxDriverPath);
			var options = new FirefoxOptions();
			options.BinaryLocation = firefoxBinaryLocationPath;

			using (var driver = new FirefoxDriver(firefoxDriverService, options))
			{
				string testUrl = $"{url}{Uri.EscapeDataString(payload)}";

				driver.Navigate().GoToUrl(testUrl);

				System.Threading.Thread.Sleep(2000); // Adjust as necessary

				try
				{
					WebDriverWait wait = new WebDriverWait(driver, TimeSpan.FromSeconds(5)); // how long to wait before closing window

					IAlert alert = wait.Until(driver =>
					{
						try
						{
							return driver.SwitchTo().Alert();
						}
						catch (NoAlertPresentException)
						{
							return null!; // Continue waiting
						}
					});

					if (alert != null)
					{
						DisplayMessage($"{alert.Text} detected from payload: " + payload, NewLine.Yes, TextColor.Success);

						string outputPath = outputXSSPath; //writes all working XSS payloads to the output_xss
						using (StreamWriter writer = new StreamWriter(outputPath))
						{
							writer.WriteLine(payload);
						}

						alert.Accept(); // Dismiss the alert
					}
				}
				catch (WebDriverTimeoutException)
				{
					DisplayMessage($"No alert detected, {payload} did not execute.", NewLine.Yes, TextColor.Warning);
				}
			}
		}
	}
}
