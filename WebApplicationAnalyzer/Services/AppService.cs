using Newtonsoft.Json.Linq;
using System.Text;
using WebApplicationAnalyzer.AppConstants;
using static WebApplicationAnalyzer.AppConstants.PathConstants.PayloadConstants;
using static WebApplicationAnalyzer.Services.DriverService;
using static WebApplicationAnalyzer.Services.UIService;

namespace WebApplicationAnalyzer.Services
{
	internal class AppService
	{
		public static async Task<string> GetLocationAsync(string ip)
		{
			using (HttpClient client = new HttpClient())
			{
				// Use ipinfo.io for geolocation
				string url = $"https://ipinfo.io/{ip}/json";


				// Make the HTTP GET request
				var response = await client.GetStringAsync(url);

				// Parse the JSON response
				JObject json = JObject.Parse(response);

				StringBuilder sb = new StringBuilder();
				foreach (var item in json)
				{
					if (item.Key == "ip")
						sb.Append(item.Value + ", ");
					if(item.Key == "city")
						sb.Append(item.Value);
				}
				return sb.ToString();
			}
		}
		public static async void SharpXSSLogicAsync()
		{
			try
			{
				string userInput = "";
				do
				{
					DisplayMessage("-> ", NewLine.No, TextColor.None);
					userInput = Console.ReadLine()!;

					if (userInput.Contains("-h")) // help
					{
						PrintControls();
					}
					else if (userInput.Contains("-p") && !userInput.Contains("-t") && !userInput.Contains("-s")) // show payload options
					{

						if (userInput.Replace(" ", "") == "-p")
						{
							List<string> payloadList = PayloadOptions.Payloads.ToList();

							DisplayMessage("Printing xss payload options...", NewLine.Yes, TextColor.Formal);
							foreach (var item in payloadList)
							{
								DisplayMessage($"{item}", NewLine.Yes, TextColor.None);
							}
							DisplayMessage("Payload options printed.", NewLine.Yes, TextColor.Success);
							continue;
						}

						DisplayMessage("Invalid command", NewLine.Yes, TextColor.Error);
						PrintControls();
						continue;
					}
					else if (userInput.Contains("-p") && userInput.Contains("-t")) // analyze a target with a payload
					{
						var splitted = userInput.Split(new string[] { "-p ", "-t " }, StringSplitOptions.RemoveEmptyEntries);

						string payloadInput = splitted[0].Replace(" ", "").ToLower();

						string payloadType = payloadInput != "basic" && payloadInput != "alert" && payloadInput != "body" && payloadInput != "cloudflare"
											&& payloadInput != "svg" && payloadInput != "waf" && payloadInput != "polyglot" && payloadInput != "img"
											&& payloadInput != "div" && payloadInput != "custom" && payloadInput != "akamai" && payloadInput != "cloudfront"
											&& payloadInput != "imperva" && payloadInput != "incapsula" && payloadInput != "wordfence" && payloadInput != "audio" 
											? null! : payloadInput;

						if (payloadType == null)
						{
							DisplayMessage("Invalid payload", NewLine.Yes, TextColor.Error);
							PrintControls();
							continue;
						}


						string targetUrl = splitted[1];

						if (targetUrl == null)
						{
							DisplayMessage("Invalid target", NewLine.Yes, TextColor.Error);
							PrintControls();
							continue;
						}

						if (await RunAsync(payloadType, targetUrl))
						{
							DisplayMessage("Scan conducted successfully.", NewLine.Yes, TextColor.Success);
							continue;
						}
						else
						{
							DisplayMessage("Scan discontinued.", NewLine.Yes, TextColor.Error);
							continue;
						}

					}
					else if (userInput.Contains("-p") && userInput.Contains("-s")) // show payload contents
					{
						var splitted = userInput.Split(new string[] { "-p ", "-s" }, StringSplitOptions.RemoveEmptyEntries);

						string payloadInput = splitted[0].Replace(" ", "").ToLower();

						string payloadType = payloadInput != "basic" && payloadInput != "alert" && payloadInput != "body" && payloadInput != "cloudflare"
											&& payloadInput != "svg" && payloadInput != "waf" && payloadInput != "polyglot" && payloadInput != "img"
											&& payloadInput != "div" && payloadInput != "custom" && payloadInput != "akamai" && payloadInput != "cloudfront"
											&& payloadInput != "imperva" && payloadInput != "incapsula" && payloadInput != "wordfence" && payloadInput != "audio"
											? null! : payloadInput;

						if (payloadType == null)
						{
							DisplayMessage("Invalid payload", NewLine.Yes, TextColor.Error);
							PrintControls();
							continue;
						}

						PrintPayload(payloadType);
						continue;
					}
					else if (userInput.Contains("-e")) // exit
					{
						DisplayMessage("Exiting...", NewLine.Yes, TextColor.Error);
						break;
					}
					else
					{
						DisplayMessage("Invalid input.", NewLine.Yes, TextColor.Error);
						PrintControls();
						continue;
					}

				}
				while (!userInput.Contains("-e"));

			}
			catch (Exception ex)
			{
				DisplayMessage($"{ex.Message}, ABORTING...", NewLine.Yes, TextColor.Error);
			}
		}
		public static async Task<bool> IsWebsiteOnlineAsync(string targetUrl)
		{
			using (HttpClient client = new HttpClient())
			{
				try
				{
					HttpResponseMessage response = await client.GetAsync(targetUrl);
					return response.IsSuccessStatusCode;
				}
				catch (HttpRequestException ex)
				{
					DisplayMessage($"{ex.Message}, ABORTING...", NewLine.Yes, TextColor.Error);
					return false;
				}
			}
		}
		public static async Task<string> GetLocalIPAddressAsync()
		{
			using (HttpClient client = new HttpClient())
			{
				// Use api.ipify.org to get the public IP
				string url = "https://api.ipify.org"; // or use https for better security
				string ip = await client.GetStringAsync(url);
				return ip;
			}
		}
		public static async Task<bool> RunAsync(string payloadType, string targetUrl)
		{
			try
			{
				//if (await IsWebsiteOnlineAsync(targetUrl))
				//{
				//	DisplayMessage($"{targetUrl} is up and running.", NewLine.Yes, TextColor.Success);
				//}

				// check if payloads exist in the Payloads directory 
				switch (payloadType)
				{
					case "basic":
						DisplayMessage("Loading basic XSS payloads...", NewLine.Yes, TextColor.Formal);
						string xssPath = basicXSSPath;
						List<string> xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Basic XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "audio":
						DisplayMessage("Loading audio XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = audioXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Aydio XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "alert":
						DisplayMessage("Loading alert XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = alertXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Alert XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "body":
						DisplayMessage("Loading body tag XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = bodyXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Body Tag XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "cloudflare":
						DisplayMessage("Loading cloudflare XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = cloudflareXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Cloudflare XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "div":
						DisplayMessage("Loading div tag XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = divXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Div Tag XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "img":
						DisplayMessage("Loading image tag XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = imgXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Image Tag XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "polyglot":
						DisplayMessage("Loading polyglot XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = polyglotXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Polyglot XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "svg":
						DisplayMessage("Loading SVG XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = svgXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for SVG XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "waf":
						DisplayMessage("Loading WAF bypassing XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = wafXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for WAF XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "akamai":
						DisplayMessage("Loading Akamai bypassing XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = akamaiXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Akamai XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "cloudfront":
						DisplayMessage("Loading Cloudfront bypassing XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = cloudfrontXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Cloudfront XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "imperva":
						DisplayMessage("Loading Imperva bypassing XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = impervaXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Imperva XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "incapsula":
						DisplayMessage("Loading Incapsula bypassing XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = incapsulaXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Incapsula XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "wordfence":
						DisplayMessage("Loading Wordfence bypassing XSS payloads...", NewLine.Yes, TextColor.Formal);
						xssPath = wordfenceXSSPath;
						xssPayloads = System.IO.File.ReadAllLines(@xssPath).ToList();
						DisplayMessage("XSS payloads loaded!", NewLine.Yes, TextColor.Success);

						DisplayMessage($"Analyzing {targetUrl} for Wordfence XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						foreach (var payload in xssPayloads)
						{
							CheckInBrowser(targetUrl, payload);
						}
						return true;
					case "custom":
						DisplayMessage("Enter your custom XSS payload: ", NewLine.No, TextColor.Formal);
						string customPayload = Console.ReadLine()!;
						if (customPayload == null)
						{
							DisplayMessage("Payload cannot be empty, ABORTING...", NewLine.Yes, TextColor.Error);
							break;
						}
						DisplayMessage($"Analyzing {targetUrl} for custom XSS vulnerablities.", NewLine.Yes, TextColor.Formal);
						CheckInBrowser(targetUrl, customPayload);
						return true;
					default:
						break;
				}
			}
			catch (Exception ex)
			{
				DisplayMessage($"{ex.Message}, ABORTING...", NewLine.Yes, TextColor.Error);
			}

			return false;
		}
	}
}