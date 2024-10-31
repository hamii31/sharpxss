using static WebApplicationAnalyzer.Services.UIService;

namespace WebApplicationAnalyzer
{
	class Program
	{
		static async Task Main(string[] args)
		{
			await StartSharpXSS();
		}
	}
}